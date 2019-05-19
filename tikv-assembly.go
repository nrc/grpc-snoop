package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/pingcap/kvproto/pkg/coprocessor"
	"github.com/pingcap/kvproto/pkg/kvrpcpb"
	"github.com/pingcap/kvproto/pkg/tikvpb"
	"github.com/pingcap/kvproto/pkg/pdpb"
	"github.com/pingcap/kvproto/pkg/raft_serverpb"

	"go.etcd.io/etcd/etcdserver/etcdserverpb"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 4096, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and dst port 80", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

const connPreface string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func parseRequest(net string, prefix string, buf *bufio.Reader) (bool, error) {
	prefix = strings.ToUpper(prefix)
	if strings.HasPrefix(prefix, "GET") || strings.HasPrefix(prefix, "POST") ||
		strings.HasPrefix(prefix, "PUT") || strings.HasPrefix(prefix, "DELET") ||
		strings.HasPrefix(prefix, "HEAD") {
		r, err := http.ReadRequest(buf)
		if err != nil {
			return false, err
		}

		log.Printf("%s Req %v", net, r)

		buf.Discard(int(r.ContentLength))
		r.Body.Close()
		return true, nil
	}
	return false, nil
}

func parseResponse(net string, prefix string, buf *bufio.Reader) (bool, error) {
	prefix = strings.ToUpper(prefix)
	if strings.HasPrefix(prefix, "HTTP") {
		resp, err := http.ReadResponse(buf, nil)
		if err != nil {
			return false, err
		}

		log.Printf("%s Resp %v", net, resp)

		buf.Discard(int(resp.ContentLength))
		resp.Body.Close()
		return true, nil
	}
	return false, nil
}

var readNum int64

var streamPath = map[string]map[uint32]string{}
var pathLock sync.RWMutex

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	framer := http2.NewFramer(ioutil.Discard, buf)
	framer.MaxHeaderListSize = uint32(16 << 20)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	net := fmt.Sprintf("%s:%s -> %s:%s", h.net.Src(), h.transport.Src(), h.net.Dst(), h.transport.Dst())
	revNet := fmt.Sprintf("%s:%s -> %s:%s", h.net.Dst(), h.transport.Dst(), h.net.Src(), h.transport.Src())
	// 1 request, 2 response, 0 unkonwn
	var streamSide = map[uint32]int{}

	defer func() {
		pathLock.Lock()
		delete(streamPath, net)
		delete(streamPath, revNet)
		pathLock.Unlock()
	}()
	for {
		peekBuf, err := buf.Peek(9)
		if err == io.EOF {
			return
		} else if err != nil {
			log.Print("Error reading frame", h.net, h.transport, ":", err)
			continue
		}

		prefix := string(peekBuf)

		// log.Printf("%s prefix %q", net, prefix)
		if ok, err := parseRequest(net, prefix, buf); ok || err != nil {
			continue
		}

		if ok, err := parseResponse(net, prefix, buf); ok || err != nil {
			continue
		}

		if strings.HasPrefix(prefix, "PRI") {
			buf.Discard(len(connPreface))
		}

		frame, err := framer.ReadFrame()
		if err == io.EOF {
			return
		}

		if err != nil {
			log.Print("Error reading frame", h.net, h.transport, ":", err)
			continue
		}

		id := frame.Header().StreamID
		// log.Printf("%s id %d frame %v", net, id, frame.Header())
		switch frame := frame.(type) {
		case *http2.MetaHeadersFrame:
			for _, hf := range frame.Fields {
				// log.Printf("%s id %d %s=%s", net, id, hf.Name, hf.Value)
				if hf.Name == ":path" {
					// TODO: remove stale stream ID
					pathLock.Lock()
					_, ok := streamPath[net]
					if !ok {
						streamPath[net] = map[uint32]string{}
					}
					streamPath[net][id] = hf.Value
					pathLock.Unlock()
					streamSide[id] = 1
				} else if hf.Name == ":status" {
					streamSide[id] = 2
				}
			}
		case *http2.DataFrame:
			var path string
			pathLock.RLock()
			nets, ok := streamPath[net]
			if !ok {
				nets, ok = streamPath[revNet]
			}

			if ok {
				path = nets[id]
			}

			pathLock.RUnlock()
			// log.Printf("%s id %d path %s, data", net, id, path)
			dumpMsg(net, path, frame, streamSide[id])
		default:
		}
	}
}

func dumpMsg(net string, path string, frame *http2.DataFrame, side int) {
	buf := frame.Data()
	id := frame.Header().StreamID
	compress := buf[0]
	// length := binary.BigEndian.Uint32(buf[1:5])
	if compress == 1 {
		// use compression, check Message-Encoding later
		log.Printf("%s %d use compression, msg %q", net, id, buf[5:])
		return
	}

	// Em, a little ugly here, try refactor later.
	if msgs, ok := pathMsgs[path]; ok {
		switch side {
		case 1:
			msg := proto.Clone(msgs[0])
			if err := proto.Unmarshal(buf[5:], msg); err == nil {
				log.Printf("%s %d %s %s", net, id, path, msg)
				return
			}
		case 2:
			msg := proto.Clone(msgs[1])
			if err := proto.Unmarshal(buf[5:], msg); err == nil {
				log.Printf("%s %d %s %s", net, id, path, msg)
				return
			}
		default:
			// We can't know the data is request or response
			for _, msg := range msgs {
				msg := proto.Clone(msg)
				if err := proto.Unmarshal(buf[5:], msg); err == nil {
					log.Printf("%s %d %s %s", net, id, path, msg)
					return
				}
			}
		}
	}

	dumpProto(net, id, path, buf[5:])
}

func dumpProto(net string, id uint32, path string, buf []byte) {
	var out bytes.Buffer
	if err := decodeProto(&out, buf, 0); err != nil {
		// decode failed
		log.Printf("%s %d %s %q", net, id, path, buf)
	} else {
		log.Printf("%s %d %s\n%s", net, id, path, out.String())
	}
}

func decodeProto(out *bytes.Buffer, buf []byte, depth int) error {
out:
	for {
		if len(buf) == 0 {
			return nil
		}

		for i := 0; i < depth; i++ {
			out.WriteString("  ")
		}

		op, n := proto.DecodeVarint(buf)
		if n == 0 {
			return io.ErrUnexpectedEOF
		}

		buf = buf[n:]

		tag := op >> 3
		wire := op & 7

		switch wire {
		default:
			fmt.Fprintf(out, "tag=%d unknown wire=%d\n", tag, wire)
			break out
		case proto.WireBytes:
			l, n := proto.DecodeVarint(buf)
			if n == 0 {
				return io.ErrUnexpectedEOF
			}
			buf = buf[n:]
			if len(buf) < int(l) {
				return io.ErrUnexpectedEOF
			}

			// Here we can't know the raw bytes is string, or embedded message
			// So we try to parse like a embedded message at first
			outLen := out.Len()
			fmt.Fprintf(out, "tag=%d struct\n", tag)
			if err := decodeProto(out, buf[0:int(l)], depth+1); err != nil {
				// Seem this is not a embedded message, print raw buffer
				out.Truncate(outLen)
				fmt.Fprintf(out, "tag=%d bytes=%q\n", tag, buf[0:int(l)])
			}
			buf = buf[l:]
		case proto.WireFixed32:
			if len(buf) < 4 {
				return io.ErrUnexpectedEOF
			}
			u := binary.LittleEndian.Uint32(buf[0:4])
			buf = buf[4:]
			fmt.Fprintf(out, "tag=%d fix32=%d\n", tag, u)
		case proto.WireFixed64:
			if len(buf) < 8 {
				return io.ErrUnexpectedEOF
			}
			u := binary.LittleEndian.Uint64(buf[0:8])
			buf = buf[4:]
			fmt.Fprintf(out, "tag=%d fix64=%d\n", tag, u)
		case proto.WireVarint:
			u, n := proto.DecodeVarint(buf)
			if n == 0 {
				return io.ErrUnexpectedEOF
			}
			buf = buf[n:]
			fmt.Fprintf(out, "tag=%d varint=%d\n", tag, u)
		case proto.WireStartGroup:
			fmt.Fprintf(out, "tag=%d start\n", tag)
			depth++
		case proto.WireEndGroup:
			fmt.Fprintf(out, "tag=%d end\n", tag)
			depth--
		}
	}
	return io.ErrUnexpectedEOF
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

var pathMsgs map[string][]proto.Message

func init() {
	pathMsgs = map[string][]proto.Message{
		"/pdpb.PD/GetMembers":        {new(pdpb.GetMembersRequest), new(pdpb.GetMembersResponse)},
		"/pdpb.PD/Tso":               {new(pdpb.TsoRequest), new(pdpb.TsoResponse)},
		"/pdpb.PD/Bootstrap":         {new(pdpb.BootstrapRequest), new(pdpb.BootstrapResponse)},
		"/pdpb.PD/IsBootstrapped":    {new(pdpb.IsBootstrappedRequest), new(pdpb.IsBootstrappedResponse)},
		"/pdpb.PD/AllocID":           {new(pdpb.AllocIDRequest), new(pdpb.AllocIDResponse)},
		"/pdpb.PD/GetStore":          {new(pdpb.GetStoreRequest), new(pdpb.GetStoreResponse)},
		"/pdpb.PD/PutStore":          {new(pdpb.PutStoreRequest), new(pdpb.PutStoreResponse)},
		"/pdpb.PD/GetAllStores":      {new(pdpb.GetAllStoresRequest), new(pdpb.GetAllStoresResponse)},
		"/pdpb.PD/StoreHeartbeat":    {new(pdpb.StoreHeartbeatRequest), new(pdpb.StoreHeartbeatResponse)},
		"/pdpb.PD/RegionHeartbeat":   {new(pdpb.RegionHeartbeatRequest), new(pdpb.RegionHeartbeatResponse)},
		"/pdpb.PD/GetRegion":         {new(pdpb.GetRegionRequest), new(pdpb.GetRegionResponse)},
		"/pdpb.PD/GetPrevRegion":     {new(pdpb.GetRegionRequest), new(pdpb.GetRegionResponse)},
		"/pdpb.PD/GetRegionByID":     {new(pdpb.GetRegionByIDRequest), new(pdpb.GetRegionResponse)},
		"/pdpb.PD/AskSplit":          {new(pdpb.AskSplitRequest), new(pdpb.AskSplitResponse)},
		"/pdpb.PD/ReportSplit":       {new(pdpb.ReportSplitRequest), new(pdpb.ReportSplitResponse)},
		"/pdpb.PD/AskBatchSplit":     {new(pdpb.AskBatchSplitRequest), new(pdpb.AskBatchSplitResponse)},
		"/pdpb.PD/ReportBatchSplit":  {new(pdpb.ReportBatchSplitRequest), new(pdpb.ReportBatchSplitResponse)},
		"/pdpb.PD/GetClusterConfig":  {new(pdpb.GetClusterConfigRequest), new(pdpb.GetClusterConfigResponse)},
		"/pdpb.PD/PutClusterConfig":  {new(pdpb.PutClusterConfigRequest), new(pdpb.PutClusterConfigResponse)},
		"/pdpb.PD/ScatterRegion":     {new(pdpb.ScatterRegionRequest), new(pdpb.ScatterRegionResponse)},
		"/pdpb.PD/GetGCSafePoint":    {new(pdpb.GetGCSafePointRequest), new(pdpb.GetGCSafePointResponse)},
		"/pdpb.PD/UpdateGCSafePoint": {new(pdpb.UpdateGCSafePointRequest), new(pdpb.UpdateGCSafePointResponse)},
		"/pdpb.PD/SyncRegions":       {new(pdpb.SyncRegionRequest), new(pdpb.SyncRegionResponse)},

		"/tikvpb.Tikv/KvGet":              {new(kvrpcpb.GetRequest), new(kvrpcpb.GetResponse)},
		"/tikvpb.Tikv/KvScan":             {new(kvrpcpb.ScanRequest), new(kvrpcpb.ScanResponse)},
		"/tikvpb.Tikv/KvPrewrite":         {new(kvrpcpb.PrewriteRequest), new(kvrpcpb.PrewriteResponse)},
		"/tikvpb.Tikv/KvPessimisticLock":  {new(kvrpcpb.PessimisticLockRequest), new(kvrpcpb.PessimisticLockResponse)},
		"/tikvpb.Tikv/KVPessimisticRollback": {new(kvrpcpb.PessimisticRollbackRequest), new(kvrpcpb.PessimisticRollbackResponse)},
		"/tikvpb.Tikv/KvCommit":           {new(kvrpcpb.CommitRequest), new(kvrpcpb.CommitResponse)},
		"/tikvpb.Tikv/KvImport":           {new(kvrpcpb.ImportRequest), new(kvrpcpb.ImportResponse)},
		"/tikvpb.Tikv/KvCleanup":          {new(kvrpcpb.CleanupRequest), new(kvrpcpb.CleanupResponse)},
		"/tikvpb.Tikv/KvBatchGet":         {new(kvrpcpb.BatchGetRequest), new(kvrpcpb.BatchGetResponse)},
		"/tikvpb.Tikv/KvBatchRollback":    {new(kvrpcpb.BatchRollbackRequest), new(kvrpcpb.BatchRollbackResponse)},
		"/tikvpb.Tikv/KvScanLock":         {new(kvrpcpb.ScanLockRequest), new(kvrpcpb.ScanLockResponse)},
		"/tikvpb.Tikv/KvResolveLock":      {new(kvrpcpb.ResolveLockRequest), new(kvrpcpb.ResolveLockResponse)},
		"/tikvpb.Tikv/KvGC":               {new(kvrpcpb.GCRequest), new(kvrpcpb.GCResponse)},
		"/tikvpb.Tikv/KvDeleteRange":      {new(kvrpcpb.DeleteRangeRequest), new(kvrpcpb.DeleteRangeResponse)},
		"/tikvpb.Tikv/RawGet":             {new(kvrpcpb.RawGetRequest), new(kvrpcpb.RawGetResponse)},
		"/tikvpb.Tikv/RawBatchGet":        {new(kvrpcpb.RawBatchGetRequest), new(kvrpcpb.RawBatchGetResponse)},
		"/tikvpb.Tikv/RawPut":             {new(kvrpcpb.RawPutRequest), new(kvrpcpb.RawPutResponse)},
		"/tikvpb.Tikv/RawBatchPut":        {new(kvrpcpb.RawBatchPutRequest), new(kvrpcpb.RawBatchPutResponse)},
		"/tikvpb.Tikv/RawDelete":          {new(kvrpcpb.RawDeleteRequest), new(kvrpcpb.RawDeleteResponse)},
		"/tikvpb.Tikv/RawBatchDelete":     {new(kvrpcpb.RawBatchDeleteRequest), new(kvrpcpb.RawBatchDeleteResponse)},
		"/tikvpb.Tikv/RawScan":            {new(kvrpcpb.RawScanRequest), new(kvrpcpb.RawScanResponse)},
		"/tikvpb.Tikv/RawDeleteRange":     {new(kvrpcpb.RawDeleteRangeRequest), new(kvrpcpb.RawDeleteRangeResponse)},
		"/tikvpb.Tikv/RawBatchScan":       {new(kvrpcpb.RawBatchScanRequest), new(kvrpcpb.RawBatchScanResponse)},
		"/tikvpb.Tikv/UnsafeDestroyRange": {new(kvrpcpb.UnsafeDestroyRangeRequest), new(kvrpcpb.UnsafeDestroyRangeResponse)},
		"/tikvpb.Tikv/Coprocessor":        {new(coprocessor.Request), new(coprocessor.Response)},
		"/tikvpb.Tikv/CoprocessorStream":  {new(coprocessor.Request), new(coprocessor.Response)},
		"/tikvpb.Tikv/Raft":               {new(raft_serverpb.RaftMessage), new(raft_serverpb.Done)},
		"/tikvpb.Tikv/Snapshot":           {new(raft_serverpb.SnapshotChunk), new(raft_serverpb.Done)},
		"/tikvpb.Tikv/SplitRegion ":       {new(kvrpcpb.SplitRegionRequest), new(kvrpcpb.SplitRegionResponse)},
		"/tikvpb.Tikv/MvccGetByKey":       {new(kvrpcpb.MvccGetByKeyRequest), new(kvrpcpb.MvccGetByKeyResponse)},
		"/tikvpb.Tikv/MvccGetByStartTs":   {new(kvrpcpb.MvccGetByStartTsRequest), new(kvrpcpb.MvccGetByStartTsResponse)},
		"/tikvpb.Tikv/BatchCommandsRequest": {new(tikvpb.BatchCommandsRequest), new(tikvpb.BatchCommandsResponse)},

		"/etcdserverpb.KV/Range":       {new(etcdserverpb.RangeRequest), new(etcdserverpb.RangeResponse)},
		"/etcdserverpb.KV/Put":         {new(etcdserverpb.PutRequest), new(etcdserverpb.PutResponse)},
		"/etcdserverpb.KV/DeleteRange": {new(etcdserverpb.DeleteRangeRequest), new(etcdserverpb.DeleteRangeResponse)},
		"/etcdserverpb.KV/Txn":         {new(etcdserverpb.TxnRequest), new(etcdserverpb.TxnResponse)},
		"/etcdserverpb.KV/Compact":     {new(etcdserverpb.CompactionRequest), new(etcdserverpb.CompactionResponse)},

		"/etcdserverpb.Watch/Watch": {new(etcdserverpb.WatchRequest), new(etcdserverpb.WatchResponse)},

		"/etcdserverpb.Lease/LeaseGrant":      {new(etcdserverpb.LeaseGrantRequest), new(etcdserverpb.LeaseGrantResponse)},
		"/etcdserverpb.Lease/LeaseRevoke":     {new(etcdserverpb.LeaseRevokeRequest), new(etcdserverpb.LeaseRevokeResponse)},
		"/etcdserverpb.Lease/LeaseKeepAlive":  {new(etcdserverpb.LeaseKeepAliveRequest), new(etcdserverpb.LeaseKeepAliveResponse)},
		"/etcdserverpb.Lease/LeaseTimeToLive": {new(etcdserverpb.LeaseTimeToLiveRequest), new(etcdserverpb.LeaseTimeToLiveResponse)},
		"/etcdserverpb.Lease/LeaseLeases":     {new(etcdserverpb.LeaseLeasesRequest), new(etcdserverpb.LeaseLeasesResponse)},

		"/etcdserverpb.Cluster/MemberAdd":    {new(etcdserverpb.MemberAddRequest), new(etcdserverpb.MemberAddResponse)},
		"/etcdserverpb.Cluster/MemberRemove": {new(etcdserverpb.MemberRemoveRequest), new(etcdserverpb.MemberRemoveResponse)},
		"/etcdserverpb.Cluster/MemberUpdate": {new(etcdserverpb.MemberUpdateRequest), new(etcdserverpb.MemberUpdateResponse)},
		"/etcdserverpb.Cluster/MemberList":   {new(etcdserverpb.MemberListRequest), new(etcdserverpb.MemberListResponse)},

		"/etcdserverpb.Maintenance/Alarm":      {new(etcdserverpb.AlarmRequest), new(etcdserverpb.AlarmResponse)},
		"/etcdserverpb.Maintenance/Status":     {new(etcdserverpb.StatusRequest), new(etcdserverpb.StatusResponse)},
		"/etcdserverpb.Maintenance/Defragment": {new(etcdserverpb.DefragmentRequest), new(etcdserverpb.DefragmentResponse)},
		"/etcdserverpb.Maintenance/Hash":       {new(etcdserverpb.HashRequest), new(etcdserverpb.HashResponse)},
		"/etcdserverpb.Maintenance/HashKV":     {new(etcdserverpb.HashKVRequest), new(etcdserverpb.HashKVResponse)},
		"/etcdserverpb.Maintenance/Snapshot":   {new(etcdserverpb.SnapshotRequest), new(etcdserverpb.SnapshotResponse)},
		"/etcdserverpb.Maintenance/MoveLeader": {new(etcdserverpb.MoveLeaderRequest), new(etcdserverpb.MoveLeaderResponse)},

		"/etcdserverpb.Auth/AuthEnable":           {new(etcdserverpb.AuthEnableRequest), new(etcdserverpb.AuthEnableResponse)},
		"/etcdserverpb.Auth/AuthDisable":          {new(etcdserverpb.AuthDisableRequest), new(etcdserverpb.AuthDisableResponse)},
		"/etcdserverpb.Auth/Authenticate":         {new(etcdserverpb.AuthenticateRequest), new(etcdserverpb.AuthenticateResponse)},
		"/etcdserverpb.Auth/UserAdd":              {new(etcdserverpb.AuthUserAddRequest), new(etcdserverpb.AuthUserAddResponse)},
		"/etcdserverpb.Auth/UserGet":              {new(etcdserverpb.AuthUserGetRequest), new(etcdserverpb.AuthUserGetResponse)},
		"/etcdserverpb.Auth/UserList":             {new(etcdserverpb.AuthUserListRequest), new(etcdserverpb.AuthUserListResponse)},
		"/etcdserverpb.Auth/UserDelete":           {new(etcdserverpb.AuthUserDeleteRequest), new(etcdserverpb.AuthUserDeleteResponse)},
		"/etcdserverpb.Auth/UserChangePassword":   {new(etcdserverpb.AuthUserChangePasswordRequest), new(etcdserverpb.AuthUserChangePasswordResponse)},
		"/etcdserverpb.Auth/UserGrantRole":        {new(etcdserverpb.AuthUserGrantRoleRequest), new(etcdserverpb.AuthUserGrantRoleResponse)},
		"/etcdserverpb.Auth/UserRevokeRole":       {new(etcdserverpb.AuthUserRevokeRoleRequest), new(etcdserverpb.AuthUserRevokeRoleResponse)},
		"/etcdserverpb.Auth/RoleAdd":              {new(etcdserverpb.AuthRoleAddRequest), new(etcdserverpb.AuthRoleAddResponse)},
		"/etcdserverpb.Auth/RoleGet":              {new(etcdserverpb.AuthRoleGetRequest), new(etcdserverpb.AuthRoleGetResponse)},
		"/etcdserverpb.Auth/RoleList":             {new(etcdserverpb.AuthRoleListRequest), new(etcdserverpb.AuthRoleListResponse)},
		"/etcdserverpb.Auth/RoleDelete":           {new(etcdserverpb.AuthRoleDeleteRequest), new(etcdserverpb.AuthRoleDeleteResponse)},
		"/etcdserverpb.Auth/RoleGrantPermission":  {new(etcdserverpb.AuthRoleGrantPermissionRequest), new(etcdserverpb.AuthRoleGrantPermissionResponse)},
		"/etcdserverpb.Auth/RoleRevokePermission": {new(etcdserverpb.AuthRoleRevokePermissionRequest), new(etcdserverpb.AuthRoleRevokePermissionResponse)},
	}
}
