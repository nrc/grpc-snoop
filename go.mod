module github.com/siddontang/tikvassemble

require (
	github.com/coreos/etcd v0.0.0-00010101000000-000000000000 // indirect
	github.com/gogo/protobuf v1.2.0 // indirect
	github.com/golang/protobuf v1.2.0
	github.com/google/go-cmp v0.2.0 // indirect
	github.com/google/gopacket v1.1.17
	github.com/mdlayher/raw v0.0.0-20181016155347-fa5ef3332ca9 // indirect
	github.com/pingcap/kvproto v0.0.0-20190517030054-ff2e03f6fdfe
	go.etcd.io/etcd v3.3.13+incompatible
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3
)

replace github.com/coreos/etcd => go.etcd.io/etcd v0.0.0-20181228175106-cc8d446a6ec3
