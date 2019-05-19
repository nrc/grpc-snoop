# grpc-snoop

A tool to capture TiKV gRPC messages.

## Building

Clone outside of your `$GOPATH`.

```bash
go build
```

## Running

```
$ go run tikv-assembly.go -f "port 20160" -i lo0
2018/12/29 20:17:17 Starting capture on interface "lo0"
2018/12/29 20:17:17 reading in packets
2018/12/29 20:17:26 127.0.0.1:64989 -> 127.0.0.1:20160 /tikvpb.Tikv/KvPrewrite context:<region_id:2 region_epoch:<conf_ver:1 version:1 > peer:<id:3 store_id:1 > > mutations:<key:"usertable:a" value:"\010\000\002\0020" > primary_lock:"usertable:a" start_version:405297128206237697 lock_ttl:3000
2018/12/29 20:17:26 127.0.0.1:20160 -> 127.0.0.1:64989 /tikvpb.Tikv/KvPrewrite
2018/12/29 20:17:26 127.0.0.1:64995 -> 127.0.0.1:20160 /tikvpb.Tikv/KvCommit context:<region_id:2 region_epoch:<conf_ver:1 version:1 > peer:<id:3 store_id:1 > > start_version:405297128206237697 keys:"usertable:a" commit_version:405297128206237698
2018/12/29 20:17:26 127.0.0.1:20160 -> 127.0.0.1:64995 /tikvpb.Tikv/KvCommit
2018/12/29 20:17:29 127.0.0.1:64999 -> 127.0.0.1:20160 /tikvpb.Tikv/KvGet context:<region_id:2 region_epoch:<conf_ver:1 version:1 > peer:<id:3 store_id:1 > > key:"usertable:a" version:405297128901443585
2018/12/29 20:17:29 127.0.0.1:20160 -> 127.0.0.1:64999 /tikvpb.Tikv/KvGet value:"\010\000\002\0020"
```
