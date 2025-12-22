# WerSuDef-Rest-Api
 
### dev
##### generate protobuf code
```bash
protoc --go_out=. --go_opt=paths=source_relative     --go-grpc_out=. --go-grpc_opt=paths=source_relative     src/proto/*.proto
```