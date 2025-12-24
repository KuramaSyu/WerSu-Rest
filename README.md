# WerSuDef-Rest-Api
 
### dev
##### generate protobuf code
1. Install protoc for go
    ```bash
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    ```
2. Generate Protocol Buffers
    ```bash
    protoc --go_out=. --go_opt=paths=source_relative     --go-grpc_out=. --go-grpc_opt=paths=source_relative     src/proto/*.proto
    ```