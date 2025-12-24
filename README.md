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
##### setup discord
1. Go to the [Discord Developer Portal](https://discord.com/developers/applications) and create a new application.
2. Go to OAuth2 section and add a redirect URL: `https://{backend_url}/api/auth/discord/callback`
   locally: `http://localhost:8080/api/auth/discord/callback`
3. Copy CLIENT ID and CLIENT SECREET and put them into the `.env` file
4. in OAuth2 generator select `identify` and `email` scopes and copy the generated URL
5. Select the redirected URL and then copy the generated URL which is used for the frontend
   
##### start the server
```bash
go run src/main.go
```

