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

### Building swagger docs out of Go comments:

install `swag`:

```
go install github.com/swaggo/swag/cmd/swag@latest
```

```
cd src/
swag init
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

### docker

The image is built from [`Dockerfile`](Dockerfile). The binary inside the
container reads configuration from process env first and falls back to a
`.env` file in its working directory (`/app`), so both delivery paths
work:

Pass the host `.env` as env vars (recommended):

```bash
docker build -t wersu-rest .
docker run --rm -p 8080:8080 --env-file .env wersu-rest
```

Or mount the `.env` file at the working directory so `godotenv.Load()`
picks it up directly:

```bash
docker run --rm -p 8080:8080 \
    -v "$(pwd)/.env:/app/.env:ro" \
    wersu-rest
```

`FRONTEND_URL` works in both setups: it ends up on
`config.AppConfig.FrontendURL`, which is what `main.go` uses for the CORS
allow-list and what `auth_controller.go` redirects the OAuth callback to.
The `.dockerignore` already excludes `.env`, so a stray `.env` on the
host is never baked into the image.

##### proxy Openinary requests

Set the following environment variables to forward media requests through this API:

```bash
OPENINARY_BASE_URL=https://your-openinary-instance.com
OPENINARY_API_KEY=your-openinary-api-key
```

The proxy is exposed under `/api/openinary/*path`, so your website can send requests such as `POST /api/openinary/upload`, `DELETE /api/openinary/storage/photo.jpg`, and `GET /api/openinary/t/w_800,image.jpg` through this backend.

