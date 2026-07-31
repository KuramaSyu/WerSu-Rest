package controllers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// defaultImgproxyPort is the port the imgproxy HTTP server listens on by
// default; used as a fallback if IMGPROXY_ADDRESS doesn't include a port.
const defaultImgproxyPort = "8083"

// defaultPostgresPort is the port Postgres listens on by default; used as
// a fallback when DATABASE_DSN doesn't include an explicit port.
const defaultPostgresPort = "5432"

// CheckResult is the per-check payload reported for every reachability probe.
type CheckResult struct {
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
	// Address that was probed (host:port) for the service-level checks, or
	// the host portion for DNS-level checks.
	Address string `json:"address,omitempty"`
	// LatencyMs measures how long the probe took. Zero if the probe was
	// skipped (e.g. DNS already failed).
	LatencyMs int64 `json:"latency_ms"`
	// Detail is an optional human-readable note for the response (e.g.
	// the gRPC status name, the number of buckets returned, ...).
	Detail string `json:"detail,omitempty"`
}

// ServiceStatus groups the DNS and service-level checks for one dependency.
type ServiceStatus struct {
	Address   string      `json:"address"`
	DNS       CheckResult `json:"dns"`
	Service   CheckResult `json:"service"`
	Reachable bool        `json:"reachable"`
	Detail    string      `json:"detail,omitempty"`
	// Error is a convenience field that mirrors the first non-empty error
	// from DNS or Service, so monitoring can read the top-level state
	// without traversing the nested checks.
	Error string `json:"error,omitempty"`
}

// StatusResponse is the body returned by GET /api/status.
type StatusResponse struct {
	OverallOK bool          `json:"overall_ok"`
	Postgres  ServiceStatus `json:"postgres"`
	Garage    ServiceStatus `json:"garage"`
	SpiceDB   ServiceStatus `json:"spicedb"`
	WerSu     ServiceStatus `json:"wersu"`
	Imgproxy  ServiceStatus `json:"imgproxy"`
	CheckedAt time.Time     `json:"checked_at"`
}

// StatusController answers GET /api/status with liveness/reachability
// information for the three backing services: Garage (S3), SpiceDB (gRPC),
// and WerSu itself (gRPC).
type StatusController struct {
	appConfig      *config.Config
	userGrpcClient *proto.UserServiceClient
	s3Client       *s3.Client
}

// NewStatusController wires up the dependencies needed to perform the
// status probes.
func NewStatusController(
	appConfig *config.Config,
	userGrpcClient *proto.UserServiceClient,
	s3Client *s3.Client,
) *StatusController {
	return &StatusController{
		appConfig:      appConfig,
		userGrpcClient: userGrpcClient,
		s3Client:       s3Client,
	}
}

// GetStatus runs all reachability checks in parallel and returns the
// aggregated StatusResponse. The HTTP status code is always 200 — the body
// carries the per-dependency reachability flags so monitoring can decide
// what to do with the response.
//
// GetStatus godoc
// @Summary      Service reachability status
// @Description  Reports DNS reachability and service-level reachability for
// @Description  Garage (S3), SpiceDB (gRPC), imgproxy (HTTP /health), the
// @Description  WerSu gRPC backend, and Postgres (when DATABASE_DSN is set).
// @Description  The response is always returned with HTTP 200; inspect the
// @Description  `overall_ok` and per-service `reachable` flags for health.
// @Tags         Status
// @Produce      json
// @Success      200  {object}  StatusResponse
// @Router       /status [get]
func (sc *StatusController) GetStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make(map[string]ServiceStatus, 5)
	)

	run := func(name string, fn func(context.Context) ServiceStatus) {
		defer wg.Done()
		s := fn(ctx)
		mu.Lock()
		results[name] = s
		mu.Unlock()
	}

	wg.Add(5)
	go run("garage", sc.checkGarage)
	go run("spicedb", sc.checkSpiceDB)
	go run("imgproxy", sc.checkImgproxy)
	go run("wersu", sc.checkWerSu)
	go run("postgres", sc.checkPostgres)
	wg.Wait()

	// mask keys which are maybe within the responses
	for name, st := range results {
		st.Error = maskKeysInString(st.Error)
		st.Detail = maskKeysInString(st.Detail)
		st.DNS.Error = maskKeysInString(st.DNS.Error)
		st.DNS.Detail = maskKeysInString(st.DNS.Detail)
		st.Service.Error = maskKeysInString(st.Service.Error)
		st.Service.Detail = maskKeysInString(st.Service.Detail)
		results[name] = st
	}

	resp := StatusResponse{
		Garage:    results["garage"],
		SpiceDB:   results["spicedb"],
		Imgproxy:  results["imgproxy"],
		WerSu:     results["wersu"],
		Postgres:  results["postgres"],
		CheckedAt: time.Now().UTC(),
	}
	// Postgres is optional: when DATABASE_DSN is empty the probe reports
	// itself as not configured, so we don't factor it into OverallOK.
	postgresOK := resp.Postgres.Reachable || resp.Postgres.Error == "DATABASE_DSN is not configured"
	resp.OverallOK = resp.Garage.Reachable &&
		resp.SpiceDB.Reachable &&
		resp.WerSu.Reachable &&
		resp.Imgproxy.Reachable &&
		postgresOK

	c.JSON(http.StatusOK, resp)
}

// ---------- individual probes ----------

func (sc *StatusController) checkGarage(ctx context.Context) ServiceStatus {
	st := ServiceStatus{Address: redactURLCredentials(sc.appConfig.S3Endpoint)}

	host, port := splitHostPort(sc.appConfig.S3Endpoint, "3900")
	st.DNS = checkDNS(ctx, host)
	if !st.DNS.Reachable {
		st.Error = st.DNS.Error
		return st
	}

	st.Service = sc.probeS3(ctx)
	st.Service.Address = joinHostPort(host, port)
	st.Reachable = st.Service.Reachable
	if !st.Reachable {
		st.Error = st.Service.Error
	}
	st.Detail = st.Service.Detail
	return st
}

func (sc *StatusController) checkSpiceDB(ctx context.Context) ServiceStatus {
	st := ServiceStatus{Address: sc.appConfig.SpiceDbAddress}

	host, port := splitHostPort(sc.appConfig.SpiceDbAddress, "50051")
	st.DNS = checkDNS(ctx, host)
	if !st.DNS.Reachable {
		st.Error = st.DNS.Error
		return st
	}

	st.Service = sc.probeSpiceDB(ctx, host, port)
	st.Reachable = st.Service.Reachable
	if !st.Reachable {
		st.Error = st.Service.Error
	}
	return st
}

func (sc *StatusController) checkWerSu(ctx context.Context) ServiceStatus {
	st := ServiceStatus{Address: sc.appConfig.GRPCServerAddress}

	host, port := splitHostPort(sc.appConfig.GRPCServerAddress, "50052")
	st.DNS = checkDNS(ctx, host)
	if !st.DNS.Reachable {
		st.Error = st.DNS.Error
		return st
	}

	st.Service = sc.probeWerSu(ctx)
	st.Service.Address = joinHostPort(host, port)
	st.Reachable = st.Service.Reachable
	if !st.Reachable {
		st.Error = st.Service.Error
	}
	return st
}

// checkImgproxy verifies DNS reachability of the configured imgproxy host
// and then issues a GET /health against it. imgproxy returns 200 OK on
// /health once the server has finished starting up — this works both
// with and without a signing key, since /health doesn't require any URL
// signature.
func (sc *StatusController) checkImgproxy(ctx context.Context) ServiceStatus {
	st := ServiceStatus{Address: redactURLCredentials(sc.appConfig.ImgproxyAddress)}

	host, port := splitHostPort(sc.appConfig.ImgproxyAddress, defaultImgproxyPort)
	st.DNS = checkDNS(ctx, host)
	if !st.DNS.Reachable {
		st.Error = st.DNS.Error
		return st
	}

	st.Service = sc.probeImgproxy(ctx, host, port)
	st.Service.Address = joinHostPort(host, port)
	st.Reachable = st.Service.Reachable
	if !st.Reachable {
		st.Error = st.Service.Error
	}
	return st
}

// checkPostgres verifies DNS reachability of the host embedded in
// DATABASE_DSN and then opens a short-lived Postgres connection and runs
// `SELECT 1`. The DSN is intentionally optional — when it's empty the
// probe reports itself as not configured rather than failing the overall
// status, since the application itself does not depend on it.
//
// The address reported back is the redacted DSN: credentials and query
// string (sslmode, ...) are stripped so the full DSN never leaves the
// server.
func (sc *StatusController) checkPostgres(ctx context.Context) ServiceStatus {
	dsn := sc.appConfig.DatabaseDSN
	st := ServiceStatus{Address: redactPostgresDSN(dsn)}

	if dsn == "" {
		st.Error = "DATABASE_DSN is not configured"
		return st
	}

	host, port, err := parsePostgresDSN(dsn)
	if err != nil {
		st.Error = fmt.Sprintf("parse DSN: %v", err)
		return st
	}

	st.DNS = checkDNS(ctx, host)
	if !st.DNS.Reachable {
		st.Error = st.DNS.Error
		return st
	}

	st.Service = sc.probePostgres(ctx, dsn, host, port)
	st.Service.Address = joinHostPort(host, port)
	st.Reachable = st.Service.Reachable
	if !st.Reachable {
		st.Error = st.Service.Error
	}
	return st
}

// ---------- low-level probes ----------

// probeS3 issues a ListBuckets call against the configured S3 endpoint
// and then a HeadBucket against the configured default bucket. This
// exercises TCP reachability, credentials, AND bucket existence/permission
// in one status check.
func (sc *StatusController) probeS3(ctx context.Context) CheckResult {
	start := time.Now()
	res := CheckResult{}

	if sc.s3Client == nil {
		res.Error = "s3 client not configured"
		res.LatencyMs = msSince(start)
		return res
	}

	bucket := sc.appConfig.S3DefaultBucket
	if bucket == "" {
		res.Error = "GARAGE_DEFAULT_BUCKET is not configured"
		res.LatencyMs = msSince(start)
		return res
	}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	out, err := sc.s3Client.ListBuckets(callCtx, &s3.ListBucketsInput{})
	if err != nil {
		res.LatencyMs = msSince(start)
		res.Error = err.Error()
		return res
	}

	if _, err := sc.s3Client.HeadBucket(callCtx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		res.LatencyMs = msSince(start)
		res.Error = fmt.Sprintf("head_bucket(%q): %v", bucket, err)
		return res
	}

	res.LatencyMs = msSince(start)
	res.Reachable = true
	res.Detail = fmt.Sprintf(
		"list_buckets ok (%d buckets); head_bucket(%q) ok",
		len(out.Buckets), bucket,
	)
	return res
}

// probeSpiceDB opens a short-lived insecure gRPC connection and calls the
// standard gRPC health check service with an empty service name to query
// overall server health.
func (sc *StatusController) probeSpiceDB(ctx context.Context, host, port string) CheckResult {
	start := time.Now()
	res := CheckResult{Address: joinHostPort(host, port)}

	addr := net.JoinHostPort(host, port)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		res.Error = fmt.Sprintf("create grpc client: %v", err)
		res.LatencyMs = msSince(start)
		return res
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := healthClient.Check(callCtx, &grpc_health_v1.HealthCheckRequest{Service: ""})
	res.LatencyMs = msSince(start)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		res.Error = fmt.Sprintf("spicedb not serving: %s", resp.GetStatus())
		return res
	}
	res.Reachable = true
	res.Detail = "grpc_health_v1: SERVING"
	return res
}

// probeWerSu calls GetUser with a random id and considers the service
// reachable as long as the call returns *some* response — even a gRPC
// NotFound error proves the service is up and answering RPCs.
func (sc *StatusController) probeWerSu(ctx context.Context) CheckResult {
	start := time.Now()
	res := CheckResult{}

	if sc.userGrpcClient == nil {
		res.Error = "user gRPC client not configured"
		res.LatencyMs = msSince(start)
		return res
	}

	randomID, err := randomString(16)
	if err != nil {
		res.Error = fmt.Sprintf("generate probe id: %v", err)
		res.LatencyMs = msSince(start)
		return res
	}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = (*sc.userGrpcClient).GetUser(callCtx, &proto.GetUserRequest{
		Id: &randomID,
	})
	res.LatencyMs = msSince(start)

	if err == nil {
		res.Reachable = true
		res.Detail = "GetUser returned a user"
		return res
	}

	// Any gRPC status means the server replied; only network/transport
	// failures indicate the service is down.
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound, codes.InvalidArgument:
			res.Reachable = true
			res.Detail = fmt.Sprintf("GetUser answered: %s", st.Code())
			return res
		}
		res.Error = st.String()
		return res
	}

	res.Error = err.Error()
	return res
}

// probeImgproxy issues an HTTP GET /health against the configured imgproxy
// address. We don't reuse a shared client because imgproxy is only probed
// here and we want a clean, bounded timeout per call.
func (sc *StatusController) probeImgproxy(ctx context.Context, host, port string) CheckResult {
	start := time.Now()
	res := CheckResult{Address: joinHostPort(host, port)}

	scheme := "http"
	if strings.EqualFold(port, "443") {
		scheme = "https"
	}
	base := sc.appConfig.ImgproxyAddress
	if !strings.Contains(base, "://") {
		base = scheme + "://" + joinHostPort(host, port)
	}
	target := strings.TrimRight(base, "/") + "/health"

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, target, nil)
	if err != nil {
		res.Error = fmt.Sprintf("build health request: %v", err)
		res.LatencyMs = msSince(start)
		return res
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	res.LatencyMs = msSince(start)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Sprintf("imgproxy /health returned HTTP %d", resp.StatusCode)
		return res
	}
	res.Reachable = true
	res.Detail = "GET /health returned 200 OK"
	return res
}

// probePostgres opens a Postgres connection via the pgx/stdlib driver
// and runs `SELECT 1`. The connection is closed immediately after the
// ping so this probe has no persistent state on the server.
func (sc *StatusController) probePostgres(ctx context.Context, dsn, host, port string) CheckResult {
	start := time.Now()
	res := CheckResult{Address: joinHostPort(host, port)}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		res.Error = fmt.Sprintf("open db: %v", err)
		res.LatencyMs = msSince(start)
		return res
	}
	defer db.Close()

	if err := db.PingContext(callCtx); err != nil {
		res.Error = fmt.Sprintf("ping db: %v", err)
		res.LatencyMs = msSince(start)
		return res
	}

	res.LatencyMs = msSince(start)
	res.Reachable = true
	res.Detail = "SELECT 1 ok"
	return res
}

// parsePostgresDSN extracts (host, port) from a libpq-style URL DSN such
// as `postgres://user:pass@host:5432/db?sslmode=disable`. Returns an
// error if the DSN can't be parsed or has no host.
func parsePostgresDSN(dsn string) (host, port string, err error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", "", fmt.Errorf("parse url: %w", err)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("DSN has no host")
	}
	host = u.Hostname()
	port = u.Port()
	if port == "" {
		port = defaultPostgresPort
	}
	return host, port, nil
}

// redactPostgresDSN returns the DSN with credentials replaced by `***`
// and the query string dropped. The query string carries the sslmode and
// any other flags; neither belongs in the status response.
//
//	postgres://alice:s3cret@db.example.com:5432/app?sslmode=disable
//	  -> postgres://***@db.example.com:5432/app
//
// If the DSN is empty or can't be parsed, the input is returned as-is
// (the caller handles the "not configured" / "parse failed" cases).
func redactPostgresDSN(dsn string) string {
	return redactURLCredentials(dsn)
}

// redactURLCredentials strips embedded `user:pass@` from a URL-shaped
// address and drops the query string. Bare `host:port` values and URLs
// without credentials pass through unchanged; addresses that can't be
// parsed are returned as-is.
//
//	http://alice:s3cret@garage:3900 -> http://***@garage:3900
//	garage:3900                      -> garage:3900
//	https://imgproxy.example.com     -> https://imgproxy.example.com
func redactURLCredentials(addr string) string {
	if addr == "" {
		return ""
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return addr
	}
	if u.User == nil {
		// No userinfo; just strip the query string.
		if i := strings.Index(addr, "?"); i >= 0 {
			return addr[:i]
		}
		return addr
	}
	// url.UserPassword percent-encodes the placeholder ("***" ->
	// "%2A%2A%2A"), which would surface literally to the frontend.
	// Do the swap on the raw string instead so the asterisks survive.
	userStart := strings.Index(addr, "://") + 3
	relAt := strings.Index(addr[userStart:], "@")
	if relAt < 0 {
		return addr
	}
	out := addr[:userStart] + "***" + addr[userStart+relAt:]
	if i := strings.Index(out, "?"); i >= 0 {
		return out[:i]
	}
	return out
}

// maskSensitiveValue mirrors `config.maskSensitiveValue`. It is duplicated
// here so the controllers package can scrub response strings without
// exporting the symbol from `config`. Keep the two in sync.
func maskSensitiveValue(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

// tokenPatterns match substrings that look like API keys, JWTs, or
// bearer tokens. Each match is replaced by `maskSensitiveValue` of the
// match so the surrounding text (hostnames, error context) is preserved.
var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                     // AWS access key ID
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), // JWT
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-+/=]{16,}`),                 // Bearer token
}

// maskKeysInString replaces each key-shaped substring in s with
// `maskSensitiveValue` of the match. Non-matching characters pass
// through unchanged.
func maskKeysInString(s string) string {
	for _, p := range tokenPatterns {
		s = p.ReplaceAllStringFunc(s, func(match string) string {
			return maskSensitiveValue(match)
		})
	}
	return s
}

// ---------- helpers ----------

// checkDNS resolves the given host and returns a CheckResult describing
// whether DNS resolution succeeded. An empty host, an IP literal, or
// "localhost" is always considered reachable — they don't need DNS.
func checkDNS(ctx context.Context, host string) CheckResult {
	start := time.Now()
	res := CheckResult{Address: host}

	if host == "" {
		res.Reachable = true
		res.Detail = "empty host"
		res.LatencyMs = msSince(start)
		return res
	}
	if ip := net.ParseIP(host); ip != nil {
		res.Reachable = true
		res.Detail = "ip literal"
		res.LatencyMs = msSince(start)
		return res
	}
	if host == "localhost" {
		res.Reachable = true
		res.Detail = "localhost"
		res.LatencyMs = msSince(start)
		return res
	}

	resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(resolveCtx, host)
	res.LatencyMs = msSince(start)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if len(addrs) == 0 {
		res.Error = "no addresses returned"
		return res
	}
	res.Reachable = true
	res.Detail = fmt.Sprintf("resolved to %d address(es): %s",
		len(addrs), strings.Join(addrs, ", "))
	return res
}

// splitHostPort parses an "host:port" or full URL into (host, port). If no
// port is present, defaultPort is returned.
func splitHostPort(raw, defaultPort string) (host, port string) {
	if raw == "" {
		return "", defaultPort
	}
	// Accept both bare "host:port" and full URLs like "http://host:port".
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		return h, p
	}
	// If raw looks like a bare host (no colon), treat the whole thing as
	// the host and use the default port.
	if !strings.Contains(raw, ":") {
		return raw, defaultPort
	}
	// Raw has a colon but SplitHostPort rejected it (e.g. "::1"). Fall back
	// to using the default port.
	return raw, defaultPort
}

func joinHostPort(host, port string) string {
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// randomString returns a hex-encoded random string suitable for probing
// with a non-existent user id.
func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func msSince(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}
