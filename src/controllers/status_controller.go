package controllers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KuramaSyu/WerSu-Rest/src/config"
	"github.com/KuramaSyu/WerSu-Rest/src/proto"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// defaultImgproxyPort is the port the imgproxy HTTP server listens on by
// default; used as a fallback if IMGPROXY_ADDRESS doesn't include a port.
const defaultImgproxyPort = "8083"

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
// @Description  Garage (S3), SpiceDB (gRPC), imgproxy (HTTP /health), and
// @Description  the WerSu gRPC backend.
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
		results = make(map[string]ServiceStatus, 4)
	)

	run := func(name string, fn func(context.Context) ServiceStatus) {
		defer wg.Done()
		s := fn(ctx)
		mu.Lock()
		results[name] = s
		mu.Unlock()
	}

	wg.Add(4)
	go run("garage", sc.checkGarage)
	go run("spicedb", sc.checkSpiceDB)
	go run("imgproxy", sc.checkImgproxy)
	go run("wersu", sc.checkWerSu)
	wg.Wait()

	resp := StatusResponse{
		Garage:    results["garage"],
		SpiceDB:   results["spicedb"],
		Imgproxy:  results["imgproxy"],
		WerSu:     results["wersu"],
		CheckedAt: time.Now().UTC(),
	}
	resp.OverallOK = resp.Garage.Reachable &&
		resp.SpiceDB.Reachable &&
		resp.WerSu.Reachable &&
		resp.Imgproxy.Reachable

	c.JSON(http.StatusOK, resp)
}

// ---------- individual probes ----------

func (sc *StatusController) checkGarage(ctx context.Context) ServiceStatus {
	st := ServiceStatus{Address: sc.appConfig.S3Endpoint}

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
	st := ServiceStatus{Address: sc.appConfig.ImgproxyAddress}

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
