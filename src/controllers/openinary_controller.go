package controllers

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/KuramaSyu/WerSu-Rest/src/utils"
	"github.com/gin-gonic/gin"
)

// OpeninaryController proxies upload, delete, and image transformation requests
// to an upstream Openinary server.
type OpeninaryController struct {
	proxy   *httputil.ReverseProxy
	baseURL *url.URL
	apiKey  string
}

// NewOpeninaryController creates a proxy controller for an Openinary instance.
func NewOpeninaryController(baseURL string, apiKey string) *OpeninaryController {
	if baseURL == "" {
		return &OpeninaryController{}
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		log.Printf("invalid OPENINARY_BASE_URL %q: %v", baseURL, err)
		return &OpeninaryController{}
	}

	// create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	// replace request URL to match openinary endpoint
	proxy.Director = func(req *http.Request) {
		trimmedPath := strings.TrimPrefix(req.URL.Path, "/api/openinary")
		if trimmedPath == "" {
			trimmedPath = "/"
		}
		if !strings.HasPrefix(trimmedPath, "/") {
			trimmedPath = "/" + trimmedPath
		}

		req.URL.Scheme = parsedURL.Scheme
		req.URL.Host = parsedURL.Host
		req.URL.Path = singleJoiningSlash(parsedURL.Path, trimmedPath)
		req.Host = parsedURL.Host

		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("openinary proxy error for %s %s: %v", r.Method, r.URL.String(), err)
		http.Error(w, "failed to reach Openinary upstream", http.StatusBadGateway)
	}

	return &OpeninaryController{proxy: proxy, baseURL: parsedURL, apiKey: apiKey}
}

// Handle forwards the incoming request to the configured Openinary upstream.
func (oc *OpeninaryController) Handle(c *gin.Context) {
	if oc == nil || oc.proxy == nil || oc.baseURL == nil {
		utils.SetGinError(c, http.StatusServiceUnavailable, fmt.Errorf("openinary proxy is not configured"))
		return
	}

	oc.proxy.ServeHTTP(c.Writer, c.Request)
}

func singleJoiningSlash(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	ashasSuffix := strings.HasSuffix(a, "/")
	bhasPrefix := strings.HasPrefix(b, "/")
	switch {
	case ashasSuffix && bhasPrefix:
		return a + b[1:]
	case !ashasSuffix && !bhasPrefix:
		return a + "/" + b
	default:
		return a + b
	}
}
