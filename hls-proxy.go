package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config represents the configuration structure
type Config struct {
	ListenAddress   string               `json:"listen_address"`
	TargetHost      string               `json:"target_host"`
	Headers         map[string]string    `json:"headers"`
	RewriteRules    []RewriteRule        `json:"rewrite_rules"`
	LogRequests     bool                 `json:"log_requests"`
	LogResponses    bool                 `json:"log_responses"`
	Timeout         int                  `json:"timeout"` // in seconds
	TLS             TLSConfig            `json:"tls"`
	ContentRewrites []ContentRewriteRule `json:"content_rewrites"`
}

// ContentRewriteRule defines a transformation rule for response content
type ContentRewriteRule struct {
	Pattern      string   `json:"pattern"`       // Regex pattern to match
	Replacement  string   `json:"replacement"`   // Replacement string
	ContentTypes []string `json:"content_types"` // Apply only to these content types (empty means all)
	Global       bool     `json:"global"`        // Replace all occurrences if true
}

// TLSConfig holds TLS configuration settings
type TLSConfig struct {
	Enabled        bool   `json:"enabled"`
	CertFile       string `json:"cert_file"`
	KeyFile        string `json:"key_file"`
	SkipTlsVerify  bool   `json:"skip_tls_verify"`  // Skip verification of target origin certificate
	ClientCertFile string `json:"client_cert_file"` // Client certificate for mTLS with target
	ClientKeyFile  string `json:"client_key_file"`  // Client key for mTLS with target
	RootCAFile     string `json:"root_ca_file"`     // Custom CA roots for target verification
}

// RewriteRule defines a URL rewrite rule
type RewriteRule struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
}

var (
	configFile     = flag.String("config", "", "Path to config file")
	targetHost     = flag.String("target", "", "Target host to proxy (overrides config file)")
	listenAddr     = flag.String("listen", "", "Address to listen on (overrides config file)")
	addHeader      = flag.String("header", "", "Add header in format 'Name:Value' (can be specified multiple times)")
	logRequests    = flag.Bool("log-requests", false, "Log all requests")
	logFile        = flag.String("log", "", "Log file path")
	tlsEnabled     = flag.Bool("tls", false, "Enable TLS for the proxy server")
	tlsCert        = flag.String("tls-cert", "", "TLS certificate file path")
	tlsKey         = flag.String("tls-key", "", "TLS key file path")
	clientCert     = flag.String("client-cert", "", "Client certificate for mTLS with target")
	clientKey      = flag.String("client-key", "", "Client key for mTLS with target")
	rootCAFile     = flag.String("root-ca", "", "Custom CA roots file for target verification")
	skipTlsVerify  = flag.Bool("skip-tls-verify", false, "Skip TLS verification of target origin")
	contentRewrite = flag.String("content-rewrite", "", "Add content rewrite in format 'pattern:replacement[:content-type]'")
	globalRewrite  = flag.Bool("global-rewrite", false, "Apply content rewrite globally (all occurrences)")
)

func main() {
	flag.Parse()

	// Setup logging
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Load config
	config := Config{
		ListenAddress: ":8080",
		Headers:       make(map[string]string),
		LogRequests:   false,
		LogResponses:  false,
		Timeout:       30,
	}

	if *configFile != "" {
		err := loadConfig(*configFile, &config)
		if err != nil {
			log.Fatalf("Error loading config: %v", err)
		}
	}

	// Override config with command line flags
	if *targetHost != "" {
		config.TargetHost = *targetHost
	}

	if *listenAddr != "" {
		config.ListenAddress = *listenAddr
	}

	if *logRequests {
		config.LogRequests = true
	}

	// TLS configuration from command line
	if *tlsEnabled {
		config.TLS.Enabled = true
	}
	if *tlsCert != "" {
		config.TLS.CertFile = *tlsCert
	}
	if *tlsKey != "" {
		config.TLS.KeyFile = *tlsKey
	}
	if *skipTlsVerify {
		config.TLS.SkipTlsVerify = true
	}
	if *clientCert != "" {
		config.TLS.ClientCertFile = *clientCert
	}
	if *clientKey != "" {
		config.TLS.ClientKeyFile = *clientKey
	}
	if *rootCAFile != "" {
		config.TLS.RootCAFile = *rootCAFile
	}

	// Add headers from command line
	if *addHeader != "" {
		parts := strings.SplitN(*addHeader, ":", 2)
		if len(parts) == 2 {
			config.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Add content rewrite rule from command line
	if *contentRewrite != "" {
		parts := strings.SplitN(*contentRewrite, ":", 3)
		if len(parts) >= 2 {
			rule := ContentRewriteRule{
				Pattern:     parts[0],
				Replacement: parts[1],
				Global:      *globalRewrite,
			}

			// If content type is specified
			if len(parts) == 3 && parts[2] != "" {
				rule.ContentTypes = []string{parts[2]}
			}

			config.ContentRewrites = append(config.ContentRewrites, rule)
		}
	}

	if config.TargetHost == "" {
		log.Fatal("Target host is required. Specify in config file or with -target flag")
	}

	// Print configuration
	fmt.Printf("Starting HLS Proxy with the following configuration:\n")
	fmt.Printf("  Listening on: %s\n", config.ListenAddress)
	fmt.Printf("  Target host: %s\n", config.TargetHost)
	fmt.Printf("  TLS enabled: %v\n", config.TLS.Enabled)
	if config.TLS.Enabled {
		fmt.Printf("  TLS cert file: %s\n", config.TLS.CertFile)
		fmt.Printf("  TLS key file: %s\n", config.TLS.KeyFile)
	}
	fmt.Printf("  Target TLS verification skip: %v\n", config.TLS.SkipTlsVerify)
	fmt.Printf("  Headers:\n")
	for k, v := range config.Headers {
		fmt.Printf("    %s: %s\n", k, v)
	}
	fmt.Printf("  Rewrite rules: %d rules defined\n", len(config.RewriteRules))
	fmt.Printf("  Content rewrite rules: %d rules defined\n", len(config.ContentRewrites))
	fmt.Printf("  Logging: requests=%v, responses=%v\n", config.LogRequests, config.LogResponses)

	// Parse the target URL
	targetURL, err := url.Parse(config.TargetHost)
	if err != nil {
		log.Fatalf("Invalid target host URL: %v", err)
	}

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Customize the Director func to add our headers and handle rewrites
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Apply headers
		for k, v := range config.Headers {
			req.Header.Set(k, v)
		}

		// Apply URL rewrite rules
		for _, rule := range config.RewriteRules {
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				log.Printf("Invalid rewrite pattern '%s': %v", rule.Pattern, err)
				continue
			}
			req.URL.Path = re.ReplaceAllString(req.URL.Path, rule.Replacement)
		}

		if config.LogRequests {
			log.Printf("Proxying request: %s %s", req.Method, req.URL.String())
			for k, v := range req.Header {
				log.Printf("  Header: %s: %s", k, v)
			}
		}
	}

	// Customize transport
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: time.Duration(config.Timeout) * time.Second,
	}

	// Configure TLS for outgoing connections to target
	if strings.HasPrefix(config.TargetHost, "https://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.TLS.SkipTlsVerify,
		}

		// Load custom Root CA if specified
		if config.TLS.RootCAFile != "" {
			rootCAPem, err := os.ReadFile(config.TLS.RootCAFile)
			if err != nil {
				log.Fatalf("Error loading root CA file: %v", err)
			}

			rootCAs, err := x509.SystemCertPool()
			if err != nil {
				rootCAs = x509.NewCertPool()
			}

			if ok := rootCAs.AppendCertsFromPEM(rootCAPem); !ok {
				log.Fatalf("Failed to append CA cert to pool")
			}

			tlsConfig.RootCAs = rootCAs
		}

		// Load client certificates for mTLS if specified
		if config.TLS.ClientCertFile != "" && config.TLS.ClientKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(config.TLS.ClientCertFile, config.TLS.ClientKeyFile)
			if err != nil {
				log.Fatalf("Error loading client certificate: %v", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		transport.TLSClientConfig = tlsConfig
	}

	proxy.Transport = transport

	// Add response logging if enabled
	if config.LogResponses {
		originalTransport := proxy.Transport
		proxy.Transport = &loggingTransport{
			transport: originalTransport,
		}
	}

	// Create a custom handler that wraps the proxy and modifies responses
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If we have content rewrite rules, use our response modifier
		if len(config.ContentRewrites) > 0 {
			modifier := newResponseModifier(w, &config)
			proxy.ServeHTTP(modifier, r)
			modifier.Flush()
		} else {
			// Otherwise, just use the proxy directly
			proxy.ServeHTTP(w, r)
		}
	})

	// Create the server
	server := &http.Server{
		Addr:    config.ListenAddress,
		Handler: handler,
	}

	// Start the server
	if config.TLS.Enabled {
		if config.TLS.CertFile == "" || config.TLS.KeyFile == "" {
			log.Fatal("TLS enabled but certificate or key file not specified")
		}

		fmt.Printf("Proxy server started with TLS on %s\n", config.ListenAddress)
		fmt.Printf("To use with mediastreamvalidator: mediastreamvalidator https://localhost%s/path/to/manifest.m3u8\n", config.ListenAddress)
		log.Fatal(server.ListenAndServeTLS(config.TLS.CertFile, config.TLS.KeyFile))
	} else {
		fmt.Printf("Proxy server started on %s\n", config.ListenAddress)
		fmt.Printf("To use with mediastreamvalidator: mediastreamvalidator http://localhost%s/path/to/manifest.m3u8\n", config.ListenAddress)
		log.Fatal(server.ListenAndServe())
	}
}

// Custom transport for logging responses
type loggingTransport struct {
	transport http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	log.Printf("Response from %s: status=%d, content-type=%s, content-length=%d",
		req.URL.String(), resp.StatusCode, resp.Header.Get("Content-Type"), resp.ContentLength)

	return resp, err
}

// responseModifier wraps a http.ResponseWriter to modify the response body
type responseModifier struct {
	w             http.ResponseWriter
	config        *Config
	contentType   string
	buffer        *bytes.Buffer
	statusCode    int
	headerWritten bool
}

// Create a new response modifier
func newResponseModifier(w http.ResponseWriter, config *Config) *responseModifier {
	return &responseModifier{
		w:             w,
		config:        config,
		buffer:        &bytes.Buffer{},
		statusCode:    http.StatusOK,
		headerWritten: false,
	}
}

// Implement http.ResponseWriter interface
func (rm *responseModifier) Header() http.Header {
	return rm.w.Header()
}

func (rm *responseModifier) WriteHeader(statusCode int) {
	rm.statusCode = statusCode
	// Don't actually write the header yet, as we need to buffer the response
	// to potentially modify it
}

func (rm *responseModifier) Write(b []byte) (int, error) {
	// Store the content type for later content-type specific rewrites
	if !rm.headerWritten {
		rm.contentType = rm.w.Header().Get("Content-Type")
	}

	// Write to our buffer instead of directly to the response writer
	return rm.buffer.Write(b)
}

// Flush writes the buffered data to the underlying ResponseWriter
func (rm *responseModifier) Flush() {
	// Get the buffered content
	content := rm.buffer.String()

	// Apply content rewrites
	for _, rule := range rm.config.ContentRewrites {
		// Skip if this rule doesn't apply to this content type
		if len(rule.ContentTypes) > 0 {
			matches := false
			for _, ct := range rule.ContentTypes {
				if strings.Contains(rm.contentType, ct) {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
		}

		// Apply the regex replacement
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			log.Printf("Invalid content rewrite pattern '%s': %v", rule.Pattern, err)
			continue
		}

		if rule.Global {
			content = re.ReplaceAllString(content, rule.Replacement)
		} else {
			content = re.ReplaceAllStringFunc(content, func(match string) string {
				// Only replace the first occurrence
				replaced := re.ReplaceAllString(match, rule.Replacement)
				// Update the pattern to never match again (hacky but works for this purpose)
				rule.Pattern = "a^" // This will never match anything
				return replaced
			})
		}
	}

	// Now actually write the headers
	rm.w.WriteHeader(rm.statusCode)
	rm.headerWritten = true

	// Write the potentially modified content
	rm.w.Write([]byte(content))
}

// Implement http.Flusher interface if the underlying ResponseWriter supports it
func (rm *responseModifier) Flush2() {
	if flusher, ok := rm.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// loadConfig loads the configuration from a file
func loadConfig(filename string, config *Config) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(config)
}
