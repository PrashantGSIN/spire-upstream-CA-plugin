package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// Compile-time assertion to ensure plugin conforms to pluginsdk.NeedsLogger
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

// Config defines the configuration for the plugin
type Config struct {
	CAEndpoint      string `hcl:"ca_endpoint"`
	CAURL           string `hcl:"ca_url"`
	APIKey          string `hcl:"api_key"`
	APISecret       string `hcl:"api_secret"`
	CertPath        string `hcl:"cert_path"`
	KeyPath         string `hcl:"key_path"`
	TrustBundlePath string `hcl:"trust_bundle_path"`
	Insecure        bool   `hcl:"insecure"`
}

// Plugin implements the UpstreamAuthority plugin
type Plugin struct {
	// UnimplementedUpstreamAuthorityServer is embedded to satisfy gRPC
	upstreamauthorityv1.UnimplementedUpstreamAuthorityServer

	// UnimplementedConfigServer is embedded to satisfy gRPC
	configv1.UnimplementedConfigServer

	// Configuration should be set atomically
	configMtx sync.RWMutex
	config    *Config

	// The logger received from the framework via the SetLogger method
	logger hclog.Logger

	// HVCA client for making API calls
	hvClient *hvclient.Client
}

func main() {
	plugin := new(Plugin)
	// Serve the plugin. This function call will not return.
	pluginmain.Serve(
		upstreamauthorityv1.UpstreamAuthorityPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, it may be invoked to reconfigure the plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	// Validate configuration
	if config.CAEndpoint == "" && config.CAURL == "" {
		return nil, status.Error(codes.InvalidArgument, "ca_endpoint or ca_url must be configured")
	}

	if config.APIKey == "" {
		return nil, status.Error(codes.InvalidArgument, "api_key must be configured")
	}

	if config.CertPath == "" || config.KeyPath == "" {
		return nil, status.Error(codes.InvalidArgument, "cert_path and key_path must be configured for mTLS")
	}

	if config.TrustBundlePath == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_bundle_path must be configured")
	}

	// Validate that files exist
	if _, err := ioutil.ReadFile(config.TrustBundlePath); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to read trust bundle: %v", err)
	}

	// Initialize GlobalSign hvclient
	hvConfig, err := p.createHVClientConfig(config)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create hvclient config: %v", err)
	}

	hvClient, err := hvclient.NewClient(ctx, hvConfig)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create hvclient: %v", err)
	}

	p.hvClient = hvClient
	p.setConfig(config)
	
	if p.logger != nil {
		p.logger.Info("Plugin configured successfully with GlobalSign hvclient",
			"ca_endpoint", config.CAEndpoint,
			"ca_url", config.CAURL,
		)
	}

	return &configv1.ConfigureResponse{}, nil
}

// SetLogger is called by the framework when the plugin is loaded
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// setConfig replaces the configuration atomically under a write lock
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

// getConfig gets the configuration under a read lock
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// MintX509CAAndSubscribe implements the UpstreamAuthority MintX509CAAndSubscribe RPC.
// Mints an X.509 CA and responds with the signed X.509 CA certificate chain and upstream X.509 roots.
//
// Implementation note:
// The stream should be kept open in the face of transient errors encountered while
// tracking changes to the upstream X.509 roots as SPIRE Server will not reopen a
// closed stream until the next X.509 CA rotation.
func (p *Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	ctx := stream.Context()

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	p.logger.Info("Minting X.509 CA certificate from external CA")

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse CSR: %v", err)
	}

	p.logger.Debug("CSR parsed successfully",
		"subject", csr.Subject.String(),
		"dns_names", csr.DNSNames,
	)

	// Send CSR to external CA and get signed certificate
	certChainBytes, rootCertsBytes, err := p.signCSRWithExternalCA(ctx, config, req.Csr, req.PreferredTtl)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to sign CSR with external CA: %v", err)
	}

	// Convert [][]byte to []*types.X509Certificate
	certChain := make([]*types.X509Certificate, len(certChainBytes))
	for i, certBytes := range certChainBytes {
		certChain[i] = &types.X509Certificate{
			Asn1: certBytes,
		}
	}

	rootCerts := make([]*types.X509Certificate, len(rootCertsBytes))
	for i, certBytes := range rootCertsBytes {
		rootCerts[i] = &types.X509Certificate{
			Asn1: certBytes,
		}
	}

	// Send the minted certificate back
	resp := &upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       certChain,
		UpstreamX509Roots: rootCerts,
	}

	if err := stream.Send(resp); err != nil {
		return status.Errorf(codes.Internal, "failed to send response: %v", err)
	}

	p.logger.Info("X.509 CA certificate minted successfully")

	// Keep the stream open for updates (or until context is cancelled)
	// In a production implementation, you could monitor for upstream root changes
	// and send updates on the stream. For this basic implementation, we just
	// keep the stream alive until cancelled.
	<-ctx.Done()
	return nil
}

// PublishJWTKeyAndSubscribe implements the UpstreamAuthority PublishJWTKeyAndSubscribe RPC.
// Publishes a JWT signing key upstream and responds with the upstream JWT keys.
//
// This RPC is optional and returns NotImplemented for this plugin as it focuses
// on X.509 certificate integration with external CAs.
//
// Implementation note:
// The stream should be kept open in the face of transient errors encountered while
// tracking changes to the upstream JWT keys as SPIRE Server will not reopen a
// closed stream until the next JWT key rotation.
func (p *Plugin) PublishJWTKeyAndSubscribe(req *upstreamauthorityv1.PublishJWTKeyRequest, stream upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}
	// Silence unused variable warning
	_ = config

	return status.Error(codes.Unimplemented, "JWT key publishing is not supported by this plugin")
}

// signCSRWithExternalCA sends the CSR to external CA and retrieves signed certificate
func (p *Plugin) signCSRWithExternalCA(ctx context.Context, config *Config, csrBytes []byte, ttl int32) ([][]byte, [][]byte, error) {
	// This is where you integrate with your specific CA
	// Examples: HashiCorp Vault, AWS Certificate Manager, Azure Key Vault, etc.
	
	p.logger.Info("Sending CSR to external CA",
		"endpoint", config.CAEndpoint,
		"ttl", ttl,
	)

	// Example implementation - customize based on your CA's API
	// 1. Connect to external CA API
	// 2. Submit CSR for signing
	// 3. Retrieve signed certificate and chain
	// 4. Return certificate chain and root certificates

	// Call external CA API to sign the CSR
	certChain, err := p.callExternalCAAPI(ctx, config, csrBytes, ttl)
	if err != nil {
		return nil, nil, fmt.Errorf("external CA API call failed: %w", err)
	}

	// Get root certificates from the CA
	rootCerts, err := p.fetchCARootCertificates(ctx, config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch CA root certificates: %w", err)
	}

	return certChain, rootCerts, nil
}

// callExternalCAAPI makes the actual API call to GlobalSign HVCA using hvclient
func (p *Plugin) callExternalCAAPI(ctx context.Context, config *Config, csrBytes []byte, ttl int32) ([][]byte, error) {
	p.logger.Info("Calling GlobalSign HVCA API to sign CSR using hvclient")

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Extract Common Name from CSR subject or use a default
	commonName := csr.Subject.CommonName
	if commonName == "" {
		// If CSR doesn't have CN, use the first DNS name or a default
		if len(csr.DNSNames) > 0 {
			commonName = csr.DNSNames[0]
		} else {
			// Use a default CN for SPIRE intermediate CA
			commonName = "SPIRE Intermediate CA"
		}
		p.logger.Info("CSR missing Common Name, using generated value", "cn", commonName)
	}

	// Create hvclient Request with the CSR and required subject DN
	hvRequest := &hvclient.Request{
		CSR: csr,
		Subject: &hvclient.DN{
			CommonName: commonName,
		},
		Validity: &hvclient.Validity{
			NotBefore: time.Now(),
			// Calculate NotAfter based on TTL (ttl is in seconds)
			NotAfter: time.Now().Add(time.Duration(ttl) * time.Second),
		},
		Signature: &hvclient.Signature{
			HashAlgorithm: "SHA-256",
		},
	}

	p.logger.Debug("Submitting certificate request to GlobalSign HVCA",
		"ttl_seconds", ttl,
		"common_name", commonName,
		"not_after", hvRequest.Validity.NotAfter,
		"signature_hash", "SHA-256",
	)

	// Request certificate from HVCA
	serialNumber, err := p.hvClient.CertificateRequest(ctx, hvRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to request certificate from HVCA: %w", err)
	}

	p.logger.Info("Certificate request successful", "serial_number", serialNumber.Text(16))

	// Retrieve the issued certificate
	certInfo, err := p.hvClient.CertificateRetrieve(ctx, serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificate: %w", err)
	}

	// Parse the PEM certificate
	block, _ := pem.Decode([]byte(certInfo.PEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	certChain := [][]byte{block.Bytes}
	p.logger.Debug("Successfully retrieved certificate from HVCA")

	// Get the trust chain (intermediate certificates)
	trustChain, err := p.hvClient.TrustChain(ctx)
	if err != nil {
		p.logger.Warn("Failed to retrieve trust chain", "error", err)
	} else {
		// Add intermediate certificates to the chain
		// trustChain is []*x509.Certificate from hvclient.TrustChain()
		for i, cert := range trustChain {
			certChain = append(certChain, cert.Raw)
			p.logger.Debug("Added intermediate certificate to chain", "index", i)
		}
	}

	p.logger.Info("Successfully retrieved certificate from GlobalSign HVCA",
		"chain_length", len(certChain),
		"serial_number", serialNumber.Text(16),
	)

	return certChain, nil
}

// getTrustChain retrieves intermediate certificates from GlobalSign HVCA
func (p *Plugin) getTrustChain(ctx context.Context, config *Config, client *http.Client) ([][]byte, error) {
	baseURL := config.CAURL
	if baseURL == "" {
		baseURL = config.CAEndpoint
	}
	
	apiEndpoint := baseURL
	if !strings.Contains(apiEndpoint, "/v2") {
		apiEndpoint += "/v2"
	}
	apiEndpoint += "/trustchain"
	
	req, err := http.NewRequestWithContext(ctx, "GET", apiEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create trustchain request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+config.APIKey)
		req.Header.Set("X-API-Key", config.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute trustchain request: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read trustchain response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trustchain request failed: %s", resp.Status)
	}

	// Parse trustchain response
	var trustChainResp struct {
		Certificates []string `json:"certificates"`
		Chain        []string `json:"chain"`
		TrustChain   []string `json:"trust_chain"`
	}

	if err := json.Unmarshal(body, &trustChainResp); err != nil {
		return nil, fmt.Errorf("failed to parse trustchain response: %w", err)
	}

	// Try different field names
	chains := trustChainResp.Certificates
	if len(chains) == 0 {
		chains = trustChainResp.Chain
	}
	if len(chains) == 0 {
		chains = trustChainResp.TrustChain
	}

	var intermediates [][]byte
	for i, certPEM := range chains {
		block, _ := pem.Decode([]byte(certPEM))
		if block != nil && block.Type == "CERTIFICATE" {
			intermediates = append(intermediates, block.Bytes)
			p.logger.Debug("Added intermediate certificate", "index", i)
		}
	}

	return intermediates, nil
}

// fetchCARootCertificates retrieves root certificates from the CA
func (p *Plugin) fetchCARootCertificates(ctx context.Context, config *Config) ([][]byte, error) {
	// Read root certificates from the configured trust bundle file
	if config.TrustBundlePath != "" {
		certs, err := p.readCertificatesFromFile(config.TrustBundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read trust bundle: %w", err)
		}
		
		p.logger.Debug("Loaded root certificates from trust bundle",
			"path", config.TrustBundlePath,
			"count", len(certs),
		)
		
		return certs, nil
	}

	// Alternative: Fetch from CA API
	// TODO: Implement API-based root certificate fetching if needed
	/*
		import (
			"net/http"
			"io/ioutil"
		)
		
		client := &http.Client{Timeout: 30 * time.Second}
		req, err := http.NewRequestWithContext(ctx, "GET", config.CAURL+"/roots", nil)
		if err != nil {
			return nil, err
		}
		
		req.Header.Set("Authorization", "Bearer "+config.APIKey)
		
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		
		pemData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		
		// Parse PEM data
		var certs [][]byte
		for {
			block, rest := pem.Decode(pemData)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certs = append(certs, block.Bytes)
			}
			pemData = rest
		}
		
		return certs, nil
	*/

	return nil, fmt.Errorf("trust_bundle_path not configured")
}

// readCertificatesFromFile reads certificates from a PEM file
func (p *Plugin) readCertificatesFromFile(path string) ([][]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var certs [][]byte
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in file")
	}

	return certs, nil
}

// createHTTPClient creates an HTTP client with optional mTLS configuration
func (p *Plugin) createHTTPClient(config *Config) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Insecure,
	}

	// Load client certificate if provided (for mTLS)
	if config.CertPath != "" && config.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		p.logger.Info("Loaded client certificate for mTLS authentication",
			"cert_path", config.CertPath,
		)
	}

	// Create HTTP transport with TLS config
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return client, nil
}

// createHVClientConfig creates hvclient configuration from plugin config
func (p *Plugin) createHVClientConfig(config *Config) (*hvclient.Config, error) {
	// Determine base URL
	baseURL := config.CAURL
	if baseURL == "" {
		baseURL = config.CAEndpoint
	}

	if p.logger != nil {
		p.logger.Debug("Creating hvclient configuration",
			"url", baseURL,
			"cert_path", config.CertPath,
			"key_path", config.KeyPath,
		)
	}

	// Load TLS certificate and key for mTLS
	cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Parse the X.509 certificate from the cert
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	// Use api_secret if provided, otherwise fall back to api_key
	apiSecret := config.APISecret
	if apiSecret == "" {
		apiSecret = config.APIKey
		if p.logger != nil {
			p.logger.Warn("api_secret not configured, using api_key for both key and secret")
		}
	}

	hvConfig := &hvclient.Config{
		URL:       baseURL,
		APIKey:    config.APIKey,
		APISecret: apiSecret,
		TLSCert:   x509Cert,
		TLSKey:    cert.PrivateKey,
	}

	if p.logger != nil {
		p.logger.Info("Created GlobalSign hvclient configuration",
			"url", baseURL,
			"has_api_key", config.APIKey != "",
			"has_api_secret", config.APISecret != "",
			"cert_subject", x509Cert.Subject.String(),
		)
	}

	return hvConfig, nil
}
