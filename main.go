package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
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

	if config.TrustBundlePath == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_bundle_path must be configured")
	}

	// Validate that trust bundle file exists and is readable
	if _, err := ioutil.ReadFile(config.TrustBundlePath); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to read trust bundle: %v", err)
	}

	p.setConfig(config)
	
	if p.logger != nil {
		p.logger.Info("Plugin configured successfully",
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
	certChain, rootCerts, err := p.signCSRWithExternalCA(ctx, config, req.Csr, req.PreferredTtl)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to sign CSR with external CA: %v", err)
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

// callExternalCAAPI makes the actual API call to your external CA
func (p *Plugin) callExternalCAAPI(ctx context.Context, config *Config, csrBytes []byte, ttl int32) ([][]byte, error) {
	// TODO: Implement your CA-specific API integration here
	// This is a placeholder that you need to customize based on your CA
	
	p.logger.Warn("Using placeholder CA integration - implement actual CA API calls")

	// Example structure for CA API integration:
	/*
		import (
			"bytes"
			"encoding/json"
			"io/ioutil"
			"net/http"
			"time"
		)
		
		client := &http.Client{Timeout: 30 * time.Second}
		
		// Prepare request
		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})
		
		reqBody := map[string]interface{}{
			"csr": string(csrPEM),
			"ttl": ttl,
		}
		
		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}
		
		// Make API request
		req, err := http.NewRequestWithContext(ctx, "POST", config.CAURL+"/sign", bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, err
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+config.APIKey)
		
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, fmt.Errorf("CA returned error: %s - %s", resp.Status, string(body))
		}
		
		// Parse response
		var result struct {
			Certificate string   `json:"certificate"`
			Chain       []string `json:"chain"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}
		
		// Convert PEM to DER format (SPIRE expects DER-encoded certificates)
		var certChain [][]byte
		for _, certPEM := range append([]string{result.Certificate}, result.Chain...) {
			block, _ := pem.Decode([]byte(certPEM))
			if block != nil && block.Type == "CERTIFICATE" {
				certChain = append(certChain, block.Bytes)
			}
		}
		
		if len(certChain) == 0 {
			return nil, fmt.Errorf("no valid certificates in CA response")
		}
		
		return certChain, nil
	*/

	return nil, fmt.Errorf("CA API integration not implemented - customize this method for your CA")
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
