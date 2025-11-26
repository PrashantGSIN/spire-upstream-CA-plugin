# SPIRE UpstreamAuthority Plugin for External CA

This plugin integrates SPIRE Server with an external Certificate Authority (CA) for X.509 certificate signing.

## Features

- Custom integration with external CA systems
- Configurable CA endpoints and authentication
- Support for certificate chain retrieval
- Flexible trust bundle management

## Configuration

### Plugin Configuration (server.conf)

```hcl
plugins {
    UpstreamAuthority "external_ca" {
        plugin_cmd = "/path/to/spire-upstream-ca-plugin"
        plugin_checksum = "sha256:your_checksum_here"
        plugin_data {
            ca_endpoint = "https://ca.example.com"
            ca_url = "https://ca.example.com/api/v1"
            api_key = "your-api-key"
            trust_bundle_path = "/path/to/ca-roots.pem"
            insecure = false
        }
    }
}
```

### Configuration Parameters

- **ca_endpoint**: The endpoint URL of your external CA
- **ca_url**: The API URL for certificate signing operations
- **api_key**: Authentication key/token for the CA API
- **cert_path**: (Optional) Client certificate for mTLS authentication
- **key_path**: (Optional) Client key for mTLS authentication
- **trust_bundle_path**: Path to CA root certificates (PEM format)
- **insecure**: Skip TLS verification (not recommended for production)

## Building

```bash
cd spire-upstream-ca-plugin
go mod download
go build -o spire-upstream-ca-plugin
```

## Installation

1. Build the plugin binary
2. Place it in a secure location accessible by SPIRE Server
3. Calculate the SHA256 checksum: `sha256sum spire-upstream-ca-plugin`
4. Update SPIRE Server configuration with plugin details
5. Restart SPIRE Server

## Customization Guide

### Integrating with Your CA

The plugin provides placeholder methods that you need to customize for your specific CA:

#### 1. **callExternalCAAPI** method
Implement the actual API call to your CA for certificate signing.

Example integrations:
- **HashiCorp Vault**: Use Vault API client
- **AWS ACM Private CA**: Use AWS SDK
- **Azure Key Vault**: Use Azure SDK
- **EJBCA**: Use EJBCA REST API
- **Custom CA**: Implement your CA's API protocol

#### 2. **fetchCARootCertificates** method
Retrieve root certificates from your CA or trust bundle.

#### 3. **readCertificatesFromFile** method
Parse PEM-encoded certificates from files.

### Example: HashiCorp Vault Integration

```go
import (
    "github.com/hashicorp/vault/api"
)

func (p *Plugin) callExternalCAAPI(ctx context.Context, csrBytes []byte, ttl int32) ([][]byte, error) {
    config := api.DefaultConfig()
    config.Address = p.config.CAURL
    
    client, err := api.NewClient(config)
    if err != nil {
        return nil, err
    }
    
    client.SetToken(p.config.APIKey)
    
    csrPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE REQUEST",
        Bytes: csrBytes,
    })
    
    data := map[string]interface{}{
        "csr": string(csrPEM),
        "ttl": fmt.Sprintf("%ds", ttl),
    }
    
    secret, err := client.Logical().Write("pki/sign/spire", data)
    if err != nil {
        return nil, err
    }
    
    // Parse certificate chain from Vault response
    // ...
}
```

### Example: REST API Integration

```go
import (
    "net/http"
    "encoding/json"
)

func (p *Plugin) callExternalCAAPI(ctx context.Context, csrBytes []byte, ttl int32) ([][]byte, error) {
    client := &http.Client{Timeout: 30 * time.Second}
    
    csrPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE REQUEST",
        Bytes: csrBytes,
    })
    
    reqBody := map[string]interface{}{
        "csr": string(csrPEM),
        "ttl": ttl,
    }
    
    jsonData, _ := json.Marshal(reqBody)
    req, _ := http.NewRequestWithContext(ctx, "POST", 
        p.config.CAURL+"/api/sign", bytes.NewBuffer(jsonData))
    
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
    
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    // Parse response and extract certificates
    // ...
}
```

## Testing

```bash
# Unit tests
go test ./...

# Integration test with SPIRE
spire-server run -config server.conf
```

## Security Considerations

1. **Protect API credentials**: Use secure storage for API keys
2. **Enable TLS verification**: Set `insecure = false` in production
3. **Use mTLS**: Configure client certificates when supported
4. **Audit logging**: Monitor all certificate signing operations
5. **Principle of least privilege**: Use CA API keys with minimal permissions

## Troubleshooting

Enable debug logging in SPIRE Server:
```hcl
server {
    log_level = "DEBUG"
}
```

Check plugin logs:
```bash
grep "external_ca" /var/log/spire/server.log
```

## Support

For SPIRE-specific questions: https://spiffe.io/docs/latest/spire/
For plugin development: https://github.com/spiffe/spire-plugin-sdk

## License

Apache License 2.0
