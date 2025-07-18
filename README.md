# FedMCP Go SDK

Go SDK for creating, signing, and verifying FedMCP compliance artifacts.

## Installation

```bash
go get github.com/FedMCP/go-sdk
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/FedMCP/go-sdk/pkg/fedmcp"
)

func main() {
    // Create an artifact
    artifact := &fedmcp.Artifact{
        Type: "ssp-fragment",
        Name: "ML Pipeline Security Controls",
        Content: map[string]interface{}{
            "controls": []string{"AC-2", "AU-3", "SC-7"},
        },
    }

    // Sign the artifact
    signer := fedmcp.NewLocalSigner("path/to/key.pem")
    signedArtifact, err := signer.Sign(artifact)
    if err != nil {
        panic(err)
    }

    // Verify the signature
    verifier := fedmcp.NewVerifier()
    valid, err := verifier.Verify(signedArtifact)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signature valid: %v\n", valid)
}
```

## Features

- **Artifact Creation**: Build compliance artifacts with structured metadata
- **Cryptographic Signing**: ECDSA P-256 signatures for integrity
- **Signature Verification**: Validate artifact authenticity
- **Audit Support**: Built-in audit event generation
- **Multiple Artifact Types**: SSP fragments, POA&M templates, agent recipes, etc.

## API Reference

### Creating Artifacts

```go
artifact := &fedmcp.Artifact{
    ID:          uuid.New().String(),
    Type:        "ssp-fragment",
    Name:        "Security Controls",
    Content:     controlData,
    WorkspaceID: "prod-workspace",
    CreatedAt:   time.Now(),
}
```

### Signing

```go
// Local key signing
signer := fedmcp.NewLocalSigner("private-key.pem")

// KMS signing (AWS)
signer := fedmcp.NewKMSSigner("arn:aws:kms:region:account:key/id")

// Sign artifact
signed, err := signer.Sign(artifact)
```

### Verification

```go
verifier := fedmcp.NewVerifier()

// Verify with embedded public key
valid, err := verifier.Verify(signedArtifact)

// Verify with specific public key
valid, err := verifier.VerifyWithKey(signedArtifact, publicKey)
```

## Examples

See the [examples](https://github.com/FedMCP/examples) repository for:
- SSP fragment creation
- Batch signing workflows
- Audit trail integration
- CI/CD pipeline usage

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on submitting patches and the contribution workflow.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
