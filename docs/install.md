# Install CryptoDeps

The short version is in the [README](../README.md#install). This page holds every install option.

## Installation

**Option 1: Build from Source**

Requires Go 1.21+ ([install Go](https://golang.org/doc/install))

Copy and paste this entire block:

```bash
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
make build
sudo mv cryptodeps /usr/local/bin/
cd .. 
cryptodeps version
```

**Option 2: Go Install**

For Go developers:

```bash
go install github.com/csnp/qramm-cryptodeps/cmd/cryptodeps@latest
```

**Option 3: Download Binary**

Download pre-built binaries from [GitHub Releases](https://github.com/csnp/qramm-cryptodeps/releases).
