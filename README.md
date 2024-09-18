<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# ACME httpreq webhook

Implements the cert-manger ACME webhook issuer as a generic http request that calls
a remote server to handle the DNS01 updates.

HttpReq protocol is based on the Let's Encrypt [HTTP Request provider](https://go-acme.github.io/lego/dns/httpreq/)

Webhook is built off of the [Cert Manager Webhook Example](https://github.com/cert-manager/webhook-example)

### Running the test suite

```bash
make test
```


### Linters

This repo uses golangci-lint. Follow the installation instructions [here](https://github.com/golangci/golangci-lint?tab=readme-ov-file#install-golangci-lint)
