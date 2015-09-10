# authority  [![Circle CI](https://circleci.com/gh/ovrclk/authority.svg?style=svg&circle-token=f69ab359eeea3f0c3c28624267062fbd11f1819f)](https://circleci.com/gh/ovrclk/authority) [![License](https://img.shields.io/badge/License-MPL2%20-blue.svg)](https://github.com/ovrclk/authority/raw/master/LICENSE) [![Download](https://api.bintray.com/packages/ovrclk/pkgs/authority/images/download.svg)](https://bintray.com/ovrclk/pkgs/authority/_latestVersion)

Authority is tool for provisioning x509 certificates. Authority requires a [Vault](https://www.vaultproject.io) server backend.

## Usage

### Getting started

Install the appropriate package and follow the below to get started

1. Run a Vault server, and generate a token with `write` access to the path `secret/authority`

2. Set your Vault server + token as environment variables (or pass as arguments)

  ```
  $ export AUTHORITY_VAULT_SERVER=https://localhost:8200
  $ export AUTHORITY_VAULT_TOKEN=377e1028-9320-913e-9dc6-16a4c341a8e5
  ```

3. Configure Authority:

  ```
  $ authority config:set
    root_domain: ovrclk.com
          email: hello@ovrclk.com
            org: Ovrclk
       org_unit: Infrastructure
           city: San Francisco
         region: California
        country: US
       crl_days: 3650
         digest: sha256
    cert_expiry: 3650
   authority: configuration stored
  ```

4. Generate a root certificate

  ```
  $ authority ca:create
  Root certificate created, or exists
  ```

5. Retrieve the certificate and key

  ```
  $ authority ca:cert
  -----BEGIN CERTIFICATE-----
  MIIDnzCCAoegAwIBAgIBATANBgk...
  -----END CERTIFICATE-----

  $ authority ca:key
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpgIBAAKCAQEAvrREShntqhv...
  -----END RSA PRIVATE KEY-----
  ```

6. Generate a client certificate

  ```
  $ authority cert:create my_client
  access token for client: 6651b042-ae7b-d862-e9e7-f446c11a8a39
  ```

7. Use the newly generated restricted access token to get and store the certificate locally

  ```
  $ AUTHORITY_VAULT_TOKEN=6651b042-ae7b-d862-e9e7-f446c11a8a39 authority cert:cert my_client
  -----BEGIN CERTIFICATE-----
  MIIDozCCAougAwIBAgIBAjANB...
  -----END CERTIFICATE-----

  $ AUTHORITY_VAULT_TOKEN=6651b042-ae7b-d862-e9e7-f446c11a8a39 authority cert:key my_client
  -----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAyVn3fxtAuO3...
  -----END RSA PRIVATE KEY-----
  ```

8. Revoke a client certificate

  ```
  $ authority cert:revoke my_client
  certificate my_client revoked
  ```

9. Get the updated CRL

  ```
  $ authority ca:crl > crl.der
  ```

### Getting help

Top level help

```
$ authority help
Authority is a server providing x509 certificate management

Usage: authority COMMAND [<args>..] [options]

Primary help topics, type "authority help TOPIC" for more details:

  ca      manage root certificate
  cert    manage client certificates

Additional topics:

  config  edit certificate configuration settings
  version display version
```

`ca` command help

```
$ authority help ca
Usage: authority ca [options]

Options:

  -h, --help=false: help for ca

General Options:

  -s, --server="": address of vault server (AUTHORITY_VAULT_SERVER)
  -t, --token="": vault access token (AUTHORITY_VAULT_TOKEN)

Additional commands, type "ovrclk COMMAND --help" for more details:

  ca:create Create root certificate
  ca:cert   Get root certificate
  ca:key    Get root certificate private key
  ca:crl    Get root certificate revocation list
```

`cert` command help

```
$ authority help cert
Usage: authority cert [options]

Options:

  -h, --help=false: help for cert

General Options:

  -s, --server="": address of vault server (AUTHORITY_VAULT_SERVER)
  -t, --token="": vault access token (AUTHORITY_VAULT_TOKEN)

Additional commands, type "ovrclk COMMAND --help" for more details:

  cert:create <name> [--root <rootname>] Create certificate
  cert:cert <name>                       Get certificate
  cert:key <name>                        Get certificate private key
  cert:revoke <name>                     Revoke certificate
  cert:crl <name>                        Get certificate revocation list
```

`config` command help

```
$ authority help config
Usage: authority config [options]

Options:

  -h, --help=false: help for config

General Options:

  -s, --server="": address of vault server (AUTHORITY_VAULT_SERVER)
  -t, --token="": vault access token (AUTHORITY_VAULT_TOKEN)

Additional commands, type "ovrclk COMMAND --help" for more details:

  config:get                 Get authority configuration
  config:set [<key> <value> | -f <file>] Set authority configuration, either a single value or a file with multiple values
```

## Development

For local dev first make sure Go is properly installed, including setting up a [GOPATH](http://golang.org/doc/code.html#GOPATH). Next, install the following software packages, which are needed for some dependencies:

- [Git](http://git-scm.com/)
- [Mercurial](http://mercurial.selenic.com/)
- [Godep](https://github.com/tools/godep)

Next, clone this repository into `$GOPATH/src/github.com/ovrclk/authority`. Just type `make` to build and run tests. If this exits with exit status 0, then everything is working!

```
$ make
...
```

To compile a development version of Authority, run `make dev`. This will put Authority binaries in the `bin` and `$GOPATH/bin` folders:

```
$ make build
...
$ bin/authority
...
```

## Installation

Find the appropriate package from http://dl.bintray.com/ovrclk/pkgs and place it under directory that is available in your `$PATH`, usually `/usr/local/bin`

