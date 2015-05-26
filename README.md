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

3. Generate a root certificate, and store locally (`~/.authority` by default)

  ```
  $ authority ca
  2015/05/22 22:01:52 creating certificate for ca
  2015/05/22 22:01:55 created certificate for ca
  2015/05/22 22:01:55 certificate authority information stored
  ```

4. Generate a client certificate

  ```
  $ authority generate myclient
  2015/05/22 22:01:59 creating certificate for myclient
  2015/05/22 22:01:59 created certificate for myclient
  2015/05/22 22:01:59 access token for myclient: cb88a027-6c13-816d-0031-3ffb2a61080f
  ```

5. Use the newly generated restricted access token to get and store the certificate locally

  ```
  $ AUTHORITY_VAULT_TOKEN=cb88a027-6c13-816d-0031-3ffb2a61080f authority get myclient
  2015/05/22 22:03:31 certificate myclient stored
  ```

  Alternatively you can output the cert, key, CA cert, or CRL to stdout, i.e.:

  ```
  $ AUTHORITY_VAULT_TOKEN=cb88a027-6c13-816d-0031-3ffb2a61080f authority get myclient cert
-----BEGIN CERTIFICATE-----
MIIDQDCCAiqgAwIBAgIBAjALBgkqhkiG9w0BAQswYzEQMA4GA1UEBhMHQ291bnRy
....
GfwyBOiYDpd6FJXBaJBmXGYy8FM=
-----END CERTIFICATE-----
  ```

6. Revoke a client certificate

  ```
  $ authority revoke foo
  2015/05/22 22:05:39 certificate myclient revoked
  ```

7. Get CA information again, with your updated CRL

  ```
  $ authority ca
  2015/05/22 22:05:57 certificate authority information stored
  ```

### Getting help

```
$ authority --help
Usage: authority config [<configfile>] [--server=SERVER --token=TOKEN]
       authority (generate|revoke) <name> [--server=SERVER --token=TOKEN]
       authority get [ca|cert|key]  <name> [--server=SERVER --token=TOKEN]
       authority ca [cert|key|crl] [--server=SERVER --token=TOKEN]

Authority is a server providing x509 certificate management

Commands:

    config     Display or set authority configuration
    generate   Generate a signed client certificate and access token
    get        Get a signed client certificate
    revoke     Revoke an existing signed client certificate
    ca         Get certificate authority files

Options:

  --server=SERVER   Address of authority server (AUTHORITY_VAULT_SERVER)
                    [default: https://localhost:8200]
  --token=TOKEN     Vault access token (AUTHORITY_VAULT_TOKEN)
  --help            Display this message
  --version         Show version and exit
```

## Development

For local dev first make sure Go is properly installed, including setting up a [GOPATH](http://golang.org/doc/code.html#GOPATH). Next, install the following software packages, which are needed for some dependencies:

- [Git](http://git-scm.com/)
- [Mercurial](http://mercurial.selenic.com/)

Next, clone this repository into `$GOPATH/src/github.com/ovrclk/authority`. Install the necessary dependencies by running `make updatedeps` and then just type `make`. This will compile some more dependencies and then run the tests. If this exits with exit status 0, then everything is working!

```
$ make updatedeps
...
$ make
...
```

To compile a development version of Authority, run `make dev`. This will put Authority binaries in the `bin` and `$GOPATH/bin` folders:

```
$ make dev
...
$ bin/authority
...
```

## Installation

Find the appropriate package from http://dl.bintray.com/ovrclk/pkgs and place it under directory that is available in your `$PATH`, usually `/usr/local/bin`

