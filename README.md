# authority  [![Circle CI](https://circleci.com/gh/ovrclk/authority.svg?style=svg&circle-token=f69ab359eeea3f0c3c28624267062fbd11f1819f)](https://circleci.com/gh/ovrclk/authority) [ ![Download](https://api.bintray.com/packages/ovrclk/pkgs/authority/images/download.svg) ](https://bintray.com/ovrclk/pkgs/authority/_latestVersion) 

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
Usage: authority server [--config=<config>]
       authority (get|revoke) <name> [--server=<server>] [--strict]
       authority ca [--server=<server>]

Authority is a server providing x509 certificate management

Commands:

    server     Run an authority server
    get        Get (after potentially generating) a signed certificate
    revoke     Revoke an existing signed client certificate
    ca         Get certificate authority files

Options:

  --config     Config file for authority server (AUTHORITY_CONFIG)
               [default: /etc/authority.conf]
  --server     Address of authority server (AUTHORITY_SERVER)
               [default: localhost:8200]
  --strict     Fail if the certificate doesn't already exist
  -h, --help   Display this message
  --version    Show version and exit

You can override config file values for the Vault backend with the following
environment variables: AUTHORITY_VAULT_SERVER and AUTHORITY_VAULT_TOKEN
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
