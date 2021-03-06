package api

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"

	"github.com/ovrclk/authority/authority"
	"github.com/ovrclk/authority/backend"
	"github.com/ovrclk/authority/config"
)

// Represents an x509 certificate as well as corresponding private key and
// certificate revocation list.
type Certificate struct {
	CommonName  string
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CRL         *pkix.CertificateList
}

// Client provides an API for creating, storing, retrieving and revoking x509
// certificates.
type Client struct {
	Path   string
	Server string
	Token  string

	backend backend.Backend
	config  *config.Config
}

// Create a new Client for local filesystem API operations given the provided path.
func NewLocalClient(path string) (*Client, error) {
	return newClientWithConfig("file", "", "", path, nil)
}

// Create a new Client for local filesystem API operations given the provided path.
func NewLocalClientWithConfig(path string, config *config.Config) (*Client, error) {
	return newClientWithConfig("file", "", "", path, config)
}

// Create a new Client for API operations given the provided Vault server and token.
func NewClient(server, token string) (*Client, error) {
	return newClientWithConfig("vault", server, token, "", nil)
}

// Create a new Client for API operations given the provided server and token,
// and config.Config.
func NewClientWithConfig(server, token string, config *config.Config) (*Client, error) {
	return newClientWithConfig("vault", server, token, "", config)
}

func newClientWithConfig(backendType, server, token, path string, config *config.Config) (*Client, error) {
	c := &Client{
		Path:   path,
		Server: server,
		Token:  token,
		config: config,
	}

	if backendType == "vault" {
		c.backend = backend.Backend(&backend.Vault{
			Server: c.Server,
			Token:  c.Token,
		})
	} else {
		c.backend = backend.Backend(&backend.File{
			Path: c.Path,
		})
	}

	err := c.backend.Connect()
	if err != nil {
		return nil, err
	}

	if c.config != nil {
		err := c.SetConfig(c.config)
		if err != nil {
			return nil, err
		}
	}

	return c, err
}

// Retrieve stored configuration information from the backend.
func (c *Client) GetConfig() (*config.Config, error) {
	cfg, err := c.backend.GetConfig()
	if err != nil {
		return nil, authority.ErrConfigMissing
	}
	c.config = cfg
	return cfg, nil
}

// Stores a previously generated certificate and key in authority's backend.
func (c *Client) SetCertificate(name string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	var err error
	if err = c.backend.PutCertificate(name, cert); err != nil {
		return err
	}
	if err = c.backend.PutPrivateKey(name, key); err != nil {
		return err
	}
	return nil
}

// Store authority configuration information in the backend.
func (c *Client) SetConfig(config *config.Config) error {
	c.config = config
	conf, err := config.ToString()
	if err != nil {
		return err
	}
	if err = c.backend.PutConfig(conf); err != nil {
		return fmt.Errorf("authority: cannot store configuration: %v", err)
	}
	return nil
}

// Generate creates and returns a certificate for the provided common name.
// It will also generate and return a backend access token with granular
// permissions to access the certificate.
//
// If there is already an existing certificate with the same name, Generate
// will return that certificate, as well as an error.
func (c *Client) Generate(name string) (*Certificate, string, error) {
	return c.GenerateWithOptions(name, "", nil, nil)
}

// GenerateWithParent creates and returns a certificate for the provided
// common name.  It will also generate and return a backend access token with
// granular permissions to access the certificate.
//
// If there is already an existing certificate with the same name, Generate
// will return that certificate, as well as an error.
//
// If GenerateWithParent is provided with a parent name, the certificate will
// be signed by the certificate with the provided parent name if it exists. An
// empty string will create a certificate signed by the root certificate.
func (c *Client) GenerateWithParent(name string, parent string) (*Certificate, string, error) {
	return c.GenerateWithOptions(name, parent, nil, nil)
}

// GenerateWithOptions creates and returns a certificate for the provided
// common name.  It will also generate and return a backend access token with
// granular permissions to access the certificate.
//
// If there is already an existing certificate with the same name, Generate
// will return that certificate, as well as an error.
//
// If GenerateWithOptions is provided with a parent name, the certificate will
// be signed by the certificate with the provided parent name if it exists. An
// empty string will create a certificate signed by the root certificate.
//
// If dnsNames or ipAddresses are provided and non-empty, the certificate will
// created with corresponding Subject Alt Names.
func (c *Client) GenerateWithOptions(name string, parent string, dnsNames []string, ipAddresses []net.IP) (*Certificate, string, error) {
	var err error
	var token string
	var clientCert *Certificate

	if !nameIsValid(name) {
		return nil, "", fmt.Errorf("authority: %s is a restricted name", name)
	}

	cert := &authority.Cert{
		CommonName:  name,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
		Backend:     c.backend,
		Config:      c.config,
	}

	if parent == "" {
		cert.ParentName = "ca"
	} else {
		cert.ParentName = parent
	}

	if cert.Exists() {
		clientCert, err = c.Get(name)
		if err != nil {
			return nil, "", fmt.Errorf("authority: certificate %s already exists, but unable to retrieve %v", err)
		}
		return clientCert, "", authority.ErrCertAlreadyExists
	}

	if err = cert.Create(); err != nil {
		return clientCert, token, err
	}

	token, err = c.backend.CreateTokenForCertificate(name)
	if err != nil {
		return clientCert, token, fmt.Errorf("authority: unable to generate certificate token %v", err)
	}

	clientCert, err = c.Get(name)
	return clientCert, token, err
}

// Get retrieves a previously generated x509 certificate.
func (c *Client) Get(name string) (*Certificate, error) {
	cert := &authority.Cert{
		CommonName: name,
		Backend:    c.backend,
		Config:     c.config,
	}

	if !cert.Exists() {
		return nil, authority.ErrCertNotFound
	}

	return &Certificate{
		CommonName:  cert.CommonName,
		Certificate: cert.GetCertificate(),
		PrivateKey:  cert.GetPrivateKey(),
	}, nil
}

// Revoke adds the certificate with the provided common name to the signing
// certificate's certificate revocation list, assuming that the indicated
// certificate exists.
func (c *Client) Revoke(name string) error {
	ca, err := authority.GetCA(c.backend, c.config)
	if err != nil {
		return err
	}

	cert := &authority.Cert{
		CommonName: name,
		Backend:    c.backend,
		Config:     c.config,
	}

	if !cert.Exists() {
		return authority.ErrCertNotFound
	}

	err = ca.Revoke(cert.GetCertificate())
	if err != nil {
		return fmt.Errorf("authority: unable to revoke certificate %v", err)
	}

	return nil
}

// GetCA retrieves the root certificate, private key and certificate revocation list.
func (c *Client) GetCA() (*Certificate, error) {
	cert, err := authority.GetCA(c.backend, c.config)
	if err != nil {
		return nil, err
	}

	var crl *pkix.CertificateList
	bytes := cert.GetCRLRaw()
	if len(bytes) == 0 {
		crl = &pkix.CertificateList{}
	} else {
		crl, err = x509.ParseCRL(bytes)
		if err != nil {
			return nil, fmt.Errorf("authority: error parsing CRL %v", err)
		}
	}

	return &Certificate{
		CommonName:  cert.CommonName,
		Certificate: cert.GetCertificate(),
		PrivateKey:  cert.GetPrivateKey(),
		CRL:         crl,
	}, nil
}

var restrictedNames []string = []string{"ca", "cert", "config", "crl", "generate", "get", "key", "revoke"}

func nameIsValid(name string) bool {
	toCheck := strings.ToLower(name)
	for _, rn := range restrictedNames {
		if rn == toCheck {
			return false
		}
	}
	return true
}
