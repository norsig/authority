package api

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"

	"github.com/ovrclk/authority/authority"
	"github.com/ovrclk/authority/backend"
	"github.com/ovrclk/authority/config"
)

// Represents a client x509 certificate and corresponding private key.
type ClientCertificate struct {
	CommonName  string
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// Represents a root signing x509 certificate and corresponding private key
// and certificate revocation list.
type RootCertificate struct {
	*ClientCertificate
	CRL *pkix.CertificateList
}

// Client provides an API for creating, storing, retrieving and revoking x509
// certificates.
type Client struct {
	Server string
	Token  string

	backend backend.Backend
	config  *config.Config
}

// Create a new Client for API operations given the provided server and token,
// as well as an optional config.Config object.
func NewClient(server, token string, config *config.Config) (*Client, error) {
	c := &Client{
		Server: server,
		Token:  token,
		config: config,
	}

	c.backend = backend.Backend(&backend.Vault{
		Server: c.Server,
		Token:  c.Token,
	})

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
func (c *Client) Generate(name string) (*ClientCertificate, string, error) {
	var err error
	var token string
	var clientCert *ClientCertificate

	if !nameIsValid(name) {
		return nil, "", fmt.Errorf("authority: %s is a restricted name", name)
	}

	cert := &authority.Cert{
		CommonName: name,
		Backend:    c.backend,
		Config:     c.config,
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
func (c *Client) Get(name string) (*ClientCertificate, error) {
	cert := &authority.Cert{
		CommonName: name,
		Backend:    c.backend,
		Config:     c.config,
	}

	if !cert.Exists() {
		return nil, authority.ErrCertNotFound
	}

	return &ClientCertificate{
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
func (c *Client) GetCA() (*RootCertificate, error) {
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

	return &RootCertificate{
		ClientCertificate: &ClientCertificate{
			CommonName:  cert.CommonName,
			Certificate: cert.GetCertificate(),
			PrivateKey:  cert.GetPrivateKey(),
		},
		CRL: crl,
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
