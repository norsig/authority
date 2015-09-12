package authority

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ovrclk/authority/backend"
	"github.com/ovrclk/authority/config"
)

// Cert represents an x509 certificate, including it's private key, and
// in the case of a root key, it's certificate revocation list.
type Cert struct {
	CommonName  string
	Backend     backend.Backend
	ParentName  string
	DNSNames    []string
	IPAddresses []net.IP

	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	crl         *pkix.CertificateList
	loaded      bool

	*config.Config
}

// GetCA returns the root certificate, creating it if it does not already
// exist.
func GetCA(backend backend.Backend, config *config.Config) (*Cert, error) {
	return GetCert("ca", backend, config)
}

// GetCertificate returns the certificate with the supplied if it already exists.
func GetCert(name string, backend backend.Backend, config *config.Config) (*Cert, error) {
	cert := &Cert{
		CommonName: name,
		Backend:    backend,
		Config:     config,
	}

	// we'll implicitly make a CA cert
	if !cert.Exists() {
		if name == "ca" {
			err := cert.Create()
			if err != nil {
				return nil, err
			}
		} else {
			return nil, ErrCertNotFound
		}
	}

	return cert, nil
}

// CertificatePEM returns a PEM encoded string representation of the
// provided x509.Certificate.
func CertificatePEM(c *x509.Certificate) string {
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
	return string(pem)
}

// PrivateKeyPEM returns a PEM encoded string representation of the
// provided rsa.PrivateKey.
func PrivateKeyPEM(k *rsa.PrivateKey) string {
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})
	return string(pem)
}

// CRLPEM returns a PEM encoded string representation of the provided
// pkix.CertificateList.
func CRLPEM(c *pkix.CertificateList) string {
	if c == nil {
		return ""
	}
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: c.TBSCertList.Raw,
	})
	return string(pem)
}

// Load the certificate and private key from the backend.
func (c *Cert) load() {
	var err error
	if c.certificate, err = c.Backend.GetCertificate(c.GetName()); err != nil {
		return
	}
	if c.privateKey, err = c.Backend.GetPrivateKey(c.GetName()); err != nil {
		return
	}
	c.loaded = true
}

// Save the certificate and private key to the backend.
func (c *Cert) store() error {
	if c.loaded {
		if err := c.Backend.PutCertificate(c.GetName(), c.certificate); err != nil {
			return err
		}
	}

	return c.Backend.PutPrivateKey(c.GetName(), c.privateKey)
}

// GetCertificate returns the certificate for this Cert, loading it if
// neccesary in the process.
func (c *Cert) GetCertificate() *x509.Certificate {
	if !c.loaded {
		c.load()
	}
	return c.certificate
}

// GetPrivateKey returns the private key for this Cert, loading it if
// neccesary in the process.
func (c *Cert) GetPrivateKey() *rsa.PrivateKey {
	if !c.loaded {
		c.load()
	}
	return c.privateKey
}

// GetCRLRaw returns a []byte holding the certificate revocation list for
// this Cert. It returns nil if this Cert is not a root certificate.
func (c *Cert) GetCRLRaw() []byte {
	return c.Backend.GetCRLRaw(c.CommonName)
}

// Revoke adds the provided certificate to this Cert's CRL. If this Cert is
// not a root certificate, it will return an error.
func (c *Cert) Revoke(cert *x509.Certificate) error {
	bytes := c.GetCRLRaw()
	if len(bytes) == 0 {
		c.crl = &pkix.CertificateList{}
	} else {
		var err error
		c.crl, err = x509.ParseCRL(bytes)
		if err != nil {
			return err
		}
	}

	revocation := pkix.RevokedCertificate{
		SerialNumber:   cert.SerialNumber,
		RevocationTime: time.Now().UTC(),
	}

	currentlyRevoked := c.crl.TBSCertList.RevokedCertificates
	currentlyRevoked = append(currentlyRevoked, revocation)

	ca := c.GetCertificate()
	key := c.GetPrivateKey()

	if key == nil {
		return fmt.Errorf("authority: can't load private key")
	}

	newCRL, _ := ca.CreateCRL(rand.Reader, key, currentlyRevoked, time.Now().UTC(), time.Now().UTC().AddDate(10, 0, 0))
	c.Backend.PutCRL(c.CommonName, newCRL)

	return nil
}

// Create creates the certificate and private key for this Cert.
func (c *Cert) Create() error {
	ssl := &Crypto{Cert: c}

	if len(c.GetName()) == 0 {
		return fmt.Errorf("authority: name cannot be blank")
	}

	if c.Exists() {
		return nil
	}

	var err error

	if c.certificate, c.privateKey, err = ssl.CreateCertificate(); err != nil {
		return fmt.Errorf("authority: %v", err)
	}

	c.loaded = true
	return c.store()
}

// GetName returns the common name of this Cert.
func (c *Cert) GetName() string {
	return strings.Replace(strings.ToLower(c.CommonName), " ", "-", -1)
}

// Exists returns whether or not a certificate with this Cert's common
// name has been created and stored in the backend.
func (c *Cert) Exists() bool {
	return c.Backend.CheckCertificateExists(c.GetName())
}

// determines whether a root certificate has been created
func (c *Cert) rootCertMissing() bool {
	return c.Backend.CheckCertificateExists("ca")
}
