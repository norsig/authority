package authority

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"
)

const keySize = 2048

// Crypto provides and interface for lower level x509 certificate operations.
type Crypto struct {
	*Cert
}

// CreateCertificate creates a new certificate and private key. The
// certificate will be signed by the root certificate.
func (c *Crypto) CreateCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	if c.Cert.Config == nil {
		return nil, nil, errors.New("configuration not available")
	}
	d := &c.Cert.Config.Defaults
	subject := &pkix.Name{
		Country:            []string{d.Country},
		Organization:       []string{d.Org},
		OrganizationalUnit: []string{d.OrgUnit},
		Locality:           []string{d.City},
		Province:           []string{d.Region},
		CommonName:         c.Cert.CommonName,
	}

	key := c.makePrivateKey(keySize)
	certBytes := c.makeCert(subject, key)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func (c *Crypto) getSubject() *pkix.Name {
	d := &c.Cert.Config.Defaults
	subject := &pkix.Name{
		CommonName:   c.Cert.CommonName,
		Organization: []string{d.Org},
		Locality:     []string{d.City},
		Country:      []string{d.Country},
	}
	return subject
}

func (c *Crypto) makePrivateKey(bits int) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		fmt.Println("error:", err)
	}

	return privateKey
}

func (c *Crypto) makeCert(subject *pkix.Name, key *rsa.PrivateKey) []byte {
	var parent *x509.Certificate = nil
	var parentKey *rsa.PrivateKey = nil
	var signingCert *Cert
	var err error

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:       c.Backend.GetNextSerialNumber(),
		Subject:            *subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          now.Add(-5 * time.Minute).UTC(),
		NotAfter:           now.AddDate(10, 0, 0).UTC(),
	}

	template.KeyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template.IsCA = true
	template.BasicConstraintsValid = true

	if c.ParentName == "" {
		c.ParentName = "ca"
	}

	if subject.CommonName == "ca" {
		parent = &template
		parentKey = key
	} else {
		signingCert, err = GetCert(c.ParentName, c.Backend, c.Config)
		if err != nil {
			return nil
		}
		parent = signingCert.GetCertificate()
		parentKey = signingCert.GetPrivateKey()
		template.Issuer = parent.Subject
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, parent, &key.PublicKey, parentKey)

	if err != nil {
		fmt.Println("error:", err)
	}

	return cert
}
