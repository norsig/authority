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

// CreateCA creates a root signing certificate given the previously provided
// configuration.
func (c *Crypto) CreateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	d := &c.Cert.Config.Defaults
	subject := &pkix.Name{
		Country:            []string{d.Country},
		Organization:       []string{d.Org},
		OrganizationalUnit: []string{d.OrgUnit},
		Locality:           []string{d.City},
		Province:           []string{d.Region},
		CommonName:         "ca",
	}

	key := c.makePrivateKey(keySize)

	certBytes := c.makeCert(true, subject, key)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// CreateCertificateRequest creates a new certificate and private key. The
// certificate will be signed by the root certificate.
func (c *Crypto) CreateCertificateRequest() (*x509.Certificate, *rsa.PrivateKey, error) {
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

	// TODO: what are we doing with this CSR?
	_ = c.makeCSR(subject, key)

	certBytes := c.makeCert(false, subject, key)
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

func (c *Crypto) makeCSR(subject *pkix.Name, key *rsa.PrivateKey) []byte {
	certReq := &x509.CertificateRequest{
		PublicKey:          key,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            *subject,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, certReq, key)
	if err != nil {
		fmt.Println("error:", err)
	}

	return csr
}

func (c *Crypto) makeCert(isCA bool, subject *pkix.Name, key *rsa.PrivateKey) []byte {
	now := time.Now()
	template := x509.Certificate{
		SerialNumber:       c.Backend.GetNextSerialNumber(),
		Subject:            *subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          now.Add(-5 * time.Minute).UTC(),
		NotAfter:           now.AddDate(10, 0, 0).UTC(),
	}

	var parent *x509.Certificate = nil
	var parentKey *rsa.PrivateKey = nil

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		parent = &template
		parentKey = key
	} else {
		ca := GetCA(c.Backend, c.Config)
		parent = ca.GetCertificate()
		parentKey = ca.GetPrivateKey()
		template.Issuer = parent.Subject
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, parent, &key.PublicKey, parentKey)

	if err != nil {
		fmt.Println("error:", err)
	}

	return cert
}
