package authority

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ovrclk/authority/backend"
)

type Cert struct {
	CommonName string
	IsRoot     bool
	Backend    backend.Backend

	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	crl         *pkix.CertificateList
	loaded      bool

	*Config
}

func GetCA(backend backend.Backend, config *Config) *Cert {
	cert := &Cert{
		CommonName: "ca",
		IsRoot:     true,
		Backend:    backend,
		Config:     config,
	}

	// we'll implicitly make a CA cert
	if !cert.Exists() {
		cert.Create()
	}

	return cert
}

func CertificatePEM(c *x509.Certificate) string {
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
	return string(pem)
}

func PrivateKeyPEM(k *rsa.PrivateKey) string {
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})
	return string(pem)
}

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

func (c *Cert) store() {
	if c.loaded {
		if err := c.Backend.PutCertificate(c.GetName(), c.certificate); err != nil {
			log.Println("error storing certificate:", err)
		}

		if err := c.Backend.PutPrivateKey(c.GetName(), c.privateKey); err != nil {
			log.Println("error storing private key:", err)
		}
	}
}

func (c *Cert) GetCertificate() *x509.Certificate {
	if !c.loaded {
		c.load()
	}
	return c.certificate
}

func (c *Cert) GetPrivateKey() *rsa.PrivateKey {
	if !c.loaded {
		c.load()
	}
	return c.privateKey
}

func (c *Cert) GetCRLRaw() []byte {
	if !c.IsRoot {
		return nil
	}
	return c.Backend.GetCRLRaw()
}

func (c *Cert) Revoke(cert *x509.Certificate) error {
	if !c.IsRoot {
		return fmt.Errorf("certificate is not a root certificate and has no CRL")
	}

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
		return fmt.Errorf("can't load private key")
	}

	newCRL, _ := ca.CreateCRL(rand.Reader, key, currentlyRevoked, time.Now().UTC(), time.Now().UTC().AddDate(10, 0, 0))
	c.Backend.PutCRL(newCRL)

	return nil
}

func (c *Cert) Create() error {
	ssl := &Crypto{Cert: c}

	if c.Exists() {
		return nil
	}

	creationFunc := ssl.CreateCertificateRequest
	if c.IsRoot {
		creationFunc = ssl.CreateCA
	}

	log.Println("creating certificate for", c.GetName())

	var err error

	if c.certificate, c.privateKey, err = creationFunc(); err != nil {
		return fmt.Errorf("error generating cert: %s", err)
	} else {
		log.Println("created certificate for", c.GetName())
		c.loaded = true
	}

	c.store()

	return nil
}

func (c *Cert) GetName() string {
	return strings.Replace(strings.ToLower(c.CommonName), " ", "-", -1)
}

func (c *Cert) Exists() bool {
	return c.Backend.CheckCertificateExists(c.GetName())
}

func (c *Cert) rootCertMissing() bool {
	return c.Backend.CheckCertificateExists("ca")
}
