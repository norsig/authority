package authority

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/ovrclk/authority/backend"
)

func makeTempDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "authority")
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return dir
}

func testAuthorityConfig(t *testing.T) (backend.Backend, *Config) {
	dir := makeTempDir(t)
	backend := backend.Backend(&backend.File{Path: dir})
	backend.Connect()
	config := &Config{
		Defaults: DefaultsConfig{
			RootDomain: "authority.root",
			Email:      "user@example.com",
			Org:        "foo",
			OrgUnit:    "bar",
			City:       "sf",
			Region:     "ca",
			Country:    "us",
			Digest:     "sha256",
			CertExpiry: "365",
			CrlDays:    "365",
		},
	}
	return backend, config
}

func TestNewCert(t *testing.T) {
	backend, config := testAuthorityConfig(t)
	cert := &Cert{
		CommonName: "ca",
		IsRoot:     true,
		Backend:    backend,
		Config:     config,
	}

	if cert.Exists() {
		t.Fatal("new cert already exists")
	}

	if err := cert.Create(); err != nil {
		t.Fatal("can't create certificate", err)
	}
}

func TestCertificateSerialNumbers(t *testing.T) {
	backend, config := testAuthorityConfig(t)
	cert := &Cert{
		CommonName: "foobar1",
		IsRoot:     true,
		Backend:    backend,
		Config:     config,
	}

	if cert.Exists() {
		t.Fatal("new cert already exists")
	}

	if err := cert.Create(); err != nil {
		t.Fatal("can't create certificate", err)
	}

	cert1 := &Cert{
		CommonName: "foobar2",
		IsRoot:     true,
		Backend:    backend,
		Config:     config,
	}

	if cert1.Exists() {
		t.Fatal("new cert already exists")
	}

	if err := cert1.Create(); err != nil {
		t.Fatal("can't create certificate", err)
	}

	serial := cert.GetCertificate().SerialNumber
	serial1 := cert1.GetCertificate().SerialNumber

	if serial.Cmp(serial1) == 0 {
		t.Fatal("certificates have same serial numbers:", serial, serial1)
	}
}

func TestRevokeCert(t *testing.T) {
	backend, config := testAuthorityConfig(t)
	cert := &Cert{
		CommonName: "foobar",
		Backend:    backend,
		Config:     config,
	}

	if cert.Exists() {
		t.Fatal("new cert already exists")
	}

	if err := cert.Create(); err != nil {
		t.Fatal("can't create certificate", err)
	}

	serial := cert.GetCertificate().SerialNumber

	ca := GetCA(backend, config)
	ca.Revoke(cert.GetCertificate())

	crl := backend.GetCRLRaw()
	if len(crl) == 0 {
		t.Fatal("failed to revoke certificate")
	}

	crlList, err := x509.ParseCRL(crl)
	if err != nil {
		t.Fatal("error parsing CRL:", err)
	}

	found := false
	for rc := range crlList.TBSCertList.RevokedCertificates {
		revoked := crlList.TBSCertList.RevokedCertificates[rc]
		fmt.Println("found revoked cert:", revoked.SerialNumber)
		if revoked.SerialNumber.Cmp(serial) == 0 {
			found = true
		}
	}

	if !found {
		t.Fatal("didn't find cert in revocation list")
	}
}

func TestLoadCert(t *testing.T) {
	backend, config := testAuthorityConfig(t)
	cert := &Cert{
		CommonName: "foobar",
		Backend:    backend,
		Config:     config,
	}

	if cert.Exists() {
		t.Fatal("new cert already exists")
	}

	if err := cert.Create(); err != nil {
		t.Fatal("can't create certificate", err)
	}

	cert1 := &Cert{
		CommonName: "foobar",
		Backend:    backend,
		Config:     config,
	}

	if !cert1.Exists() {
		t.Fatal("existing certificate not found")
	}
}

func TestImplicitCACreate(t *testing.T) {
	backend, config := testAuthorityConfig(t)
	cert := &Cert{
		CommonName: "foo",
		Backend:    backend,
		Config:     config,
	}

	if cert.Exists() {
		t.Fatal("err: cert already exists")
	}

	if err := cert.Create(); err != nil {
		t.Fatal("cert creation failed:", err)
	}

	ca := GetCA(backend, config)

	if !ca.Exists() {
		t.Fatal("ca doesn't exist")
	}
}