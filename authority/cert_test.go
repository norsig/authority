package authority

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/ovrclk/authority/backend"
	"github.com/ovrclk/authority/config"
)

func makeTempDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "authority")
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return dir
}

func testAuthorityConfig(t *testing.T) (backend.Backend, *config.Config) {
	dir := makeTempDir(t)
	backend := backend.Backend(&backend.File{Path: dir})
	backend.Connect()
	config := &config.Config{
		Defaults: config.DefaultsConfig{
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

	ca, _ := GetCA(backend, config)
	ca.Revoke(cert.GetCertificate())

	crl := ca.GetCRLRaw()
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

	ca, _ := GetCA(backend, config)

	if !ca.Exists() {
		t.Fatal("ca doesn't exist")
	}
}

func TestVerifyCertificate(t *testing.T) {
	backend, config := testAuthorityConfig(t)
	cert := &Cert{
		CommonName: "foo",
		Backend:    backend,
		Config:     config,
	}

	if err := cert.Create(); err != nil {
		t.Fatal("cert creation failed:", err)
	}

	ca, err := GetCA(backend, config)
	if err != nil {
		t.Fatal("can't get ca:", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.GetCertificate())

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.GetCertificate().Verify(opts); err != nil {
		t.Fatal("failed to verify certificate: " + err.Error())
	}
}

func TestVerifyChainedCertificate(t *testing.T) {
	backend, config := testAuthorityConfig(t)
	cert := &Cert{
		CommonName: "foo",
		Backend:    backend,
		Config:     config,
	}

	if err := cert.Create(); err != nil {
		t.Fatal("cert creation failed:", err)
	}

	cert1 := &Cert{
		CommonName: "bar",
		Backend:    backend,
		Config:     config,
		ParentName: "foo",
	}

	if err := cert1.Create(); err != nil {
		t.Fatal("cert creation failed:", err)
	}

	ca, err := GetCA(backend, config)
	if err != nil {
		t.Fatal("can't get ca:", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert.GetCertificate())
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert1.GetCertificate().Verify(opts); err != nil {
		t.Fatal("failed to verify certificate: " + err.Error())
	}

	roots = x509.NewCertPool()
	roots.AddCert(ca.GetCertificate())
	intermediates := x509.NewCertPool()
	intermediates.AddCert(cert.GetCertificate())
	opts = x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := cert1.GetCertificate().Verify(opts); err != nil {
		t.Fatal("failed to verify certificate: " + err.Error())
	}
}

func TestRevokeChainedCert(t *testing.T) {
	backend, config := testAuthorityConfig(t)
	cert := &Cert{
		CommonName: "foo",
		Backend:    backend,
		Config:     config,
	}

	if err := cert.Create(); err != nil {
		t.Fatal("cert creation failed:", err)
	}

	cert1 := &Cert{
		CommonName: "bar",
		Backend:    backend,
		Config:     config,
		ParentName: "foo",
	}

	if err := cert1.Create(); err != nil {
		t.Fatal("cert creation failed:", err)
	}

	serial := cert1.GetCertificate().SerialNumber

	cert.Revoke(cert1.GetCertificate())

	crl := cert.GetCRLRaw()
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

	ca, err := GetCA(backend, config)
	if err != nil {
		t.Fatal("can't get ca")
	}
	crl = ca.GetCRLRaw()
	if len(crl) > 0 {
		t.Fatal("root cert should have empty crl, but it doesnt")
	}
}
