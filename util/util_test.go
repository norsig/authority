package util

import (
	"strings"
	"testing"
)

var certString = `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBcMQ4wDAYDVQQGEwVlcnNl
eTEPMA0GA1UEChMGb3ZyY2xrMQ0wCwYDVQQLEwRhc2RmMQ8wDQYDVQQHEwZMb25k
b24xDDAKBgNVBAgTA05ldzELMAkGA1UEAxMCY2EwHhcNMTUwOTE1MTkxNzExWhcN
MjUwOTE1MTkyMjExWjBcMQ4wDAYDVQQGEwVlcnNleTEPMA0GA1UEChMGb3ZyY2xr
MQ0wCwYDVQQLEwRhc2RmMQ8wDQYDVQQHEwZMb25kb24xDDAKBgNVBAgTA05ldzEL
MAkGA1UEAxMCY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLI/m3
V8bHSg3jgl2lNozm42UV3kjwV9FTmowjZ5z0ptdo3La8Q7RiMyHhtr0pNG6873QR
lswbxNSYCWYKuORdn0wEivSv2Mov1Hjg5lA8FHZWTJ9fv3SVxfLGEf7Cs8RwqoQX
XzYMb08NxKqm+hWJ8Eh7Csl4ZAnionECyx75veaUuCLOJRmC03l5aGlnxBa1f54p
KczZ9F3g/FkqdDtuLzV68nHtEdQdHMsPrMGcMt+semkV9+ZT+U0jzvG8uTiOFsLK
85ZVJ73gbmJE30upktFnfn8FuLn+H+5icTaNpnRdVYie2/u9XSeFuF4fuqfn2l7o
Z70WRyLpT6zsqA5TAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAU
BggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEACzTqUz1VCM+J0/pP0CZnRAm6WTNEp4Va70Ft6dnNayjK7M47yK9W
3rDHL0Ym2VKnZKt2Vha1AaJKpxOpcSFK7xFxr4oq3tuuobn8QVyhamswusLjiD/S
mt0KEm+n2JdIPNuQyyXNc8zQAgHxLwAgtBe6AS7WViBlVo8+jKhK9scoR9q67jyT
6HhUiSPvVLWL1R4tfciiw5EpvlyBh1TS5GmIGZoudV1/vxYcy3TjSjlfpdeqNCvg
IAd0NYwmxTc7ay88/TWYkuXaak7T8vZbmQ0oAapcLNn3J5aNCnH9De6mchEzmYyV
u9iAmrJwYn1aPy3jvrU92zX1NDsFwHz1zA==
-----END CERTIFICATE-----`

var keyString = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsyW/CxTiRSgO7mRDLrB0BXLH55VyrY/yfRPRSZ73ip7y19jG
wtnedP3w2Nfrtz3sgZA6RLbAuuAbbnFoU6lmI71VY9+QN3KB1FGh+yZ7fzjWUNi2
RTQlpjtozU9wUakkV0A9g8UYhdwjms95+O858MgKBQs6A9l40vLhgqD8Q4/tM+p6
sCekEUGGiXWC3Y0K7ibRKgIkMuywocLzy01H/YaofR7EsUoDYRpUZCJu32nDuLH4
VvyT4iBtdtk9PS8op/VRfMU0rzhsBMBjn87jnOL6nBqqzA3A2p0g+1CHsRzbLnuB
uWDhN2HWYquTsV94hI4jtxyJvqacWLUgdgETWQIDAQABAoIBAHc9R4RzuQt41z9b
YtAfyImb1WzSL0tQxYD1ANd0xKTymQaMFfe5lfTe1UEvrof/4nx2aCI2Vd/MrNV9
DIiq9v4Q1lYshswxHjMYxqzo90g9p4CWTfOP+wNDBcWp+0OPRk4AxzD+rgzi8pvn
PvMvH6yhKPIkf8/yHxahbPJKfr3kXzfKDfYengYwHwFrkDo9Q/uTW10o1lF3DaIb
yxBMO93UU42f51TZ+kQM5AAYLHYVZp+bLojeczHNt1jasokzB0wWkMV1MMoXhTD0
w1fjIrELwc3l2aFdANUFQDK7sC0SxW2Y7Z41LfJrst5mjmGnedA5Iat7h3D2H/MM
vy8/LYUCgYEA6eMruFE2jn79qhO4wPC/sHweDniUqLUdwizcysTIHNIizitWl/m2
S7l4yiObwDa8I9fYHnisGA9IO+z4Q8YcbvuIimBguLer/ziNNzuVTfOmDk9xsvTR
1sFxuR3+SE2cEIDvBGDnTMO6eW98IXnQ+Xp7vnVgrvUh91JqsD2ulRcCgYEAxBWx
PrpxkU2QmX6XBIxLN/21RDOEyMloO+NDkmXlp88sa54qq30xa9qloVh5soZe06b5
hJVswMSbhAszsqXR9f3fOwquT7uRee9ZFut8FG+3RPdfK+yst1nrNlUgUqU4sn8g
AT0cNptyI0n/vxKdIU/DbS6MOXVteDK7CNSgwQ8CgYEAom0SKrGzyqfkb928W7mV
1fGMSg5xZuxI21Wei+627lT8uOMeAvL3J4WJng+2lXktlVLLkvXIxfiu+HbsPtzx
WB20yCyAXyem+dqDL41gdb80XhHL6zTcGWFEIgPzWLEVJdz0oLzPRN9UvAqxUOox
N2BZWX5Yg4hXa1PAJd7gREcCgYAEvH1mhXxexR/cBUnCi1z5wkARoKjxbKP+5lNo
gtuUPRXWl6ByOfjqoQJlLkzqOgKqXBskz7MryNP00YxzITw8E+DDfVOOi3pNFrHx
MsjxeW1U1iDPX80gNKTQ0CeSt3jyHs34GbDHxONx5MSvqdRvzIxs47XxYVu+joMk
CHbFkwKBgQCovujVFOnMgQeQDZUoR9vHBV1GhlEKsglraTUBc+NV/6bRh52kuAlk
B4OedgFUwPHOZaE+xWzn6BZwHiZ6DRaZkziUliebvSo17UXc6g4jmRX62zfWnABi
XmN/P23nxzLw/ytzKjqy8s70u6YIjCHpzTh1y676V9rOeMCY+5f4cw==
-----END RSA PRIVATE KEY-----`

func TestParseCertificateString(t *testing.T) {
	cert, err := GetCertificateFromPEM(certString)
	if err != nil || cert == nil {
		t.Fatalf("got error parsing cert: %v", err)
	}
	if cert.Subject.CommonName != "ca" {
		t.Fatal("got unexpected certificate name")
	}

	pemString := GetPEMFromCertificate(cert)

	if strings.TrimSpace(pemString) != strings.TrimSpace(certString) {
		t.Fatal("got unexpected pem encoding of certificate")
	}
}

func TestParseCertificateBytes(t *testing.T) {
	cert, err := GetCertificateFromPEMBytes([]byte(certString))
	if err != nil || cert == nil {
		t.Fatalf("got error parsing cert: %v", err)
	}
	if cert.Subject.CommonName != "ca" {
		t.Fatal("got unexpected certificate name")
	}
}

func TestParseKeyString(t *testing.T) {
	key, err := GetKeyFromPEM(keyString)
	if err != nil || key == nil {
		t.Fatalf("got error parsing key: %v", err)
	}
	if !strings.HasPrefix(key.D.String(), "15052576") || !strings.HasSuffix(key.D.String(), "78306437") {
		t.Fatalf("parsed unexpected key")
	}

	pemString := GetPEMFromKey(key)

	if strings.TrimSpace(pemString) != strings.TrimSpace(keyString) {
		t.Fatal("got unexpected pem encoding of certificate")
	}
}

func TestParseKeyBytes(t *testing.T) {
	key, err := GetKeyFromPEMBytes([]byte(keyString))
	if err != nil || key == nil {
		t.Fatalf("got error parsing key: %v", err)
	}
	if !strings.HasPrefix(key.D.String(), "15052576") || !strings.HasSuffix(key.D.String(), "78306437") {
		t.Fatalf("parsed unexpected key")
	}
}
