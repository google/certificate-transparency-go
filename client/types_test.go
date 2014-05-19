package client

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

const (
	PrecertEntryB64 = "AAAAAAFEvwd6LgABemrYgpjLplsXa6OnqyXuj5BgQDPaapisB5WfVm+jr" +
		"FQABdEwggXNoAMCAQICEAca4ZCK2+1RDyapBvaLcg0wDQYJKoZIhvcNAQEFBQAwZjELMAkGA" +
		"1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0L" +
		"mNvbTElMCMGA1UEAxMcRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgQ0EtMzAeFw0xNDAzMTAwM" +
		"DAwMDBaFw0xNTA1MTMxMjAwMDBaMIGYMQswCQYDVQQGEwJKUDERMA8GA1UECBMIa2FuYWdhd" +
		"2ExEzARBgNVBAcTClNhZ2FtaWhhcmExHDAaBgNVBAoTE0tpdGFzYXRvIFVuaXZlcnNpdHkxJ" +
		"jAkBgNVBAsTHUluZm9ybWF0aW9uIE5ldHdvcmtpbmcgQ2VudGVyMRswGQYDVQQDDBIqLmtpd" +
		"GFzYXRvLXUuYWMuanAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC41vXdZxYeN" +
		"T0R03mbtCjTAJ8pnjD6IDwvHSoMzCuaeuzhNFpLIHockWPmKglLektE6lhE3Hs7mXIW86H43" +
		"WNcYOzcpFf6PdVcJFMwBgDeTlm8sPpFTwdA1tRiIRU2T0xYM4kAESimaQJZdm3xITZwEhnBq" +
		"eWX72Tr+Yzfot0COFjpX5b9to0ahTylKsGruMHWE6NpQlk+Oj24lln4uHRjdrZn/6MrX1/J8" +
		"miru9zj6Rkjn4EM+Mo6BfgpKK15nfIuEhNXFZ6WZB/MOhPgSU4uD+AsykeLsOsSTIEteuaJW" +
		"juKqTAL4QkDvjhfrk6iZTns+UuWmNbrOnzi4jAbd3OhAgMBAAGjggNaMIIDVjAfBgNVHSMEG" +
		"DAWgBRQ6nOJ2yn7EI+e5QEg1N55mUiD9zAdBgNVHQ4EFgQUQCepkOE4RkifUlf4Sfa/cJVst" +
		"WYwLwYDVR0RBCgwJoISKi5raXRhc2F0by11LmFjLmpwghBraXRhc2F0by11LmFjLmpwMA4GA" +
		"1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwYQYDVR0fBFowW" +
		"DAqoCigJoYkaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL2NhMy1nMjcuY3JsMCqgKKAmhiRod" +
		"HRwOi8vY3JsNC5kaWdpY2VydC5jb20vY2EzLWcyNy5jcmwwggHEBgNVHSAEggG7MIIBtzCCA" +
		"bMGCWCGSAGG/WwBATCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL" +
		"3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAd" +
		"QBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4Ac" +
		"wB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAAR" +
		"ABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAe" +
		"QBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAb" +
		"ABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAb" +
		"wByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AY" +
		"wBlAC4wewYIKwYBBQUHAQEEbzBtMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vyd" +
		"C5jb20wRQYIKwYBBQUHMAKGOWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vyd" +
		"EhpZ2hBc3N1cmFuY2VDQS0zLmNydDAMBgNVHRMBAf8EAjAAAAA="
	CertEntryB64 = "AAAAAAFEwEwJngAAAAUnMIIFIzCCBAugAwIBAgIHJ6L5mPSurzANBgkqhkiG" +
		"9w0BAQsFADCBtDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj" +
		"b3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8v" +
		"Y2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3Vy" +
		"ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjAeFw0xNDAzMTIxODU0NTRaFw0xNTAzMTIx" +
		"ODU0NTRaMDkxITAfBgNVBAsTGERvbWFpbiBDb250cm9sIFZhbGlkYXRlZDEUMBIGA1UEAxML" +
		"dHJpc3VyZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQUUOZYiQ4DmtX" +
		"4k4CuCgHB4b8ZONL4CJBlFQc/nIbjgKAXMNUhsjLayR36RccSp1ZJXPwKTXCWQ6kjYTeBvFs" +
		"b6ky9ApYa/ZFecNmkzld8tilDsKH7GAdr2vUz0W8bR6YlY0cgNQ/KXrFKL5giaqUt9w5OThr" +
		"WaGEDNufSDin4AChHzPhncfjwD3DZFfjcDrR9H7xryZSWVZUYTLo7Vs/ceuWvAkuh2yZe1QS" +
		"d5XKKy52MqAwqYG4Ioi2cQfCgVEe2P8HEj1XzlYxHOD0ohNf6IRnPrGVHSTcllyeJP5uvU/e" +
		"6CiOUe0F+f98I02F18cDbDfleRc6u03idR3q4ZL9AgMBAAGjggGyMIIBrjAPBgNVHRMBAf8E" +
		"BTADAQEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMCBaAw" +
		"NgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nb2RhZGR5LmNvbS9nZGlnMnMxLTI3LmNy" +
		"bDBTBgNVHSAETDBKMEgGC2CGSAGG/W0BBxcBMDkwNwYIKwYBBQUHAgEWK2h0dHA6Ly9jZXJ0" +
		"aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8wdgYIKwYBBQUHAQEEajBoMCQGCCsG" +
		"AQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wQAYIKwYBBQUHMAKGNGh0dHA6Ly9j" +
		"ZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS9nZGlnMi5jcnQwHwYDVR0jBBgw" +
		"FoAUQMK9J47MNIMwojPX+2yz8LQsgM4wJwYDVR0RBCAwHoILdHJpc3VyZS5jb22CD3d3dy50" +
		"cmlzdXJlLmNvbTAdBgNVHQ4EFgQUncM2IqTKpShSWBCF37hH/dDVbR8wDQYJKoZIhvcNAQEL" +
		"BQADggEBAEiIEjD9CWyDyV27csg6itq48yOF/icQ6j3Y8rmyQ1levCDGaR7tv4RjU/iuQEwR" +
		"hGOG3xQ7So+qSKm0lj6ZJJpv3nLroQKpcadyW6n/s4CokHOgxxlzhwvdeTXvul0kt3QG8l4s" +
		"HgzGqvfnjUsqljQ5U4Z2BAsRuAiilVc0/TTPbb0smbnq4GFbOCXe73xFgY4NZJ6IPzvwhTdT" +
		"Lxg0dUi5yOgjsrJ7agV1sI+Wk1C7+Y70FOHcM3vNC4HZ2KIbM/pex8IH64J9/TYEkVCtTvdB" +
		"tXjj+06auSnL+GOFJgqzSfbTWT8AJIbo0GezGpN88hwulluXnhh2vPgqSvjSBjIAAA=="
)

func TestReadMerkleTreeLeafForX509Cert(t *testing.T) {
	entry, err := base64.StdEncoding.DecodeString(CertEntryB64)
	if err != nil {
		t.Fatal(err)
	}

	m, err := ReadMerkleTreeLeaf(bytes.NewReader(entry))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != V1 {
		t.Fatal("Invalid version number")
	}
	if m.LeafType != TimestampedEntryLeafType {
		t.Fatal("Invalid LeafType")
	}
	if m.TimestampedEntry.EntryType != X509LogEntryType {
		t.Fatal("Incorrect EntryType")
	}
}

func TestReadMerkleTreeLeafForPrecert(t *testing.T) {
	entry, err := base64.StdEncoding.DecodeString(PrecertEntryB64)
	if err != nil {
		t.Fatal(err)
	}

	m, err := ReadMerkleTreeLeaf(bytes.NewReader(entry))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != V1 {
		t.Fatal("Invalid version number")
	}
	if m.LeafType != TimestampedEntryLeafType {
		t.Fatal("Invalid LeafType")
	}
	if m.TimestampedEntry.EntryType != PrecertLogEntryType {
		t.Fatal("Incorrect EntryType")
	}
}

func TestReadMerkleTreeLeafChecksVersion(t *testing.T) {
	buffer := []byte{1}
	_, err := ReadMerkleTreeLeaf(bytes.NewReader(buffer))
	if err == nil || !strings.Contains(err.Error(), "unknown Version") {
		t.Fatal("Failed to check Version - accepted 1")
	}
}

func TestReadMerkleTreeLeafChecksLeafType(t *testing.T) {
	buffer := []byte{0, 0x12, 0x34}
	_, err := ReadMerkleTreeLeaf(bytes.NewReader(buffer))
	if err == nil || !strings.Contains(err.Error(), "unknown LeafType") {
		t.Fatal("Failed to check LeafType - accepted 0x1234")
	}
}
