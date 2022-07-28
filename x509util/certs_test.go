// Copyright 2022 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package x509util_test

// pemUnknownBlockType is a PEM containing only an empty block of a
// non-standard type.
const pemUnknownBlockType = `
-----BEGIN SOMETHING-----
-----END SOMETHING-----`

// pemCACertWithOtherStuff is a valid test CA certificate (pemCACert below)
// with additional blocks surrounding it.
const pemCACertWithOtherStuff = `
-----BEGIN SOMETHING-----
-----END SOMETHING-----
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
-----BEGIN SOMETHING-----
-----END SOMETHING-----`

// pemCACert is a valid test CA certificate.
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number: 0 (0x0)
//	Signature Algorithm: sha1WithRSAEncryption
//	    Issuer: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen
//	    Validity
//	        Not Before: Jun  1 00:00:00 2012 GMT
//	        Not After : Jun  1 00:00:00 2022 GMT
//	    Subject: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen
//	    Subject Public Key Info:
//	        Public Key Algorithm: rsaEncryption
//	            Public-Key: (1024 bit)
//	            Modulus:
//	                00:d5:8a:68:53:62:10:a2:71:19:93:6e:77:83:21:
//	                18:1c:2a:40:13:c6:d0:7b:8c:76:eb:91:57:d3:d0:
//	                fb:4b:3b:51:6e:ce:cb:d1:c9:8d:91:c5:2f:74:3f:
//	                ab:63:5d:55:09:9c:d1:3a:ba:f3:1a:e5:41:44:24:
//	                51:a7:4c:78:16:f2:24:3c:f8:48:cf:28:31:cc:e6:
//	                7b:a0:4a:5a:23:81:9f:3c:ba:37:e6:24:d9:c3:bd:
//	                b2:99:b8:39:dd:fe:26:31:d2:cb:3a:84:fc:7b:b2:
//	                b5:c5:2f:cf:c1:4f:ff:40:6f:5c:d4:46:69:cb:b2:
//	                f7:cf:df:86:fb:6a:b9:d1:b1
//	            Exponent: 65537 (0x10001)
//	    X509v3 extensions:
//	        X509v3 Subject Key Identifier:
//	            5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55
//	        X509v3 Authority Key Identifier:
//	            keyid:5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55
//	            DirName:/C=GB/O=Certificate Transparency CA/ST=Wales/L=Erw Wen
//	            serial:00
//
//	        X509v3 Basic Constraints:
//	            CA:TRUE
//	Signature Algorithm: sha1WithRSAEncryption
//	     06:08:cc:4a:6d:64:f2:20:5e:14:6c:04:b2:76:f9:2b:0e:fa:
//	     94:a5:da:f2:3a:fc:38:06:60:6d:39:90:d0:a1:ea:23:3d:40:
//	     29:57:69:46:3b:04:66:61:e7:fa:1d:17:99:15:20:9a:ea:2e:
//	     0a:77:51:76:41:12:27:d7:c0:03:07:c7:47:0e:61:58:4f:d7:
//	     33:42:24:72:7f:51:d6:90:bc:47:a9:df:35:4d:b0:f6:eb:25:
//	     95:5d:e1:89:3c:4d:d5:20:2b:24:a2:f3:e4:40:d2:74:b5:4e:
//	     1b:d3:76:26:9c:a9:62:89:b7:6e:ca:a4:10:90:e1:4f:3b:0a:
//	     94:2e
const pemCACert = `
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----`

// pemCACertDuplicated contains two identical copies of the same test CA cert.
const pemCACertDuplicated = `
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----`

// pemCACertBad is a PEM block containinng invalid data that should not decode.
const pemCACertBad = `
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBA!"£$%^&&**SDFSKJ$%%^%^%^%&^&^!"£$%%IRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----`

// pemCACertMultiple is a PEM block containing a valid CA and intermediate
// certificate, specifically pemCACert above and then:
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number: 9 (0x9)
//	Signature Algorithm: sha1WithRSAEncryption
//	    Issuer: C=GB, O=Certificate Transparency CA, ST=Wales, L=Erw Wen
//	    Validity
//	        Not Before: Jun  1 00:00:00 2012 GMT
//	        Not After : Jun  1 00:00:00 2022 GMT
//	    Subject: C=GB, O=Certificate Transparency Intermediate CA, ST=Wales, L=Erw Wen
//	    Subject Public Key Info:
//	        Public Key Algorithm: rsaEncryption
//	            Public-Key: (1024 bit)
//	            Modulus:
//	                00:d7:6a:67:8d:11:6f:52:2e:55:ff:82:1c:90:64:
//	                25:08:b7:07:4b:14:d7:71:15:90:64:f7:92:7e:fd:
//	                ed:b8:71:35:a1:36:5e:e7:de:18:cb:d5:ce:86:5f:
//	                86:0c:78:f4:33:b4:d0:d3:d3:40:77:02:e7:a3:ef:
//	                54:2b:1d:fe:9b:ba:a7:cd:f9:4d:c5:97:5f:c7:29:
//	                f8:6f:10:5f:38:1b:24:35:35:cf:9c:80:0f:5c:a7:
//	                80:c1:d3:c8:44:00:ee:65:d1:6e:e9:cf:52:db:8a:
//	                df:fe:50:f5:c4:93:35:0b:21:90:bf:50:d5:bc:36:
//	                f3:ca:c5:a8:da:ae:92:cd:8b
//	            Exponent: 65537 (0x10001)
//	    X509v3 extensions:
//	        X509v3 Subject Key Identifier:
//	            96:55:08:05:02:78:47:9E:87:73:76:41:31:BC:14:3A:47:E2:29:AB
//	        X509v3 Authority Key Identifier:
//	            keyid:5F:9D:88:0D:C8:73:E6:54:D4:F8:0D:D8:E6:B0:C1:24:B4:47:C3:55
//	            DirName:/C=GB/O=Certificate Transparency CA/ST=Wales/L=Erw Wen
//	            serial:00
//
//	        X509v3 Basic Constraints:
//	            CA:TRUE
//	Signature Algorithm: sha1WithRSAEncryption
//	     22:06:da:b1:c6:6b:71:dc:e0:95:c3:f6:aa:2e:f7:2c:f7:76:
//	     1b:e7:ab:d7:fc:39:c3:1a:4c:fe:1b:d9:6d:67:34:ca:82:f2:
//	     2d:de:5a:0c:8b:bb:dd:82:5d:7b:6f:3e:76:12:ad:8d:b3:00:
//	     a7:e2:11:69:88:60:23:26:22:84:c3:aa:5d:21:91:ef:da:10:
//	     bf:92:35:d3:7b:3a:2a:34:0d:59:41:9b:94:a4:85:66:f3:fa:
//	     c3:cd:8b:53:d5:a4:e9:82:70:ea:d2:97:b0:72:10:f9:ce:4a:
//	     21:38:b1:88:11:14:3b:93:fa:4e:7a:87:dd:37:e1:38:5f:2c:
//	     29:08
const pemCACertMultiple = `
-----BEGIN CERTIFICATE-----
MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC3TCCAkagAwIBAgIBCTANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMGIxCzAJBgNVBAYTAkdCMTEwLwYDVQQKEyhDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgSW50ZXJtZWRpYXRlIENBMQ4wDAYDVQQIEwVXYWxlczEQMA4GA1UE
BxMHRXJ3IFdlbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA12pnjRFvUi5V
/4IckGQlCLcHSxTXcRWQZPeSfv3tuHE1oTZe594Yy9XOhl+GDHj0M7TQ09NAdwLn
o+9UKx3+m7qnzflNxZdfxyn4bxBfOBskNTXPnIAPXKeAwdPIRADuZdFu6c9S24rf
/lD1xJM1CyGQv1DVvDbzysWo2q6SzYsCAwEAAaOBrzCBrDAdBgNVHQ4EFgQUllUI
BQJ4R56Hc3ZBMbwUOkfiKaswfQYDVR0jBHYwdIAUX52IDchz5lTU+A3Y5rDBJLRH
w1WhWaRXMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuggEA
MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAIgbascZrcdzglcP2qi73
LPd2G+er1/w5wxpM/hvZbWc0yoLyLd5aDIu73YJde28+dhKtjbMAp+IRaYhgIyYi
hMOqXSGR79oQv5I103s6KjQNWUGblKSFZvP6w82LU9Wk6YJw6tKXsHIQ+c5KITix
iBEUO5P6TnqH3TfhOF8sKQg=
-----END CERTIFICATE-----`

// pemFakeCACert is a test CA cert for testing.
//
//	Data:
//	    Version: 3 (0x2)
//	    Serial Number:
//	        b6:31:d2:ac:21:ab:65:20
//	Signature Algorithm: sha256WithRSAEncryption
//	    Issuer: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	    Validity
//	        Not Before: Jul 11 12:23:26 2016 GMT
//	        Not After : Jul 11 12:23:26 2017 GMT
//	    Subject: C=GB, ST=London, L=London, O=Google, OU=Eng, CN=FakeCertificateAuthority
//	    Subject Public Key Info:
//	        Public Key Algorithm: rsaEncryption
//	            Public-Key: (2048 bit)
//	            Modulus:
//	                00:a5:41:9a:7a:2d:98:a3:b5:78:6f:15:21:db:0c:
//	                c1:0e:a1:f8:26:f5:b3:b2:67:85:dc:a1:e6:b7:83:
//	                6d:da:63:da:d0:f6:a3:ff:bc:43:f5:2b:9f:00:19:
//	                6e:6b:60:4b:43:20:6e:e2:cb:2e:b6:65:ed:9b:dc:
//	                80:c3:e1:5a:96:af:60:78:0e:0e:fb:8f:ea:3e:3d:
//	                c9:67:8f:a4:57:1c:ba:e4:f3:37:a9:2f:dd:11:9d:
//	                10:5d:e5:d6:ef:d4:3b:06:d9:34:43:42:bb:bb:be:
//	                43:40:2b:e3:b6:d1:b5:6c:58:12:34:96:14:d4:fc:
//	                49:79:c5:26:8c:24:7d:b3:12:f5:f6:3e:b7:41:46:
//	                6b:6d:3a:41:fd:7c:e3:b5:fc:96:6c:c6:cc:ad:8d:
//	                48:09:73:44:64:ea:4f:17:1d:0a:4b:14:5a:19:07:
//	                4a:32:0f:41:2e:e4:85:bd:a1:e1:9b:de:63:7c:3b:
//	                bc:ec:aa:93:2a:0b:a8:c7:24:34:54:42:38:a5:d1:
//	                0c:c4:f9:9e:7c:69:42:71:77:d7:95:aa:bb:13:3d:
//	                f3:cc:c7:5d:b3:fd:76:25:25:e3:da:14:0e:59:81:
//	                e8:2c:58:e8:09:29:7d:22:02:91:95:81:eb:55:6f:
//	                2f:17:b9:af:4a:f3:84:8b:24:6e:ea:14:6b:bb:90:
//	                84:35
//	            Exponent: 65537 (0x10001)
//	    X509v3 extensions:
//	        X509v3 Subject Key Identifier:
//	            01:02:03:04
//	        X509v3 Authority Key Identifier:
//	            keyid:01:02:03:04
//
//	        X509v3 Basic Constraints: critical
//	            CA:TRUE, pathlen:10
//	        X509v3 Key Usage: critical
//	            Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign, Encipher Only, Decipher Only
//	Signature Algorithm: sha256WithRSAEncryption
//	     92:be:33:eb:d5:d4:32:e7:9e:4e:65:2a:e8:3f:67:b8:f4:d7:
//	     34:ab:95:11:6a:5d:ba:fd:57:9b:94:6e:8d:20:be:fb:7a:e1:
//	     49:ca:39:ea:92:d3:81:5a:b1:87:a3:9f:50:a4:e0:1e:11:de:
//	     c4:d1:07:a1:ca:d1:97:1a:92:bd:73:9a:11:ec:6a:9a:52:11:
//	     2d:40:e1:3b:4f:3c:1f:81:3f:4c:ab:6a:02:84:4f:8b:18:36:
//	     7a:cc:5c:a9:0e:25:2b:cd:57:53:88:d9:eb:82:b1:ce:62:76:
//	     56:d4:23:9e:01:b3:6d:2b:49:ea:d4:3a:c2:f5:76:a7:b3:2d:
//	     24:97:6f:b4:1c:74:6b:95:85:f6:b5:41:56:82:3c:ed:be:96:
//	     1e:5e:6a:2d:7b:f7:fd:7d:6e:3f:fb:c2:ec:61:b3:7c:7f:3b:
//	     f5:9c:64:61:5f:02:93:87:cd:81:f9:7e:53:3e:c1:f5:79:85:
//	     f4:41:87:c7:ca:bd:af:ab:2b:a4:aa:a8:1d:2c:50:ad:23:8f:
//	     db:13:1d:71:8a:85:bd:ac:59:6c:c4:53:c5:71:0c:90:91:f3:
//	     0b:41:ef:da:6e:27:bb:09:57:9c:97:b9:d7:fc:20:96:c5:75:
//	     96:ce:2e:6c:a8:b6:6e:b0:4d:0f:3e:01:95:ea:8b:cd:ae:47:
//	     d0:d9:01:b7
const pemFakeCACert = `
-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIJALYx0qwhq2UgMA0GCSqGSIb3DQEBCwUAMHExCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEPMA0GA1UE
CgwGR29vZ2xlMQwwCgYDVQQLDANFbmcxITAfBgNVBAMMGEZha2VDZXJ0aWZpY2F0
ZUF1dGhvcml0eTAeFw0xNjA3MTExMjIzMjZaFw0xNzA3MTExMjIzMjZaMHExCzAJ
BgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjEPMA0G
A1UECgwGR29vZ2xlMQwwCgYDVQQLDANFbmcxITAfBgNVBAMMGEZha2VDZXJ0aWZp
Y2F0ZUF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKVB
mnotmKO1eG8VIdsMwQ6h+Cb1s7Jnhdyh5reDbdpj2tD2o/+8Q/UrnwAZbmtgS0Mg
buLLLrZl7ZvcgMPhWpavYHgODvuP6j49yWePpFccuuTzN6kv3RGdEF3l1u/UOwbZ
NENCu7u+Q0Ar47bRtWxYEjSWFNT8SXnFJowkfbMS9fY+t0FGa206Qf1847X8lmzG
zK2NSAlzRGTqTxcdCksUWhkHSjIPQS7khb2h4ZveY3w7vOyqkyoLqMckNFRCOKXR
DMT5nnxpQnF315WquxM988zHXbP9diUl49oUDlmB6CxY6AkpfSICkZWB61VvLxe5
r0rzhIskbuoUa7uQhDUCAwEAAaNHMEUwDQYDVR0OBAYEBAECAwQwDwYDVR0jBAgw
BoAEAQIDBDASBgNVHRMBAf8ECDAGAQH/AgEKMA8GA1UdDwEB/wQFAwMH/4AwDQYJ
KoZIhvcNAQELBQADggEBAJK+M+vV1DLnnk5lKug/Z7j01zSrlRFqXbr9V5uUbo0g
vvt64UnKOeqS04FasYejn1Ck4B4R3sTRB6HK0Zcakr1zmhHsappSES1A4TtPPB+B
P0yragKET4sYNnrMXKkOJSvNV1OI2euCsc5idlbUI54Bs20rSerUOsL1dqezLSSX
b7QcdGuVhfa1QVaCPO2+lh5eai179/19bj/7wuxhs3x/O/WcZGFfApOHzYH5flM+
wfV5hfRBh8fKva+rK6SqqB0sUK0jj9sTHXGKhb2sWWzEU8VxDJCR8wtB79puJ7sJ
V5yXudf8IJbFdZbOLmyotm6wTQ8+AZXqi82uR9DZAbc=
-----END CERTIFICATE-----`
