// Copyright 2021 Google LLC. All Rights Reserved.
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

package x509util

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
)

// OIDExtensionAndroidAttestation is the OID value for an X.509 extension that holds
// Android attestation info.
var OIDExtensionAndroidAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// AndroidAttestationInfo holds attestation information attached to an Android
// hardware-backed key, describing features of the key and the device that issued
// it. See https://developer.android.com/training/articles/security-key-attestation for
// more information.
type AndroidAttestationInfo struct {
	AttestationVersion       int64
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int64
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	UniqueId                 []byte
	SoftwareEnforced         AuthorizationList
	HardwareEnforced         AuthorizationList
}

func securityLevelToString(lvl asn1.Enumerated) string {
	switch lvl {
	case 0:
		return "SOFTWARE"
	case 1:
		return "TRUSTED_ENVIRONMENT"
	case 2:
		return "STRONGBOX"
	}
	return fmt.Sprintf("UNKNOWN(%d)", lvl)
}

// RootOfTrust describes the verified boot state of an Android device at the point
// when a key was created.
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte
}

func bootStateToString(st asn1.Enumerated) string {
	switch st {
	case 0:
		return "VERIFIED"
	case 1:
		return "SELF_SIGNED"
	case 2:
		return "UNVERIFIED"
	case 3:
		return "FAILED"
	}
	return fmt.Sprintf("UNKNOWN(%d)", st)
}

// AuthorizationList holds attributes that describe the restrictions placed on
// an Android hardware-backed key, and which describe the state of the device
// that issued the key.
type AuthorizationList struct {
	Purpose                   []int         `asn1:"optional,explicit,tag:1,set"`
	Algorithm                 int           `asn1:"optional,explicit,tag:2,default:-1"`
	KeySize                   int           `asn1:"optional,explicit,tag:3,default:-1"`
	BlockMode                 []int         `asn1:"optional,explicit,tag:4,default:-1"`
	Digest                    []int         `asn1:"optional,explicit,tag:5,set"`
	Padding                   []int         `asn1:"optional,explicit,tag:6,set"`
	CallerNonce               asn1.RawValue `asn1:"optional,explicit,tag:7"`
	MinMacLength              int           `asn1:"optional,explicit,tag:8,default:-1"`
	EcCurve                   int           `asn1:"optional,explicit,tag:10,default:-1"`
	RsaPublicExponent         int           `asn1:"optional,explicit,tag:200,default:-1"`
	MgfDigest                 []int         `asn1:"optional,explicit,tag:203,set"`
	RollbackResistance        asn1.RawValue `asn1:"optional,explicit,tag:303"`
	EarlyBootOnly             asn1.RawValue `asn1:"optional,explicit,tag:305"`
	ActiveDateTime            int64         `asn1:"optional,explicit,tag:400,default:-1"`
	OriginationExpireDateTime int64         `asn1:"optional,explicit,tag:401,default:-1"`
	UsageExpireDateTime       int64         `asn1:"optional,explicit,tag:402,default:-1"`
	UsageCountLimit           int           `asn1:"optional,explicit,tag:405,default:-1"`
	UserSecureId              int           `asn1:"optional,explicit,tag:502,default:-1"`
	NoAuthRequired            asn1.RawValue `asn1:"optional,explicit,tag:503"`
	UserAuthType              int           `asn1:"optional,explicit,tag:504,default:-1"`
	AuthTimeout               int           `asn1:"optional,explicit,tag:505,default:-1"`
	AllowWhileOnBody          asn1.RawValue `asn1:"optional,explicit,tag:506"`
	TrustedUserPresenceReq    asn1.RawValue `asn1:"optional,explicit,tag:507"`
	TrustedConfirmationReq    asn1.RawValue `asn1:"optional,explicit,tag:508"`
	UnlockDeviceReq           asn1.RawValue `asn1:"optional,explicit,tag:509"`
	CreationDateTime          int64         `asn1:"optional,explicit,tag:701,default:-1"`
	Origin                    int           `asn1:"optional,explicit,tag:702,default:-1"`
	RootOfTrust               asn1.RawValue `asn1:"optional,explicit,tag:704"`
	OsVersion                 int           `asn1:"optional,explicit,tag:705,default:-1"`
	OsPatchlevel              int           `asn1:"optional,explicit,tag:706,default:-1"`
	AttestationApplicationId  []byte        `asn1:"optional,explicit,tag:709"`
	AttestationIdBrand        []byte        `asn1:"optional,explicit,tag:710"`
	AttestationIdDevice       []byte        `asn1:"optional,explicit,tag:711"`
	AttestationIdProduct      []byte        `asn1:"optional,explicit,tag:712"`
	AttestationIdSerial       []byte        `asn1:"optional,explicit,tag:713"`
	AttestationIdImei         []byte        `asn1:"optional,explicit,tag:714"`
	AttestationIdMeid         []byte        `asn1:"optional,explicit,tag:715"`
	AttestationIdManufacturer []byte        `asn1:"optional,explicit,tag:716"`
	AttestationIdModel        []byte        `asn1:"optional,explicit,tag:717"`
	VendorPatchlevel          int           `asn1:"optional,explicit,tag:718,default:-1"`
	BootPatchlevel            int           `asn1:"optional,explicit,tag:719,default:-1"`
	DeviceUniqueAttestation   asn1.RawValue `asn1:"optional,explicit,tag:720"`
	IdentityCredentialKey     asn1.RawValue `asn1:"optional,explicit,tag:721"`
}

// AttestInfoFromCert retrieves and parses an Android attestation information extension
// from a certificate, if present.
func AttestInfoFromCert(cert *x509.Certificate) (*AndroidAttestationInfo, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDExtensionAndroidAttestation) {
			var attestInfo AndroidAttestationInfo
			rest, err := asn1.Unmarshal(ext.Value, &attestInfo)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal attestation info: %v", err)
			} else if len(rest) > 0 {
				return nil, fmt.Errorf("trailing data (%d bytes) after attestation info", len(rest))
			}
			return &attestInfo, nil
		}
	}
	return nil, errors.New("no Android Attestation extension found")
}

func showAndroidAttestation(result *bytes.Buffer, cert *x509.Certificate) {
	count, critical := OIDInExtensions(OIDExtensionAndroidAttestation, cert.Extensions)
	if count == 0 {
		return
	}
	result.WriteString(fmt.Sprintf("            Android Attestation Information:"))
	showCritical(result, critical)
	attestInfo, err := AttestInfoFromCert(cert)
	if err != nil {
		result.WriteString(fmt.Sprintf("              Failed to decode attestation info: (%s)\n", err))
		return
	}
	result.WriteString(fmt.Sprintf("              Attestation Version: %d\n", attestInfo.AttestationVersion))
	result.WriteString(fmt.Sprintf("              Attestation Security Level: %s\n", securityLevelToString(attestInfo.AttestationSecurityLevel)))
	result.WriteString(fmt.Sprintf("              KeyMint Version: %d\n", attestInfo.KeyMintVersion))
	result.WriteString(fmt.Sprintf("              KeyMint Security Level: %s\n", securityLevelToString(attestInfo.KeyMintSecurityLevel)))
	showHex(result, "              ", "Attestation Challenge", attestInfo.AttestationChallenge)
	showHex(result, "              ", "Unique ID", attestInfo.UniqueId)
	result.WriteString(fmt.Sprintf("              Software Enforced:\n"))
	showKeyAuthorizations(result, attestInfo.SoftwareEnforced, "                    ")
	result.WriteString(fmt.Sprintf("              Hardware Enforced:\n"))
	showKeyAuthorizations(result, attestInfo.HardwareEnforced, "                    ")

	result.WriteString("\n")
}

func showKeyAuthorizations(buf *bytes.Buffer, auths AuthorizationList, prefix string) {
	if len(auths.Purpose) > 0 {
		buf.WriteString(fmt.Sprintf("%sPurpose: %s\n", prefix, enumsToString(auths.Purpose, purposeToString)))
	}
	if auths.Algorithm != -1 {
		buf.WriteString(fmt.Sprintf("%sAlgorithm: %s\n", prefix, algorithmToString(auths.Algorithm)))
	}
	if auths.KeySize != -1 {
		buf.WriteString(fmt.Sprintf("%sKey Size: %d\n", prefix, auths.KeySize))
	}
	if len(auths.BlockMode) > 0 {
		buf.WriteString(fmt.Sprintf("%sBlockMode: %s\n", prefix, enumsToString(auths.BlockMode, blockModeToString)))
	}
	if len(auths.Digest) > 0 {
		buf.WriteString(fmt.Sprintf("%sDigest: %s\n", prefix, enumsToString(auths.Digest, digestToString)))
	}
	if len(auths.Padding) > 0 {
		buf.WriteString(fmt.Sprintf("%sPadding: %s\n", prefix, enumsToString(auths.Padding, paddingToString)))
	}
	showNullValue(buf, prefix, "Caller Nonce", auths.CallerNonce)
	if auths.MinMacLength != -1 {
		buf.WriteString(fmt.Sprintf("%sMin MAC Length: %d\n", prefix, auths.MinMacLength))
	}
	if auths.EcCurve != -1 {
		buf.WriteString(fmt.Sprintf("%sEcCurve: %s\n", prefix, ecCurveToString(auths.EcCurve)))
	}
	if auths.RsaPublicExponent != -1 {
		buf.WriteString(fmt.Sprintf("%sRsa Public Exponent: %d\n", prefix, auths.RsaPublicExponent))
	}
	if len(auths.MgfDigest) > 0 {
		buf.WriteString(fmt.Sprintf("%sMGF Digest: %s\n", prefix, enumsToString(auths.MgfDigest, digestToString)))
	}
	showNullValue(buf, prefix, "Rollback Resistance", auths.RollbackResistance)
	showNullValue(buf, prefix, "Early Boot Only", auths.EarlyBootOnly)
	showDateTimeValue(buf, prefix, "Active Date Time", auths.ActiveDateTime)
	showDateTimeValue(buf, prefix, "Origination Expire Date Time", auths.OriginationExpireDateTime)
	showDateTimeValue(buf, prefix, "Usage Expire Date Time", auths.UsageExpireDateTime)
	if auths.UsageCountLimit != -1 {
		buf.WriteString(fmt.Sprintf("%sUsage Count Limit: %d\n", prefix, auths.UsageCountLimit))
	}
	if auths.UserSecureId != -1 {
		buf.WriteString(fmt.Sprintf("%sUser Secure ID: %d\n", prefix, auths.UserSecureId))
	}
	showNullValue(buf, prefix, "No Auth Required", auths.NoAuthRequired)
	if auths.UserAuthType != -1 {
		buf.WriteString(fmt.Sprintf("%sUser Auth Type: 0x%02x\n", prefix, auths.UserAuthType))
	}
	if auths.AuthTimeout != -1 {
		buf.WriteString(fmt.Sprintf("%sAuth Timeout: %d\n", prefix, auths.AuthTimeout))
	}
	showNullValue(buf, prefix, "Allow While On Body", auths.AllowWhileOnBody)
	showNullValue(buf, prefix, "Trusted User Presence Req", auths.TrustedUserPresenceReq)
	showNullValue(buf, prefix, "Trusted Confirmation Req", auths.TrustedConfirmationReq)
	showNullValue(buf, prefix, "Unlock Device Req", auths.UnlockDeviceReq)
	showDateTimeValue(buf, prefix, "Creation Date Time", auths.CreationDateTime)
	if auths.Origin != -1 {
		buf.WriteString(fmt.Sprintf("%sOrigin: %s\n", prefix, originToString(auths.Origin)))
	}

	if len(auths.RootOfTrust.FullBytes) > 0 {
		var rootOfTrust RootOfTrust
		rest, err := asn1.Unmarshal(auths.RootOfTrust.Bytes, &rootOfTrust)
		if err != nil {
			buf.WriteString(fmt.Sprintf("%sRoot of Trust: FAILED TO PARSE %s\n", prefix, err))
		} else if len(rest) > 0 {
			buf.WriteString(fmt.Sprintf("%sRoot of Trust: FAILURE: TRAILING DATA\n", prefix))
		} else {
			buf.WriteString(fmt.Sprintf("%sRoot of Trust:\n", prefix))
			showHex(buf, prefix+"    ", "Verified Boot Key", rootOfTrust.VerifiedBootKey)
			buf.WriteString(fmt.Sprintf("%sDevice Locked: %v\n", prefix+"    ", rootOfTrust.DeviceLocked))
			buf.WriteString(fmt.Sprintf("%sVerified Boot State: %s\n", prefix+"    ", bootStateToString(rootOfTrust.VerifiedBootState)))
			showHex(buf, prefix+"    ", "Verified Boot Hash", rootOfTrust.VerifiedBootHash)
		}
	}

	if auths.OsVersion != -1 {
		buf.WriteString(fmt.Sprintf("%sOS Version: %d\n", prefix, auths.OsVersion))
	}
	if auths.OsPatchlevel != -1 {
		buf.WriteString(fmt.Sprintf("%sOS Patchlevel: %d\n", prefix, auths.OsPatchlevel))
	}

	showOptionalHex(buf, prefix, "Attestation Application Id", auths.AttestationApplicationId)
	showOptionalHex(buf, prefix, "Attestation Id Brand", auths.AttestationIdBrand)
	showOptionalHex(buf, prefix, "Attestation Id Device", auths.AttestationIdDevice)
	showOptionalHex(buf, prefix, "Attestation Id Product", auths.AttestationIdProduct)
	showOptionalHex(buf, prefix, "Attestation Id Serial", auths.AttestationIdSerial)
	showOptionalHex(buf, prefix, "Attestation Id IMEI", auths.AttestationIdImei)
	showOptionalHex(buf, prefix, "Attestation Id MEID", auths.AttestationIdMeid)
	showOptionalHex(buf, prefix, "Attestation Id Manufacturer", auths.AttestationIdManufacturer)
	showOptionalHex(buf, prefix, "Attestation Id Model", auths.AttestationIdModel)
	if auths.VendorPatchlevel != -1 {
		buf.WriteString(fmt.Sprintf("%sVendor Patchlevel: %d\n", prefix, auths.VendorPatchlevel))
	}
	if auths.BootPatchlevel != -1 {
		buf.WriteString(fmt.Sprintf("%sBoot Patchlevel: %d\n", prefix, auths.BootPatchlevel))
	}
	showNullValue(buf, prefix, "Device Unique Attestation", auths.DeviceUniqueAttestation)
	showNullValue(buf, prefix, "Identity Credential Key", auths.IdentityCredentialKey)
}

func enumsToString(vals []int, fp func(int) string) string {
	var buf bytes.Buffer
	for ii, v := range vals {
		if ii > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fp(v))
	}
	return buf.String()
}

func purposeToString(v int) string {
	switch v {
	case 0:
		return "ENCRYPT"
	case 1:
		return "DECRYPT"
	case 2:
		return "SIGN"
	case 3:
		return "VERIFY"
	case 5:
		return "WRAP_KEY"
	case 6:
		return "AGREE_KEY"
	case 7:
		return "ATTEST_KEY"
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}

func algorithmToString(v int) string {
	switch v {
	case 1:
		return "RSA"
	case 3:
		return "EC"
	case 32:
		return "AES"
	case 33:
		return "TRIPLE_DES"
	case 128:
		return "HMAC"
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)

}

func digestToString(v int) string {
	switch v {
	case 0:
		return "NONE"
	case 1:
		return "MD5"
	case 2:
		return "SHA1"
	case 3:
		return "SHA_2_224"
	case 4:
		return "SHA_2_256"
	case 5:
		return "SHA_2_384"
	case 6:
		return "SHA_2_512"
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}

func paddingToString(v int) string {
	switch v {
	case 1:
		return "NONE"
	case 2:
		return "RSA_OAEP"
	case 3:
		return "RSA_PSS"
	case 4:
		return "RSA_PKCS1_1_5_ENCRYPT"
	case 5:
		return "RSA_PKCS1_1_5_SIGN"
	case 64:
		return "PKCS7"
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}

func blockModeToString(v int) string {
	switch v {
	case 1:
		return "ECB"
	case 2:
		return "CBC"
	case 3:
		return "CTR"
	case 32:
		return "GCM"
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}

func ecCurveToString(v int) string {
	switch v {
	case 0:
		return "P_224"
	case 1:
		return "P_256"
	case 2:
		return "P_384"
	case 3:
		return "P_521"
	case 4:
		return "CURVE_25519"
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}

func originToString(v int) string {
	switch v {
	case 0:
		return "GENERATED"
	case 1:
		return "DERIVED"
	case 2:
		return "IMPORTED"
	case 3:
		return "RESERVED"
	case 4:
		return "SECURELY_IMPORTED"
	}
	return fmt.Sprintf("UNKNOWN(%d)", v)
}

func showNullValue(buf *bytes.Buffer, prefix string, name string, val asn1.RawValue) {
	if bytes.Equal(val.Bytes, asn1.NullBytes) {
		buf.WriteString(fmt.Sprintf("%s%s: TRUE\n", prefix, name))
	} else if len(val.FullBytes) == 0 {
		// Absent => FALSE
	} else {
		buf.WriteString(fmt.Sprintf("%s%s: invalid contents! %+v\n", prefix, name, val))
	}
}

func showDateTimeValue(buf *bytes.Buffer, prefix string, name string, val int64) {
	if val == -1 {
		return
	}
	// Value is milliseconds since epoch
	timestamp := time.Unix(val/1000, (val%1000)*1000000)
	buf.WriteString(fmt.Sprintf("%s%s: %s\n", prefix, name, timestamp))
}

func showOptionalHex(buf *bytes.Buffer, prefix string, name string, val []byte) {
	if len(val) == 0 {
		return
	}
	showHex(buf, prefix, name, val)
}

func showHex(buf *bytes.Buffer, prefix string, name string, val []byte) {
	buf.WriteString(fmt.Sprintf("%s%s:\n", prefix, name))
	appendHexData(buf, val, 64, prefix+"    ")
	buf.WriteString("\n")
}
