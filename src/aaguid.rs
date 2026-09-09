//! Well-known authenticator AAGUIDs (informational registry).
//!
//! The AAGUID (Authenticator Attestation Globally Unique Identifier) is the
//! 16-byte model identifier embedded in attested credential data during
//! registration (CTAP2 §6.1). [`known_aaguid`] maps a small set of widely
//! deployed AAGUIDs to human-readable authenticator names for display and
//! inventory purposes.
//!
//! # This is NOT a metadata service
//!
//! This table is **informational only**. Real authenticator policy — attestation
//! root certificates, authenticator capabilities, security notices, revocation
//! — requires the [FIDO Metadata Service](https://fidoalliance.org/metadata/)
//! (MDS), whose signed blob is versioned and refreshed continuously. MDS
//! lookup is future work (see THREAT-MODEL.md OPEN-3); an AAGUID absent from
//! this table is *unknown*, not *untrusted*, and an entry here confers no
//! trust beyond the attestation verification that already happened.
//!
//! # Sources
//!
//! - Hardware security keys: FIDO Metadata Service (MDS3) metadata
//!   statements, `https://mds3.fidoalliance.org/` (retrieved 2026-09).
//! - Platform authenticators (Apple/Google/Microsoft) and password managers:
//!   the community-maintained
//!   [`passkey-authenticator-aaguids`](https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
//!   registry (retrieved 2026-09).
//! - Windows Hello hardware/software/VBS AAGUIDs additionally match
//!   Microsoft's published documentation.

/// YubiKey 5 Series (USB-A/C, firmware 5.x). Source: FIDO MDS3.
pub const AAGUID_NAME_YUBIKEY_5_SERIES: &str = "YubiKey 5 Series";
/// YubiKey 5 Series with NFC (firmware 5.x). Source: FIDO MDS3.
pub const AAGUID_NAME_YUBIKEY_5_NFC: &str = "YubiKey 5 Series with NFC";
/// YubiKey 5 Series with Lightning connector (5Ci). Source: FIDO MDS3.
pub const AAGUID_NAME_YUBIKEY_5C: &str = "YubiKey 5 Series with Lightning";
/// YubiKey 5 FIPS Series (USB). Source: FIDO MDS3.
pub const AAGUID_NAME_YUBIKEY_5_FIPS: &str = "YubiKey 5 FIPS Series";
/// YubiKey 5 FIPS Series with NFC. Source: FIDO MDS3.
pub const AAGUID_NAME_YUBIKEY_5_FIPS_NFC: &str = "YubiKey 5 FIPS Series with NFC";
/// YubiKey Bio Series — FIDO Edition (fingerprint). Source: FIDO MDS3.
pub const AAGUID_NAME_YUBIKEY_BIO: &str = "YubiKey Bio Series - FIDO Edition";
/// Security Key by Yubico (USB). Source: FIDO MDS3.
pub const AAGUID_NAME_SECURITY_KEY_YUBICO: &str = "Security Key by Yubico";
/// Security Key NFC by Yubico. Source: FIDO MDS3.
pub const AAGUID_NAME_SECURITY_KEY_YUBICO_NFC: &str = "Security Key NFC by Yubico";
/// Feitian ePass FIDO2 (USB). Source: FIDO MDS3.
pub const AAGUID_NAME_FEITIAN_EPASS_FIDO2: &str = "Feitian ePass FIDO2 Authenticator";
/// Feitian ePass FIDO2-NFC. Source: FIDO MDS3.
pub const AAGUID_NAME_FEITIAN_EPASS_FIDO2_NFC: &str = "Feitian ePass FIDO2-NFC Authenticator";
/// Feitian BioPass FIDO2 Pro (fingerprint). Source: FIDO MDS3.
pub const AAGUID_NAME_FEITIAN_BIOPASS_PRO: &str = "Feitian BioPass FIDO2 Pro Authenticator";
/// SoloKeys Solo (Secp256R1 build). Source: FIDO MDS3.
pub const AAGUID_NAME_SOLO_SECP256R1: &str = "SoloKeys Solo Secp256R1 FIDO2 Authenticator";
/// SoloKeys Solo Tap. Source: FIDO MDS3.
pub const AAGUID_NAME_SOLO_TAP: &str = "SoloKeys Solo Tap Secp256R1 FIDO2 Authenticator";
/// Nitrokey 3 (AM build). Source: FIDO MDS3.
pub const AAGUID_NAME_NITROKEY_3: &str = "Nitrokey 3 AM";
/// Google Titan Security Key v2. Source: FIDO MDS3.
pub const AAGUID_NAME_GOOGLE_TITAN_V2: &str = "Google Titan Security Key v2";
/// Apple iCloud Keychain synced passkeys. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_APPLE_ICLOUD_KEYCHAIN: &str = "Apple iCloud Keychain (Managed)";
/// Apple Passwords app. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_APPLE_PASSWORDS: &str = "Apple Passwords";
/// Google Password Manager (Android/Chrome synced passkeys).
/// Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_GOOGLE_PASSWORD_MANAGER: &str = "Google Password Manager";
/// Chrome profile-bound passkeys on macOS. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_CHROME_ON_MAC: &str = "Chrome on Mac";
/// Windows Hello hardware authenticator (TPM). Source: Microsoft documentation / FIDO MDS3.
pub const AAGUID_NAME_WINDOWS_HELLO_HARDWARE: &str = "Windows Hello Hardware Authenticator";
/// Windows Hello software authenticator. Source: Microsoft documentation / FIDO MDS3.
pub const AAGUID_NAME_WINDOWS_HELLO_SOFTWARE: &str = "Windows Hello Software Authenticator";
/// Windows Hello VBS (virtualization-based security) hardware authenticator.
/// Source: Microsoft documentation / FIDO MDS3.
pub const AAGUID_NAME_WINDOWS_HELLO_VBS: &str = "Windows Hello VBS Hardware Authenticator";
/// 1Password. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_ONEPASSWORD: &str = "1Password";
/// Bitwarden. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_BITWARDEN: &str = "Bitwarden";
/// Dashlane. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_DASHLANE: &str = "Dashlane";
/// Keeper. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_KEEPER: &str = "Keeper";
/// KeePassXC. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_KEEPASSXC: &str = "KeePassXC";
/// Samsung Pass. Source: passkey-authenticator-aaguids.
pub const AAGUID_NAME_SAMSUNG_PASS: &str = "Samsung Pass";

/// AAGUID → name table entry (the 16-byte AAGUID is written in UUID order,
/// exactly as it appears in attested credential data).
const KNOWN_AAGUIDS: &[([u8; 16], &str)] = &[
    // --- Yubico (FIDO MDS3) ---
    (
        uuid("cb69481e-8ff7-4039-93ec-0a2729a154a8"),
        AAGUID_NAME_YUBIKEY_5_SERIES,
    ),
    (
        uuid("fa2b99dc-9e39-4257-8f92-4a30d23c4118"),
        AAGUID_NAME_YUBIKEY_5_NFC,
    ),
    (
        uuid("a02167b9-ae71-4ac7-9a07-06432ebb6f1c"),
        AAGUID_NAME_YUBIKEY_5C,
    ),
    (
        uuid("57f7de54-c807-4eab-b1c6-1c9be7984e92"),
        AAGUID_NAME_YUBIKEY_5_FIPS,
    ),
    (
        uuid("c1f9a0bc-1dd2-404a-b27f-8e29047a43fd"),
        AAGUID_NAME_YUBIKEY_5_FIPS_NFC,
    ),
    (
        uuid("d8522d9f-575b-4866-88a9-ba99fa02f35b"),
        AAGUID_NAME_YUBIKEY_BIO,
    ),
    (
        uuid("f8a011f3-8c0a-4d15-8006-17111f9edc7d"),
        AAGUID_NAME_SECURITY_KEY_YUBICO,
    ),
    (
        uuid("b7d3f68e-88a6-471e-9ecf-2df26d041ede"),
        AAGUID_NAME_SECURITY_KEY_YUBICO_NFC,
    ),
    // --- Feitian (FIDO MDS3) ---
    (
        uuid("833b721a-ff5f-4d00-bb2e-bdda3ec01e29"),
        AAGUID_NAME_FEITIAN_EPASS_FIDO2,
    ),
    (
        uuid("ee041bce-25e5-4cdb-8f86-897fd6418464"),
        AAGUID_NAME_FEITIAN_EPASS_FIDO2_NFC,
    ),
    (
        uuid("4c0cf95d-2f40-43b5-ba42-4c83a11c04ba"),
        AAGUID_NAME_FEITIAN_BIOPASS_PRO,
    ),
    // --- SoloKeys (FIDO MDS3) ---
    (
        uuid("8876631b-d4a0-427f-5773-0ec71c9e0279"),
        AAGUID_NAME_SOLO_SECP256R1,
    ),
    (
        uuid("8976631b-d4a0-427f-5773-0ec71c9e0279"),
        AAGUID_NAME_SOLO_TAP,
    ),
    // --- Nitrokey (FIDO MDS3) ---
    (
        uuid("2cd2f727-f6ca-44da-8f48-5c2e5da000a2"),
        AAGUID_NAME_NITROKEY_3,
    ),
    // --- Google hardware (FIDO MDS3) ---
    (
        uuid("42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3"),
        AAGUID_NAME_GOOGLE_TITAN_V2,
    ),
    // --- Platform authenticators (passkey-authenticator-aaguids / Microsoft) ---
    (
        uuid("dd4ec289-e01d-41c9-bb89-70fa845d4bf2"),
        AAGUID_NAME_APPLE_ICLOUD_KEYCHAIN,
    ),
    (
        uuid("fbfc3007-154e-4ecc-8c0b-6e020557d7bd"),
        AAGUID_NAME_APPLE_PASSWORDS,
    ),
    (
        uuid("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"),
        AAGUID_NAME_GOOGLE_PASSWORD_MANAGER,
    ),
    (
        uuid("adce0002-35bc-c60a-648b-0b25f1f05503"),
        AAGUID_NAME_CHROME_ON_MAC,
    ),
    (
        uuid("08987058-cadc-4b81-b6e1-30de50dcbe96"),
        AAGUID_NAME_WINDOWS_HELLO_HARDWARE,
    ),
    (
        uuid("9ddd1817-af5a-4672-a2b9-3e3dd95000a9"),
        AAGUID_NAME_WINDOWS_HELLO_SOFTWARE,
    ),
    (
        uuid("6028b017-b1d4-4c02-b4b3-afcdafc96bb2"),
        AAGUID_NAME_WINDOWS_HELLO_VBS,
    ),
    // --- Password managers (passkey-authenticator-aaguids) ---
    (
        uuid("bada5566-a7aa-401f-bd96-45619a55120d"),
        AAGUID_NAME_ONEPASSWORD,
    ),
    (
        uuid("d548826e-79b4-db40-a3d8-11116f7e8349"),
        AAGUID_NAME_BITWARDEN,
    ),
    (
        uuid("531126d6-e717-415c-9320-3d9aa6981239"),
        AAGUID_NAME_DASHLANE,
    ),
    (
        uuid("0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6"),
        AAGUID_NAME_KEEPER,
    ),
    (
        uuid("fdb141b2-5d84-443e-8a35-4698c205a502"),
        AAGUID_NAME_KEEPASSXC,
    ),
    (
        uuid("53414d53-554e-4700-0000-000000000000"),
        AAGUID_NAME_SAMSUNG_PASS,
    ),
];

/// Parse the canonical textual UUID form into its 16 big-endian bytes
/// (the layout used in attested credential data).
const fn uuid(s: &str) -> [u8; 16] {
    // hex nibble → value, const-friendly.
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit in AAGUID constant"),
        }
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 16];
    let mut out_i = 0;
    let mut i = 0;
    // Walk the canonical 8-4-4-4-12 form, skipping '-' separators.
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'-' {
            i += 1;
            continue;
        }
        if out_i >= 16 || i + 1 >= bytes.len() {
            panic!("AAGUID constant is not a 16-byte UUID");
        }
        out[out_i] = (nibble(c) << 4) | nibble(bytes[i + 1]);
        out_i += 1;
        i += 2;
    }
    if out_i != 16 {
        panic!("AAGUID constant is not a 16-byte UUID");
    }
    out
}

/// Look up a known authenticator model by its AAGUID.
///
/// Returns the human-readable authenticator name for well-known AAGUIDs, or
/// `None` if the AAGUID is not in this build's registry. An unknown AAGUID is
/// *not* evidence of a bad registration — the vast majority of authenticators
/// are not in this deliberately small informational table. Security policy
/// must be based on attestation verification, not on this lookup.
///
/// # Requirements
/// REQ-WA-131
pub fn known_aaguid(aaguid: &[u8; 16]) -> Option<&'static str> {
    KNOWN_AAGUIDS
        .iter()
        .find(|(known, _)| known == aaguid)
        .map(|(_, name)| *name)
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// REQ-WA-131: well-known AAGUIDs resolve to their authenticator names.
    #[test]
    fn known_entries_resolve() {
        let yubikey5 = uuid("cb69481e-8ff7-4039-93ec-0a2729a154a8");
        assert_eq!(known_aaguid(&yubikey5), Some(AAGUID_NAME_YUBIKEY_5_SERIES));

        let windows_hello = uuid("08987058-cadc-4b81-b6e1-30de50dcbe96");
        assert_eq!(
            known_aaguid(&windows_hello),
            Some(AAGUID_NAME_WINDOWS_HELLO_HARDWARE)
        );

        let gpm = uuid("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4");
        assert_eq!(
            known_aaguid(&gpm),
            Some(AAGUID_NAME_GOOGLE_PASSWORD_MANAGER)
        );
    }

    /// REQ-WA-131: unknown and all-zero AAGUIDs return `None` (never a name).
    #[test]
    fn unknown_aaguid_returns_none() {
        assert_eq!(known_aaguid(&[0u8; 16]), None);
        assert_eq!(known_aaguid(&[0xEE; 16]), None);
    }

    /// The `uuid` const helper must produce the big-endian byte layout used
    /// in attested credential data (UUID text form → raw bytes).
    #[test]
    fn uuid_helper_layout() {
        // 53414d53-554e-4700-0000-000000000000 is ASCII "SAMSUNG" — a
        // self-checking vector for byte order.
        let samsung = uuid("53414d53-554e-4700-0000-000000000000");
        assert_eq!(&samsung[0..7], b"SAMSUNG");
        assert_eq!(samsung[7], 0x00);
        assert_eq!(&samsung[8..], &[0u8; 8]);
    }
}
