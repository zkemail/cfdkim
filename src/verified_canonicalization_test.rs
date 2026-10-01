//! Regression tests for `canonicalize_verified_signed_email`: the canonicalized output must
//! belong to the DKIM-Signature that verified, not simply to the first DKIM-Signature header.
#[cfg(test)]
mod tests {
    use crate::{
        canonicalization, canonicalize_signed_email, canonicalize_verified_signed_email,
        DkimPrivateKey, DkimPublicKey, SignerBuilder,
    };
    use base64::engine::general_purpose;
    use base64::Engine;
    use chrono::TimeZone;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use std::path::Path;

    const DOMAIN: &str = "example.com";

    fn logger() -> slog::Logger {
        slog::Logger::root(slog::Discard, slog::o!())
    }

    fn rsa_key() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::read_pkcs1_pem_file(Path::new("./test/keys/2022.private")).unwrap()
    }

    fn ed_key() -> ed25519_dalek::SigningKey {
        let decoded = general_purpose::STANDARD
            .decode(std::fs::read("./test/keys/ed.private").unwrap())
            .unwrap();
        ed25519_dalek::SigningKey::from_bytes(&ed25519_dalek::SecretKey::try_from(decoded).unwrap())
    }

    fn sign(raw_email: &str, key: DkimPrivateKey, selector: &str) -> String {
        let email = mailparse::parse_mail(raw_email.as_bytes()).unwrap();
        let logger = logger();
        let header = SignerBuilder::new()
            .with_signed_headers(&["From", "Subject"])
            .unwrap()
            .with_private_key(key)
            .with_header_canonicalization(canonicalization::Type::Relaxed)
            .with_body_canonicalization(canonicalization::Type::Relaxed)
            .with_selector(selector)
            .with_signing_domain(DOMAIN)
            .with_logger(&logger)
            .with_time(chrono::Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())
            .build()
            .unwrap()
            .sign(&email)
            .unwrap();
        format!("{}\r\n{}", header, raw_email)
    }

    fn base_email() -> String {
        "From: Alice <alice@example.com>\r\nSubject: real subject\r\n\r\nHello\r\n".to_string()
    }

    fn rsa_public() -> DkimPublicKey {
        DkimPublicKey::Rsa(rsa_key().to_public_key())
    }

    #[test]
    fn picks_the_verified_signature_not_the_first_one() {
        let legit = sign(&base_email(), DkimPrivateKey::Rsa(rsa_key()), "2022");
        // An unverifiable signature from another domain sits on top and names an extra,
        // unsigned Subject header, which select_headers resolves to the prepended one.
        let tampered = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=other.example; s=x;\r\n h=from:subject:subject; bh=AAAA; b=AAAA\r\nSubject: unsigned subject\r\n{}",
            legit
        );

        // The first-signature helper canonicalizes the bogus signature (documents the hazard).
        let (first_header, _, _) = canonicalize_signed_email(tampered.as_bytes()).unwrap();
        assert!(String::from_utf8_lossy(&first_header).contains("unsigned subject"));

        let (header, body, signature) = canonicalize_verified_signed_email(
            &logger(),
            tampered.as_bytes(),
            DOMAIN,
            rsa_public(),
            false,
        )
        .unwrap();
        let (legit_header, legit_body, legit_signature) =
            canonicalize_signed_email(legit.as_bytes()).unwrap();
        assert!(!String::from_utf8_lossy(&header).contains("unsigned subject"));
        assert_eq!(header, legit_header);
        assert_eq!(body, legit_body);
        assert_eq!(signature, legit_signature);
    }

    #[test]
    fn skips_same_domain_signature_made_with_another_key() {
        // Same d=, two selectors (key rotation / dual signing): ed25519 on top, RSA below.
        let rsa_signed = sign(&base_email(), DkimPrivateKey::Rsa(rsa_key()), "2022");
        let both = sign(&rsa_signed, DkimPrivateKey::Ed25519(ed_key()), "ed");
        assert!(both.starts_with("DKIM-Signature: v=1; a=ed25519-sha256"));

        let (header, _, _) = canonicalize_verified_signed_email(
            &logger(),
            both.as_bytes(),
            DOMAIN,
            rsa_public(),
            false,
        )
        .unwrap();
        let header = String::from_utf8_lossy(&header);
        assert!(header.contains("s=2022"), "{}", header);
        assert!(!header.contains("a=ed25519-sha256"), "{}", header);
    }

    #[test]
    fn rejects_wrong_domain_wrong_key_and_tampered_body() {
        let legit = sign(&base_email(), DkimPrivateKey::Rsa(rsa_key()), "2022");
        assert!(canonicalize_verified_signed_email(
            &logger(),
            legit.as_bytes(),
            "other.example",
            rsa_public(),
            false
        )
        .is_err());
        assert!(canonicalize_verified_signed_email(
            &logger(),
            legit.as_bytes(),
            DOMAIN,
            DkimPublicKey::Ed25519(ed_key().verifying_key()),
            false
        )
        .is_err());
        let tampered_body = legit.replace("Hello", "Goodbye");
        assert!(canonicalize_verified_signed_email(
            &logger(),
            tampered_body.as_bytes(),
            DOMAIN,
            rsa_public(),
            false
        )
        .is_err());
        // With the body hash ignored only the header signature matters.
        assert!(canonicalize_verified_signed_email(
            &logger(),
            tampered_body.as_bytes(),
            DOMAIN,
            rsa_public(),
            true
        )
        .is_ok());
    }

    /// Hand-built RSA signature carrying `l=` (the signer has no option for it).
    fn sign_with_body_length(raw_email: &str, length: usize) -> String {
        let email = mailparse::parse_mail(raw_email.as_bytes()).unwrap();
        let bh = crate::hash::compute_body_hash(
            canonicalization::Type::Relaxed,
            Some(length.to_string()),
            crate::hash::HashAlgo::RsaSha256,
            &email,
        )
        .unwrap();
        let unsigned = format!(
            "v=1; a=rsa-sha256; d={}; s=2022; c=relaxed/relaxed; l={}; h=from:subject; bh={}; b=",
            DOMAIN, length, bh
        );
        let header = crate::validate_header(&unsigned).unwrap();
        let hash = crate::hash::compute_headers_hash(
            &logger(),
            canonicalization::Type::Relaxed,
            "from:subject",
            crate::hash::HashAlgo::RsaSha256,
            &header,
            &email,
        )
        .unwrap();
        let sig = rsa_key()
            .sign(rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(), &hash)
            .unwrap();
        format!(
            "DKIM-Signature: {}{}\r\n{}",
            unsigned,
            general_purpose::STANDARD.encode(sig),
            raw_email
        )
    }

    #[test]
    fn body_length_limited_signature_is_not_returned_with_the_body() {
        // "Hello\r\n" is signed (l=7); the appended line is not covered by the signature.
        let signed = sign_with_body_length(&base_email(), 7);
        let extended = format!("{}Unsigned line\r\n", signed);

        // Header-only use: the signature itself is valid.
        assert!(canonicalize_verified_signed_email(
            &logger(),
            extended.as_bytes(),
            DOMAIN,
            rsa_public(),
            true
        )
        .is_ok());
        // Body use: refused, since the returned body would include the unsigned line.
        assert!(canonicalize_verified_signed_email(
            &logger(),
            extended.as_bytes(),
            DOMAIN,
            rsa_public(),
            false
        )
        .is_err());
    }
}
