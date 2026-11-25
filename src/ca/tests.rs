//! Certificates checked by code that did not make them: rustls-webpki for
//! every name in the table, x509-parser against the profile table in the
//! design, and `openssl verify` when it is on `PATH`.

use std::process::Command;

use rustls_pki_types::{CertificateDer, UnixTime};
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::*;
use crate::files::test_support::TempDir;
use crate::files::{CaDir, ISSUER_FILE, ISSUER_KEY_FILE, ROOT_FILE};
use crate::names::table::{CASES, Expect};

fn names(list: &[&str]) -> Vec<SubjectName> {
    list.iter()
        .map(|n| SubjectName::parse(n).unwrap())
        .collect()
}

fn ders(pem: &str) -> Vec<Vec<u8>> {
    Pem::iter_from_buffer(pem.as_bytes())
        .map(|p| p.unwrap().contents)
        .collect()
}

fn parse(der: &[u8]) -> X509Certificate<'_> {
    X509Certificate::from_der(der).unwrap().1
}

/// rustls-webpki's verdict on `leaf` with the root as the only anchor:
/// `Ok(true)` if it verifies, `Ok(false)` for a name constraint violation,
/// and any other error as it is, so a broken chain cannot pass as a refusal.
fn webpki_accepts(ca: &Ca, leaf: &Leaf, at: OffsetDateTime) -> Result<bool, webpki::Error> {
    let root = CertificateDer::from(ders(ca.root_pem()).remove(0));
    let mut chain = ders(leaf.chain_pem()).into_iter().map(CertificateDer::from);
    let end_entity = chain.next().unwrap();
    let intermediates: Vec<_> = chain.collect();
    let anchors = [webpki::anchor_from_trusted_cert(&root)?];
    let cert = webpki::EndEntityCert::try_from(&end_entity)?;
    let secs = u64::try_from(at.unix_timestamp()).unwrap();
    let result = cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs)),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    );
    match result {
        Ok(_) => Ok(true),
        Err(webpki::Error::NameConstraintViolation) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Issues every parseable name in `cases` without the `permits` check and
/// returns the names where `permits` and `verifier` disagree.
fn disagreements(
    ca: &Ca,
    cases: &[&str],
    verifier: &mut dyn FnMut(&Leaf) -> Result<bool, String>,
) -> Vec<String> {
    let now = OffsetDateTime::now_utc();
    let mut wrong = Vec::new();
    for input in cases {
        let Ok(name) = SubjectName::parse(input) else {
            continue;
        };
        let leaf = ca
            .issue_unchecked(std::slice::from_ref(&name), LeafDays::default(), now)
            .unwrap();
        let ours = permits(ca.constraints(), &name);
        match verifier(&leaf) {
            Ok(theirs) if theirs == ours => {}
            Ok(theirs) => wrong.push(format!("{input}: permits {ours}, verifier {theirs}")),
            Err(e) => wrong.push(format!("{input}: verifier error {e}")),
        }
    }
    wrong
}

fn table_inputs() -> Vec<&'static str> {
    CASES
        .iter()
        .filter(|(_, e)| *e != Expect::Invalid)
        .map(|(input, _)| *input)
        .collect()
}

#[test]
fn webpki_agrees_with_permits_on_every_table_name() {
    let ca = Ca::create(Constraints::local(), OffsetDateTime::now_utc()).unwrap();
    let at = OffsetDateTime::now_utc() + Duration::minutes(1);
    let mut verifier = |leaf: &Leaf| webpki_accepts(&ca, leaf, at).map_err(|e| e.to_string());
    let wrong = disagreements(&ca, &table_inputs(), &mut verifier);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn webpki_agrees_with_permits_under_other_constraint_lists() {
    let dns = |n: &str| DnsName::parse(n).unwrap();
    let lists = [
        // No IP range: every address must be refused, by both.
        Constraints::new(vec![dns("corp.example")], Vec::new()).unwrap(),
        // IPv4 only: IPv6 addresses must be refused.
        Constraints::new(vec![dns("test")], vec![IpNet::parse("10.0.0.0/8").unwrap()]).unwrap(),
    ];
    let inputs = [
        "corp.example",
        "a.corp.example",
        "xcorp.example",
        "localhost",
        "app.test",
        "127.0.0.1",
        "10.1.2.3",
        "11.0.0.1",
        "::1",
        "::ffff:10.1.2.3",
        "*.a.corp.example",
    ];
    let at = OffsetDateTime::now_utc() + Duration::minutes(1);
    for constraints in lists {
        let ca = Ca::create(constraints, OffsetDateTime::now_utc()).unwrap();
        let mut verifier = |leaf: &Leaf| webpki_accepts(&ca, leaf, at).map_err(|e| e.to_string());
        let wrong = disagreements(&ca, &inputs, &mut verifier);
        assert!(
            wrong.is_empty(),
            "{:?}:\n{}",
            ca.constraints(),
            wrong.join("\n")
        );
    }
}

#[test]
fn the_cross_check_sees_both_verdicts() {
    // A verifier that rejects everything, or accepts everything, must not be
    // able to pass the table: it has to hold both kinds of name.
    let at = OffsetDateTime::now_utc() + Duration::minutes(1);
    let ca = Ca::create(Constraints::local(), OffsetDateTime::now_utc()).unwrap();
    let now = OffsetDateTime::now_utc();
    let good = ca
        .issue_unchecked(&names(&["app.test"]), LeafDays::default(), now)
        .unwrap();
    let bad = ca
        .issue_unchecked(&names(&["example.com"]), LeafDays::default(), now)
        .unwrap();
    assert_eq!(webpki_accepts(&ca, &good, at), Ok(true));
    assert_eq!(webpki_accepts(&ca, &bad, at), Ok(false));
}

#[test]
fn issue_refuses_a_name_outside_the_constraints() {
    let ca = Ca::create(Constraints::local(), OffsetDateTime::now_utc()).unwrap();
    let now = OffsetDateTime::now_utc();
    let err = ca
        .issue(
            &names(&["app.test", "example.com"]),
            LeafDays::default(),
            now,
        )
        .unwrap_err();
    assert!(matches!(err, Error::Refused(SubjectName::Dns(n)) if n.as_str() == "example.com"));
    assert!(matches!(
        ca.issue(&[], LeafDays::default(), now),
        Err(Error::NoNames)
    ));
}

#[test]
fn leaf_validity_is_one_to_825_days() {
    assert!(LeafDays::new(0).is_err());
    assert!(LeafDays::new(826).is_err());
    assert_eq!(LeafDays::new(825).unwrap().get(), 825);
    assert_eq!(LeafDays::default().get(), 365);
}

fn common_name<'a>(cert: &'a X509Certificate<'_>) -> &'a str {
    let mut cns = cert.subject().iter_common_name();
    let cn = cns.next().unwrap().as_str().unwrap();
    assert!(cns.next().is_none());
    cn
}

/// `<prefix> YYYY-MM-DD hhhh`, with the date of `now`.
fn assert_ca_name(cn: &str, prefix: &str, now: OffsetDateTime) {
    let date = format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    let rest = cn
        .strip_prefix(&format!("{prefix} {date} "))
        .unwrap_or_else(|| panic!("{cn}"));
    assert!(
        rest.len() == 4 && rest.bytes().all(|b| b.is_ascii_hexdigit()),
        "{cn}"
    );
}

#[test]
fn every_certificate_field_matches_the_profile_table() {
    let now = OffsetDateTime::now_utc();
    let ca = Ca::create(Constraints::local(), now).unwrap();
    let requested = names(&["app.test", "*.app.test", "127.0.0.1", "::1"]);
    let leaf = ca
        .issue(&requested, LeafDays::new(30).unwrap(), now)
        .unwrap();

    let root_der = ders(ca.root_pem()).remove(0);
    let chain = ders(leaf.chain_pem());
    assert_eq!(chain.len(), 2, "leaf then intermediate");
    assert_eq!(chain[1], ders(ca.issuer_pem())[0]);
    let (root, issuer, leaf) = (parse(&root_der), parse(&chain[1]), parse(&chain[0]));

    // Subject CN, and who signed whom.
    assert_ca_name(common_name(&root), "homecert root", now);
    assert_ca_name(common_name(&issuer), "homecert issuer", now);
    assert_eq!(common_name(&leaf), "app.test");
    assert_eq!(root.issuer(), root.subject());
    assert_eq!(issuer.issuer(), root.subject());
    assert_eq!(leaf.issuer(), issuer.subject());

    // Validity: five years for both CA certificates, the asked days for the leaf.
    let span = |c: &X509Certificate<'_>| {
        c.validity().not_after.to_datetime() - c.validity().not_before.to_datetime()
    };
    assert_eq!(span(&root), Duration::days(5 * 365 + 1));
    assert_eq!(issuer.validity(), root.validity());
    assert_eq!(span(&leaf), Duration::days(30));
    assert!((leaf.validity().not_before.to_datetime() - now).abs() < Duration::seconds(1));

    // Basic constraints: CA with path length 1, CA with 0, not a CA.
    let bc = |c: &X509Certificate<'_>| {
        let ext = c.basic_constraints().unwrap().unwrap();
        (ext.critical, ext.value.ca, ext.value.path_len_constraint)
    };
    assert_eq!(bc(&root), (true, true, Some(1)));
    assert_eq!(bc(&issuer), (true, true, Some(0)));
    assert_eq!(bc(&leaf), (true, false, None));

    // Key usage: certificate sign and CRL sign; digital signature.
    let ku = |c: &X509Certificate<'_>| c.key_usage().unwrap().unwrap().value.flags;
    assert_eq!(ku(&root), 0b110_0000);
    assert_eq!(ku(&issuer), 0b110_0000);
    assert_eq!(ku(&leaf), 0b1);

    // Extended key usage: none; server auth; server auth.
    assert!(root.extended_key_usage().unwrap().is_none());
    for cert in [&issuer, &leaf] {
        let eku = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth && !eku.any && !eku.client_auth && eku.other.is_empty());
        assert!(!eku.code_signing && !eku.email_protection && !eku.ocsp_signing);
    }

    // Name constraints: critical, the same list in both CA certificates, none in the leaf.
    let expected = [
        GeneralName::DNSName("localhost"),
        GeneralName::DNSName("test"),
        GeneralName::DNSName("internal"),
        GeneralName::DNSName("home.arpa"),
        GeneralName::IPAddress(&[127, 0, 0, 0, 255, 0, 0, 0]),
        GeneralName::IPAddress(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255,
        ]),
    ];
    for cert in [&root, &issuer] {
        let nc = cert.name_constraints().unwrap().unwrap();
        assert!(nc.critical);
        let permitted: Vec<_> = nc
            .value
            .permitted_subtrees
            .iter()
            .flatten()
            .map(|s| s.base.clone())
            .collect();
        assert_eq!(permitted, expected);
        assert!(nc.value.excluded_subtrees.is_none());
    }
    assert!(leaf.name_constraints().unwrap().is_none());

    // Subject alternative names: none, none, every requested name.
    assert!(root.subject_alternative_name().unwrap().is_none());
    assert!(issuer.subject_alternative_name().unwrap().is_none());
    let alt_names = leaf
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .clone();
    assert_eq!(
        alt_names,
        [
            GeneralName::DNSName("app.test"),
            GeneralName::DNSName("*.app.test"),
            GeneralName::IPAddress(&[127, 0, 0, 1]),
            GeneralName::IPAddress(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ]
    );
}

#[test]
fn an_empty_ip_list_is_written_as_an_excluded_subtree_and_read_back() {
    let constraints =
        Constraints::new(vec![DnsName::parse("corp.example").unwrap()], Vec::new()).unwrap();
    let ca = Ca::create(constraints.clone(), OffsetDateTime::now_utc()).unwrap();
    let root_der = ders(ca.root_pem()).remove(0);
    let root = parse(&root_der);
    let nc = root.name_constraints().unwrap().unwrap().value;
    let excluded: Vec<_> = nc
        .excluded_subtrees
        .iter()
        .flatten()
        .map(|s| s.base.clone())
        .collect();
    assert_eq!(
        excluded,
        [
            GeneralName::IPAddress(&[0; 8]),
            GeneralName::IPAddress(&[0; 32])
        ]
    );
    let loaded = Ca::from_pem(ca.root_pem(), ca.issuer_pem(), &ca.issuer_key_pem()).unwrap();
    assert_eq!(loaded.constraints(), &constraints);
}

#[test]
fn the_root_key_is_never_stored() {
    let tmp = TempDir::new();
    let ca = Ca::create(Constraints::local(), OffsetDateTime::now_utc()).unwrap();
    let dir = CaDir::create(tmp.path().join("ca"), &ca).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(files, [ISSUER_KEY_FILE, ISSUER_FILE, ROOT_FILE]);
    assert!(!ca.root_pem().contains("PRIVATE KEY"));

    // The one key on disk belongs to the intermediate, not to the root.
    let key =
        KeyPair::from_pem(&std::fs::read_to_string(dir.path().join(ISSUER_KEY_FILE)).unwrap())
            .unwrap();
    let root_der = ders(ca.root_pem()).remove(0);
    let issuer_der = ders(ca.issuer_pem()).remove(0);
    let spki = |der| parse(der).public_key().subject_public_key.data.to_vec();
    assert_eq!(spki(&issuer_der), key.public_key_raw());
    assert_ne!(spki(&root_der), key.public_key_raw());
}

#[test]
fn a_key_that_does_not_belong_to_the_issuer_is_refused() {
    let now = OffsetDateTime::now_utc();
    let a = Ca::create(Constraints::local(), now).unwrap();
    let b = Ca::create(Constraints::local(), now).unwrap();
    assert!(Ca::from_pem(a.root_pem(), a.issuer_pem(), &b.issuer_key_pem()).is_err());
}

/// `openssl verify`'s verdict, or `None` when openssl cannot be run.
fn openssl_accepts(dir: &std::path::Path, ca: &Ca, leaf: &Leaf) -> Option<Result<bool, String>> {
    let leaf_only = leaf.chain_pem().strip_suffix(ca.issuer_pem()).unwrap();
    let path = dir.join("leaf.pem");
    std::fs::write(&path, leaf_only).unwrap();
    let output = Command::new("openssl")
        .args(["verify", "-purpose", "sslserver", "-CAfile"])
        .arg(dir.join(ROOT_FILE))
        .arg("-untrusted")
        .arg(dir.join(ISSUER_FILE))
        .arg(&path)
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some(if output.status.success() {
        Ok(true)
    } else if text.contains("subtree violation") {
        Ok(false)
    } else {
        Err(text)
    })
}

#[test]
fn openssl_agrees_with_permits_on_every_table_name() {
    let tmp = TempDir::new();
    let ca = Ca::create(Constraints::local(), OffsetDateTime::now_utc()).unwrap();
    let dir = CaDir::create(tmp.path().join("ca"), &ca).unwrap();
    // OpenSSL only. macOS ships LibreSSL as `openssl`, a different verifier
    // that the M2 consumer probe covers on its own; when neither is there,
    // the webpki cross-check above still runs.
    let is_openssl = Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|out| out.status.success() && out.stdout.starts_with(b"OpenSSL "));
    if !is_openssl {
        return;
    }
    let mut verifier = |leaf: &Leaf| openssl_accepts(dir.path(), &ca, leaf).unwrap();
    let mut wrong = disagreements(&ca, &table_inputs(), &mut verifier);
    // A leaf with several names, and one with only an address, must verify too.
    for list in [
        &["app.test", "localhost", "127.0.0.1", "::1", "*.app.test"][..],
        &["127.0.0.1"],
    ] {
        let leaf = ca
            .issue(&names(list), LeafDays::default(), OffsetDateTime::now_utc())
            .unwrap();
        if openssl_accepts(dir.path(), &ca, &leaf) != Some(Ok(true)) {
            wrong.push(format!("{list:?} was not accepted"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
