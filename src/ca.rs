//! Builds the root, the intermediate (the issuer) and leaf certificates, and
//! reads them back. Takes and returns bytes; no I/O.
//!
//! The root key lives only inside [`Ca::create`]: it signs the intermediate and
//! is dropped. See ADR 0002.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256, SanType, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::Error;
use crate::names::{Constraints, DnsName, IpNet, SubjectName, permits};

/// Lifetime of the root and the intermediate: five years of 365 days plus
/// one leap day.
const CA_DAYS: i64 = 5 * 365 + 1;

/// How long a leaf certificate is valid, in days: 1 to 825, 365 by default.
/// The upper bound is Apple's limit for TLS server certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafDays(u16);

impl LeafDays {
    /// The longest validity homecert issues.
    pub const MAX: u16 = 825;

    /// Checks the range.
    ///
    /// # Errors
    ///
    /// [`Error::LeafDays`] if `days` is 0 or more than [`LeafDays::MAX`].
    pub fn new(days: u16) -> Result<Self, Error> {
        if (1..=Self::MAX).contains(&days) {
            Ok(Self(days))
        } else {
            Err(Error::LeafDays(days))
        }
    }

    /// The number of days.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

impl Default for LeafDays {
    fn default() -> Self {
        Self(365)
    }
}

/// A certificate authority as it exists on disk: the root certificate (no
/// key), the intermediate, the intermediate's key, and the constraints read
/// from the root.
pub struct Ca {
    root_pem: String,
    issuer_pem: String,
    issuer_key: KeyPair,
    issuer_not_after: OffsetDateTime,
    constraints: Constraints,
}

impl fmt::Debug for Ca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ca")
            .field("constraints", &self.constraints)
            .field("issuer_key", &"[elided]")
            .finish_non_exhaustive()
    }
}

/// A leaf certificate and its key, ready to be written.
pub struct Leaf {
    chain_pem: String,
    key_pem: String,
}

impl fmt::Debug for Leaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leaf")
            .field("key_pem", &"[elided]")
            .finish_non_exhaustive()
    }
}

impl Leaf {
    /// The leaf certificate followed by the intermediate, in PEM, like a
    /// `fullchain.pem`.
    #[must_use]
    pub fn chain_pem(&self) -> &str {
        &self.chain_pem
    }

    /// The leaf's private key in PKCS #8 PEM.
    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }
}

impl Ca {
    /// Creates a new root and intermediate, both carrying `constraints`. The
    /// root key is generated here, signs the intermediate and is dropped
    /// before this function returns; it is never serialised.
    ///
    /// # Errors
    ///
    /// [`Error::Certificate`] if rcgen fails, [`Error::Random`] if the system
    /// random source fails.
    pub fn create(constraints: Constraints, now: OffsetDateTime) -> Result<Self, Error> {
        let date = format!(
            "{:04}-{:02}-{:02}",
            now.year(),
            u8::from(now.month()),
            now.day()
        );
        let not_after = now + Duration::days(CA_DAYS);

        let root_params = ca_params(
            format!("homecert root {date} {}", random_hex()?),
            now,
            not_after,
            &constraints,
            1,
        );
        let root = CertifiedIssuer::self_signed(root_params, new_key()?)?;

        let mut issuer_params = ca_params(
            format!("homecert issuer {date} {}", random_hex()?),
            now,
            not_after,
            &constraints,
            0,
        );
        issuer_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let issuer_key = new_key()?;
        let issuer_cert = issuer_params.signed_by(&issuer_key, &root)?;
        let root_pem = root.pem();
        // The root key ends here.
        drop(root);

        Ok(Self {
            root_pem,
            issuer_pem: issuer_cert.pem(),
            issuer_key,
            issuer_not_after: not_after,
            constraints,
        })
    }

    /// Reads a CA back from its three PEM files. The constraints come from the
    /// root certificate itself.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] if a file cannot be read as the certificate or key it
    /// should hold, if the key does not belong to the intermediate, or if the
    /// intermediate does not chain to the root: its issuer is not the root's
    /// subject, the root's key did not sign it, or its name constraints are
    /// not the root's.
    pub fn from_pem(root_pem: &str, issuer_pem: &str, issuer_key_pem: &str) -> Result<Self, Error> {
        let issuer_key =
            KeyPair::from_pem(issuer_key_pem).map_err(|_| Error::Parse("issuer key"))?;
        let issuer_der = pem_der(issuer_pem, "issuer certificate")?;
        let issuer = parse_cert(&issuer_der, "issuer certificate")?;
        if issuer.public_key().subject_public_key.data.as_ref() != issuer_key.public_key_raw() {
            return Err(Error::Parse(
                "issuer key does not match the issuer certificate",
            ));
        }
        let root_der = pem_der(root_pem, "root certificate")?;
        let root = parse_cert(&root_der, "root certificate")?;
        if issuer.issuer().as_raw() != root.subject().as_raw() {
            return Err(Error::Parse(
                "issuer certificate was not issued by the root",
            ));
        }
        // homecert only makes P-256 keys and ECDSA with SHA-256 signatures.
        UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_ASN1,
            root.public_key().subject_public_key.data.as_ref(),
        )
        .verify(
            issuer.tbs_certificate.as_ref(),
            issuer.signature_value.data.as_ref(),
        )
        .map_err(|_| Error::Parse("issuer certificate was not signed by the root key"))?;
        let constraints = constraints_of(&root)?;
        if constraints_of(&issuer)? != constraints {
            return Err(Error::Parse(
                "issuer name constraints differ from the root's",
            ));
        }
        Ok(Self {
            root_pem: root_pem.to_owned(),
            issuer_pem: issuer_pem.to_owned(),
            issuer_key,
            issuer_not_after: issuer.validity().not_after.to_datetime(),
            constraints,
        })
    }

    /// The root certificate in PEM.
    #[must_use]
    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }

    /// The intermediate certificate in PEM.
    #[must_use]
    pub fn issuer_pem(&self) -> &str {
        &self.issuer_pem
    }

    /// The intermediate's private key in PKCS #8 PEM.
    #[must_use]
    pub fn issuer_key_pem(&self) -> String {
        self.issuer_key.serialize_pem()
    }

    /// The names this CA may sign for.
    #[must_use]
    pub fn constraints(&self) -> &Constraints {
        &self.constraints
    }

    /// Issues a leaf for `names`, valid from `now` for `days`, but never
    /// past the intermediate's own end. Every name is checked with
    /// [`permits`] first.
    ///
    /// # Errors
    ///
    /// [`Error::NoNames`] for an empty list, [`Error::Refused`] for the first
    /// name outside the constraints, [`Error::Certificate`] if signing fails.
    pub fn issue(
        &self,
        names: &[SubjectName],
        days: LeafDays,
        now: OffsetDateTime,
    ) -> Result<Leaf, Error> {
        if let Some(name) = names.iter().find(|name| !permits(&self.constraints, name)) {
            return Err(Error::Refused(name.clone()));
        }
        self.sign_leaf(names, days, now)
    }

    /// [`Ca::issue`] without the [`permits`] check, so tests can ask a second
    /// verifier about names homecert would refuse.
    #[cfg(test)]
    pub(crate) fn issue_unchecked(
        &self,
        names: &[SubjectName],
        days: LeafDays,
        now: OffsetDateTime,
    ) -> Result<Leaf, Error> {
        self.sign_leaf(names, days, now)
    }

    fn sign_leaf(
        &self,
        names: &[SubjectName],
        days: LeafDays,
        now: OffsetDateTime,
    ) -> Result<Leaf, Error> {
        if names.is_empty() {
            return Err(Error::NoNames);
        }
        let mut params = CertificateParams::default();
        params.serial_number = Some(random_serial()?);
        params.not_before = now;
        params.not_after = (now + Duration::days(i64::from(days.get()))).min(self.issuer_not_after);
        params.distinguished_name = leaf_subject(names);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.subject_alt_names = names
            .iter()
            .map(|name| match name {
                SubjectName::Ip(ip) => Ok(SanType::IpAddress(*ip)),
                other => Ok(SanType::DnsName(other.to_string().try_into()?)),
            })
            .collect::<Result<_, rcgen::Error>>()?;

        let issuer = Issuer::from_ca_cert_pem(&self.issuer_pem, &self.issuer_key)?;
        let key = new_key()?;
        let leaf = params.signed_by(&key, &issuer)?;
        Ok(Leaf {
            chain_pem: format!("{}{}", leaf.pem(), self.issuer_pem),
            key_pem: key.serialize_pem(),
        })
    }
}

/// The leaf subject: the first DNS name as CN. A request with only IP
/// addresses gets no CN, because OpenSSL checks a CN that looks like a host
/// name, such as `127.0.0.1`, against the DNS constraints when the leaf has
/// no DNS name in its SAN, and rejects the leaf.
fn leaf_subject(names: &[SubjectName]) -> DistinguishedName {
    let mut subject = DistinguishedName::new();
    match names
        .iter()
        .find(|name| !matches!(name, SubjectName::Ip(_)))
    {
        Some(name) => subject.push(DnType::CommonName, name.to_string()),
        None => subject.push(DnType::OrganizationName, "homecert"),
    }
    subject
}

fn ca_params(
    common_name: String,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    constraints: &Constraints,
    path_len: u8,
) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(name_constraints(constraints));
    params.use_authority_key_identifier_extension = path_len == 0;
    params
}

/// The nameConstraints value. Permitted subtrees only restrict names of their
/// own type, so with no IP range every address would pass; an empty IP list
/// therefore becomes an excluded subtree covering all IPv4 and IPv6
/// addresses.
fn name_constraints(constraints: &Constraints) -> NameConstraints {
    let mut permitted: Vec<GeneralSubtree> = constraints
        .dns()
        .iter()
        .map(|name| GeneralSubtree::DnsName(name.as_str().to_owned()))
        .collect();
    permitted.extend(constraints.ip().iter().map(|net| {
        GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(net.addr(), net.prefix()))
    }));
    let excluded_subtrees = if constraints.ip().is_empty() {
        vec![
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([0; 4], 0)),
            GeneralSubtree::IpAddress(CidrSubnet::from_v6_prefix([0; 16], 0)),
        ]
    } else {
        Vec::new()
    };
    NameConstraints {
        permitted_subtrees: permitted,
        excluded_subtrees,
    }
}

/// Reads the constraints back from a certificate: the inverse of
/// [`name_constraints`].
fn constraints_of(cert: &X509Certificate<'_>) -> Result<Constraints, Error> {
    let unsupported = Error::Parse("root name constraints are not ones homecert writes");
    let nc = cert
        .name_constraints()
        .map_err(|_| Error::Parse("root name constraints"))?
        .ok_or(Error::Parse("root has no name constraints"))?
        .value;
    let mut dns = Vec::new();
    let mut ip = Vec::new();
    for subtree in nc.permitted_subtrees.iter().flatten() {
        match subtree.base {
            GeneralName::DNSName(name) => {
                dns.push(DnsName::parse(name).map_err(|_| Error::Parse("root DNS constraint"))?);
            }
            GeneralName::IPAddress(bytes) => {
                ip.push(ip_net(bytes).ok_or(Error::Parse("root IP constraint"))?);
            }
            _ => return Err(unsupported),
        }
    }
    let excluded: Vec<_> = nc
        .excluded_subtrees
        .iter()
        .flatten()
        .map(|s| &s.base)
        .collect();
    let all_ip = [
        GeneralName::IPAddress(&[0; 8]),
        GeneralName::IPAddress(&[0; 32]),
    ];
    // Exactly the IPv4 and the IPv6 exclusion, as `name_constraints` writes
    // them: a doubled 0.0.0.0/0 would leave every IPv6 address open.
    let excluded_ok =
        excluded.is_empty() || (ip.is_empty() && excluded == [&all_ip[0], &all_ip[1]]);
    if !excluded_ok {
        return Err(unsupported);
    }
    Constraints::new(dns, ip).map_err(|_| unsupported)
}

/// An address and mask, 8 or 32 bytes, as a range. `None` for any other
/// length or a mask that is not a prefix.
fn ip_net(bytes: &[u8]) -> Option<IpNet> {
    let (addr, mask) = bytes.split_at(bytes.len() / 2);
    let (addr, ones, bits) = match (<[u8; 4]>::try_from(addr), <[u8; 16]>::try_from(addr)) {
        (Ok(v4), _) => {
            let mask = u32::from_be_bytes(mask.try_into().ok()?);
            (
                IpAddr::V4(Ipv4Addr::from(v4)),
                mask.leading_ones(),
                mask.count_ones(),
            )
        }
        (_, Ok(v6)) => {
            let mask = u128::from_be_bytes(mask.try_into().ok()?);
            (
                IpAddr::V6(Ipv6Addr::from(v6)),
                mask.leading_ones(),
                mask.count_ones(),
            )
        }
        _ => return None,
    };
    if ones != bits {
        return None;
    }
    IpNet::new(addr, u8::try_from(ones).ok()?).ok()
}

fn new_key() -> Result<KeyPair, Error> {
    Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)
}

/// Four random hex digits, so two roots made on the same day have different
/// names.
fn random_hex() -> Result<String, Error> {
    let mut bytes = [0u8; 2];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Random)?;
    Ok(format!("{:02x}{:02x}", bytes[0], bytes[1]))
}

/// A random positive serial number: 16 bytes from the system random source,
/// with the top bit cleared so the number is positive and the next bit set so
/// it always takes all 16 bytes. That leaves 126 random bits; the CA/Browser
/// Forum asks for at least 64. Without it rcgen derives the serial from a
/// hash of the public key.
fn random_serial() -> Result<SerialNumber, Error> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Random)?;
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&bytes))
}

/// The DER of the first certificate in a PEM string.
fn pem_der(pem: &str, what: &'static str) -> Result<Vec<u8>, Error> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| Error::Parse(what))?;
    Ok(pem.contents)
}

fn parse_cert<'a>(der: &'a [u8], what: &'static str) -> Result<X509Certificate<'a>, Error> {
    X509Certificate::from_der(der)
        .map(|(_, cert)| cert)
        .map_err(|_| Error::Parse(what))
}

#[cfg(test)]
mod tests;
