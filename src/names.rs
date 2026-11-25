//! The name rules: parse and normalise DNS names and IP addresses, decide
//! whether a name is inside a constraint list, refuse unusable wildcards.
//!
//! Nothing here does I/O. [`permits`] is the one function that decides whether
//! a name may be issued.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why a name or address range was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameError {
    /// Not a DNS name or IP address homecert can put in a certificate.
    Malformed(String),
    /// A wildcard directly under a single label, such as `*.test`. Chrome and
    /// Firefox reject such certificates.
    WildcardTooBroad(String),
    /// Not an address range of the form `<address>/<prefix length>`.
    MalformedRange(String),
    /// A constraint list with no DNS name. Verifiers would then accept every
    /// DNS name, so homecert does not build one.
    NoDnsNames,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(input) => write!(f, "{input:?} is not a DNS name or IP address"),
            Self::WildcardTooBroad(input) => write!(
                f,
                "{input} is a wildcard directly under a top-level name; \
                 Chrome and Firefox reject such certificates, use a name like *.app.test"
            ),
            Self::MalformedRange(input) => {
                write!(f, "{input:?} is not an address range such as 127.0.0.0/8")
            }
            Self::NoDnsNames => f.write_str("a constraint list needs at least one DNS name"),
        }
    }
}

impl std::error::Error for NameError {}

/// A DNS name: lower case, no trailing dot, ASCII letters, digits and
/// hyphens only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName(String);

impl DnsName {
    /// Parses and normalises a DNS name. One trailing dot is removed and the
    /// name is lower-cased. Each label is 1 to 63 letters, digits and inner
    /// hyphens; the last label is not all digits; the whole name is at most
    /// 253 characters. Non-ASCII names are refused, so an internationalised
    /// name has to be given in its `xn--` form; such a label is accepted as
    /// letters, digits and hyphens and is not checked to be valid punycode.
    ///
    /// # Errors
    ///
    /// [`NameError::Malformed`] if the input breaks any of those rules.
    pub fn parse(input: &str) -> Result<Self, NameError> {
        let name = input
            .strip_suffix('.')
            .unwrap_or(input)
            .to_ascii_lowercase();
        let labels_ok = name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
        let last_is_numeric = name
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()));
        if name.len() > 253 || !labels_ok || last_is_numeric {
            return Err(NameError::Malformed(input.to_owned()));
        }
        Ok(Self(name))
    }

    /// The normalised name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this name equals `base` or is made from it by adding labels on
    /// the left. Labels are compared whole, so `xtest` is not within `test`.
    #[must_use]
    pub fn is_within(&self, base: &DnsName) -> bool {
        self.0 == base.0
            || self
                .0
                .strip_suffix(base.0.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A name a leaf certificate is issued for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubjectName {
    /// A DNS name, such as `app.test`.
    Dns(DnsName),
    /// A wildcard; the value is the name under the `*.`, so `*.app.test`
    /// holds `app.test`.
    Wildcard(DnsName),
    /// An IP address.
    Ip(IpAddr),
}

impl SubjectName {
    /// Parses a name as given on the command line: an IP address, a wildcard
    /// `*.<name>`, or a DNS name.
    ///
    /// # Errors
    ///
    /// [`NameError::Malformed`] if it is none of those, or a wildcard longer
    /// than 253 characters with its `*.`, and
    /// [`NameError::WildcardTooBroad`] for a wildcard directly under one label,
    /// such as `*.test`.
    pub fn parse(input: &str) -> Result<Self, NameError> {
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if let Some(base) = input.strip_prefix("*.") {
            let base = DnsName::parse(base)?;
            // The `*.` counts towards the 253 characters of the full name.
            if base.0.len() + 2 > 253 {
                return Err(NameError::Malformed(input.to_owned()));
            }
            if !base.0.contains('.') {
                return Err(NameError::WildcardTooBroad(input.to_owned()));
            }
            return Ok(Self::Wildcard(base));
        }
        DnsName::parse(input).map(Self::Dns)
    }
}

impl fmt::Display for SubjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => name.fmt(f),
            Self::Wildcard(base) => write!(f, "*.{base}"),
            Self::Ip(ip) => ip.fmt(f),
        }
    }
}

/// An IP address range: a network address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Makes a range. Host bits in `addr` are cleared, so `127.0.0.1/8`
    /// becomes `127.0.0.0/8`.
    ///
    /// # Errors
    ///
    /// [`NameError::MalformedRange`] if the prefix is longer than the address.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, NameError> {
        let addr = match addr {
            IpAddr::V4(v4) if prefix <= 32 => {
                IpAddr::V4(Ipv4Addr::from_bits(v4.to_bits() & mask_v4(prefix)))
            }
            IpAddr::V6(v6) if prefix <= 128 => {
                IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & mask_v6(prefix)))
            }
            _ => return Err(NameError::MalformedRange(format!("{addr}/{prefix}"))),
        };
        Ok(Self { addr, prefix })
    }

    /// Parses `<address>/<prefix length>`, such as `127.0.0.0/8` or `::1/128`.
    ///
    /// # Errors
    ///
    /// [`NameError::MalformedRange`] if the input is not of that form.
    pub fn parse(input: &str) -> Result<Self, NameError> {
        let malformed = || NameError::MalformedRange(input.to_owned());
        let (addr, prefix) = input.split_once('/').ok_or_else(malformed)?;
        let addr = addr.parse().map_err(|_| malformed())?;
        let prefix = prefix.parse().map_err(|_| malformed())?;
        Self::new(addr, prefix).map_err(|_| malformed())
    }

    /// The network address.
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits.
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is inside the range. An IPv4 address is never inside an
    /// IPv6 range and the other way round, so `::ffff:127.0.0.1` is not inside
    /// `127.0.0.0/8`.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                ip.to_bits() & mask_v4(self.prefix) == net.to_bits()
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                ip.to_bits() & mask_v6(self.prefix) == net.to_bits()
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask_v4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask_v6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

/// The names a root may sign for: DNS names, each with every name under it,
/// and IP ranges.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Constraints {
    dns: Vec<DnsName>,
    ip: Vec<IpNet>,
}

impl Constraints {
    /// Makes a constraint list. An empty `ip` list means no IP address may be
    /// issued.
    ///
    /// # Errors
    ///
    /// [`NameError::NoDnsNames`] if `dns` is empty.
    pub fn new(dns: Vec<DnsName>, ip: Vec<IpNet>) -> Result<Self, NameError> {
        if dns.is_empty() {
            return Err(NameError::NoDnsNames);
        }
        Ok(Self { dns, ip })
    }

    /// The default list: `localhost`, `test`, `internal`, `home.arpa`,
    /// `127.0.0.0/8` and `::1/128`.
    #[must_use]
    pub fn local() -> Self {
        let dns = ["localhost", "test", "internal", "home.arpa"]
            .into_iter()
            .map(|name| DnsName(name.to_owned()))
            .collect();
        let ip = vec![
            IpNet {
                addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                prefix: 8,
            },
            IpNet {
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                prefix: 128,
            },
        ];
        Self { dns, ip }
    }

    /// The DNS names.
    #[must_use]
    pub fn dns(&self) -> &[DnsName] {
        &self.dns
    }

    /// The IP ranges.
    #[must_use]
    pub fn ip(&self) -> &[IpNet] {
        &self.ip
    }
}

impl Default for Constraints {
    fn default() -> Self {
        Self::local()
    }
}

/// Whether `name` is inside `constraints`, following RFC 5280 section
/// 4.2.1.10: a DNS name must equal a constraint or end in `.` and the
/// constraint, a wildcard `*.a.test` is checked as `a.test`, and an IP address
/// must fall inside one of the ranges.
#[must_use]
pub fn permits(constraints: &Constraints, name: &SubjectName) -> bool {
    match name {
        SubjectName::Dns(name) | SubjectName::Wildcard(name) => {
            constraints.dns.iter().any(|base| name.is_within(base))
        }
        SubjectName::Ip(ip) => constraints.ip.iter().any(|net| net.contains(*ip)),
    }
}

/// The shared name table: every input with what [`permits`] must say about it
/// under [`Constraints::local`]. The `ca` tests issue each name and check
/// that rustls-webpki agrees.
#[cfg(test)]
pub(crate) mod table {
    /// What the table expects for one input.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Expect {
        /// Parses and is inside the default constraints.
        Permitted,
        /// Parses and is outside them.
        Refused,
        /// Does not parse.
        Invalid,
    }

    use Expect::{Invalid, Permitted, Refused};

    pub(crate) const CASES: &[(&str, Expect)] = &[
        // Exact matches and names under them.
        ("localhost", Permitted),
        ("test", Permitted),
        ("internal", Permitted),
        ("home.arpa", Permitted),
        ("app.test", Permitted),
        ("a.b.c.app.test", Permitted),
        ("api.localhost", Permitted),
        ("test-env.localhost", Permitted),
        ("db.internal", Permitted),
        ("router.home.arpa", Permitted),
        ("localhost.test", Permitted),
        ("127.0.0.1.test", Permitted),
        ("my-app.test", Permitted),
        ("a1.test", Permitted),
        ("x.test", Permitted),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test",
            Permitted,
        ),
        // Normalisation: case, one trailing dot, punycode.
        ("LOCALHOST", Permitted),
        ("App.Test.", Permitted),
        ("localhost.", Permitted),
        ("xn--bcher-kva.test", Permitted),
        // Wildcards one level or more below a constraint.
        ("*.app.test", Permitted),
        ("*.a.b.test", Permitted),
        ("*.app.localhost", Permitted),
        ("*.home.arpa", Permitted),
        ("*.db.internal", Permitted),
        ("*.app.test.", Permitted),
        // Label-boundary traps.
        ("xtest", Refused),
        ("apptest", Refused),
        ("notlocalhost", Refused),
        ("xhome.arpa", Refused),
        ("evil-home.arpa", Refused),
        ("test.evil", Refused),
        ("app.testing", Refused),
        ("test.com", Refused),
        ("localhost.evil.com", Refused),
        ("home.arpa.evil", Refused),
        ("127.0.0.1.nip.io", Refused),
        ("internal.example", Refused),
        ("arpa", Refused),
        ("local", Refused),
        ("localhos", Refused),
        ("example.com", Refused),
        ("WWW.EXAMPLE.COM", Refused),
        ("app.test.example", Refused),
        ("*.example.com", Refused),
        ("*.app.xtest", Refused),
        ("*.test.evil", Refused),
        // IPv4.
        ("127.0.0.1", Permitted),
        ("127.0.0.0", Permitted),
        ("127.1.2.3", Permitted),
        ("127.255.255.255", Permitted),
        ("128.0.0.1", Refused),
        ("126.255.255.255", Refused),
        ("1.0.0.127", Refused),
        ("10.0.0.5", Refused),
        ("192.168.1.1", Refused),
        ("0.0.0.0", Refused),
        ("255.255.255.255", Refused),
        // IPv6, including IPv4-mapped addresses.
        ("::1", Permitted),
        ("0:0:0:0:0:0:0:1", Permitted),
        ("::2", Refused),
        ("::", Refused),
        ("fe80::1", Refused),
        ("2001:db8::1", Refused),
        ("::ffff:127.0.0.1", Refused),
        ("::ffff:7f00:1", Refused),
        // Not names at all.
        ("*.test", Invalid),
        ("*.localhost", Invalid),
        ("*", Invalid),
        ("*app.test", Invalid),
        ("a.*.test", Invalid),
        ("", Invalid),
        (".test", Invalid),
        ("app..test", Invalid),
        ("app.test..", Invalid),
        ("-app.test", Invalid),
        ("app-.test", Invalid),
        ("app_name.test", Invalid),
        ("bücher.test", Invalid),
        ("app.123", Invalid),
        ("127.1", Invalid),
        ("[::1]", Invalid),
        ("app.test/", Invalid),
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test",
            Invalid,
        ),
    ];
}

#[cfg(test)]
mod tests {
    use super::table::{CASES, Expect};
    use super::*;

    #[test]
    fn every_table_case_gets_the_expected_verdict() {
        let constraints = Constraints::local();
        let mut wrong = Vec::new();
        for &(input, expect) in CASES {
            let got = match SubjectName::parse(input) {
                Ok(name) if permits(&constraints, &name) => Expect::Permitted,
                Ok(_) => Expect::Refused,
                Err(_) => Expect::Invalid,
            };
            if got != expect {
                wrong.push(format!("{input:?}: expected {expect:?}, got {got:?}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn the_table_has_at_least_sixty_names_that_reach_the_verifier() {
        let checked = CASES
            .iter()
            .filter(|(_, expect)| *expect != Expect::Invalid)
            .count();
        assert!(checked >= 60, "only {checked} cases");
    }

    #[test]
    fn names_are_normalised() {
        let name = SubjectName::parse("App.Test.").unwrap();
        assert_eq!(name.to_string(), "app.test");
        assert_eq!(
            SubjectName::parse("*.App.Test").unwrap().to_string(),
            "*.app.test"
        );
    }

    #[test]
    fn a_wildcard_under_one_label_is_refused_as_too_broad() {
        assert_eq!(
            SubjectName::parse("*.test"),
            Err(NameError::WildcardTooBroad("*.test".to_owned()))
        );
    }

    #[test]
    fn a_wildcard_counts_its_star_towards_253_characters() {
        // Three 63-character labels and one of `last`: 192 + `last` long.
        let base = |last: usize| {
            let full = ["a", "b", "c"].map(|c| c.repeat(63)).join(".");
            format!("{full}.{}", "d".repeat(last))
        };
        assert_eq!(base(59).len(), 251);
        let fits = format!("*.{}", base(59));
        assert_eq!(SubjectName::parse(&fits).unwrap().to_string(), fits);
        let too_long = format!("*.{}", base(60));
        assert!(DnsName::parse(&base(60)).is_ok());
        assert_eq!(
            SubjectName::parse(&too_long),
            Err(NameError::Malformed(too_long.clone()))
        );
    }

    #[test]
    fn host_bits_of_a_range_are_cleared() {
        let net = IpNet::parse("127.1.2.3/8").unwrap();
        assert_eq!(net.to_string(), "127.0.0.0/8");
        assert!(
            IpNet::parse("::/0")
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
        assert!(IpNet::parse("10.0.0.0/33").is_err());
        assert!(IpNet::parse("10.0.0.0").is_err());
    }

    #[test]
    fn an_empty_ip_list_permits_no_address() {
        let constraints =
            Constraints::new(vec![DnsName::parse("corp.example").unwrap()], Vec::new()).unwrap();
        assert!(!permits(
            &constraints,
            &SubjectName::parse("127.0.0.1").unwrap()
        ));
        assert!(permits(
            &constraints,
            &SubjectName::parse("a.corp.example").unwrap()
        ));
    }

    #[test]
    fn a_constraint_list_needs_a_dns_name() {
        assert_eq!(
            Constraints::new(Vec::new(), Vec::new()),
            Err(NameError::NoDnsNames)
        );
    }
}
