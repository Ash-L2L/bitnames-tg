/**
 * Utilities for interacting with Bitnames
*/

use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, str::FromStr};

use crypto::{sha2::Sha256, digest::Digest};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_with::{DisplayFromStr, hex::Hex as SerdeWithHex, serde_as};

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct BitnameInfo {
    #[serde_as(as = "Option<SerdeWithHex>")]
    commitment: Option<[u8; 32]>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    ip4_addr: Option<Ipv4Addr>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    ip6_addr: Option<Ipv6Addr>,
}

/** A record resolved via a BitName's IP address */
#[derive(Debug, Deserialize)]
pub struct WebRecord(JsonMap<String, JsonValue>);

impl BitnameInfo {
    fn ip_addr(&self) -> Option<IpAddr> {
        self.ip6_addr.map(IpAddr::from)
        .or_else(||self.ip4_addr.map(IpAddr::from))
    }
}

impl WebRecord {
    pub fn version_ok(&self) -> bool {
        match self.0.get("version") {
            Some(JsonValue::String(version_string)) =>
                version_string == "0.0.1", 
            Some(_) | None => false,
        }
    }

    /** canonicalize and compute the sha-256 digest as a commitment */
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let canonical_utf8 = serde_jcs::to_vec(&self.0).unwrap();
        hasher.input(&canonical_utf8);
        let mut res = [0u8; 32];
        hasher.result(&mut res);
        res
    }

    pub fn commitment_ok(&self, expected: &[u8; 32]) -> bool {
        self.commitment() == *expected
    }

    pub fn validate(&self, expected_commitment: Option<&[u8; 32]>)
        -> anyhow::Result<()> {
        if !self.version_ok() {
            anyhow::bail!("version number missing or unsupported")
        };
        if let Some(expected_commitment) = expected_commitment {
            if !self.commitment_ok(expected_commitment) {
                anyhow::bail!("commitment does not match expected commitment")
            };
        };
        Ok(())
    }

    /** query a telegram handle */
    pub fn telegram(&self) -> Option<&str> {
        self.0.get("telegram").and_then(JsonValue::as_str)
    }

    fn introductions(&self) -> Option<&JsonMap<String, JsonValue>> {
        self.0.get("introductions").and_then(JsonValue::as_object)
    }

    /** fee is resolved first from telegram-specific,
     * and then from non-specific platform fee */
    fn introductions_telegram_fee(&self) -> Option<Decimal> {
        self.introductions().and_then(|introductions| {
            introductions.get("telegram")
                .or_else(||introductions.get("fee"))
                .and_then(JsonValue::as_str)
                .and_then(|fee| Decimal::from_str(fee).ok())
        })
    }
}