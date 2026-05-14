use std::{net::IpAddr, str::FromStr};

use axum::http::HeaderMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    pub fn from_request(
        peer_ip: IpAddr,
        headers: &HeaderMap,
        trusted_proxy_ips: &[IpAddr],
    ) -> Self {
        if !trusted_proxy_ips.contains(&peer_ip) {
            return Self(peer_ip);
        }

        first_ip_from_header(headers, "cf-connecting-ip")
            .or_else(|| first_ip_from_header(headers, "x-real-ip"))
            .or_else(|| first_forwarded_for_ip(headers))
            .map(Self)
            .unwrap_or(Self(peer_ip))
    }
}

fn first_ip_from_header(headers: &HeaderMap, header_name: &str) -> Option<IpAddr> {
    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| IpAddr::from_str(value.trim()).ok())
}

fn first_forwarded_for_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| IpAddr::from_str(value.trim()).ok())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use axum::http::{HeaderMap, HeaderValue};

    use super::ClientIp;

    #[test]
    fn prefers_cf_connecting_ip_when_peer_is_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.10"));
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.12, 127.0.0.1"),
        );

        let ip = ClientIp::from_request(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &headers,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );

        assert_eq!(ip.0.to_string(), "203.0.113.10");
    }

    #[test]
    fn falls_back_to_forwarded_for_when_peer_is_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.12, 127.0.0.1"),
        );

        let ip = ClientIp::from_request(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &headers,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );

        assert_eq!(ip.0.to_string(), "198.51.100.12");
    }

    #[test]
    fn ignores_forwarded_headers_when_peer_is_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.10"));

        let ip = ClientIp::from_request(
            "198.51.100.9".parse().expect("ip should parse"),
            &headers,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );

        assert_eq!(ip.0.to_string(), "198.51.100.9");
    }
}
