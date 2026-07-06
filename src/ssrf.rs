use std::net::{IpAddr, Ipv6Addr};
use tokio::net::lookup_host;

pub async fn is_host_safe(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_public_ip(ip);
    }

    match lookup_host((host, 0u16)).await {
        Ok(addrs) => {
            addrs.into_iter().all(|addr| is_public_ip(addr.ip()))
        }
        Err(_) => {
            false
        }
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || is_ipv6_unique_local(v6))
        }
    }
}

/// Проверяет, относится ли ip к fc00::/7 (Unique Local Addresses)
fn is_ipv6_unique_local(ip: Ipv6Addr) -> bool {
    let b = ip.octets();
    
    b[0] == 0xfc || b[0] == 0xfd
}