use crate::tcp::send_tcp_packets;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};

mod config;
mod crawler;
mod tcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interfaces = pnet::datalink::interfaces();
    println!("List of Available Interfaces\n");

    for interface in interfaces.iter() {
        let iface_ip = interface.ips.iter().next().map(|x| match x.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
        });

        println!(
            "Interface name: {:?}\nInterface MAC: {:?}\nInterface IP: {:?}\n",
            &interface.name,
            &interface.mac.unwrap(),
            iface_ip
        )
    }

    // WARNING THIS IMPLEMENTATION CANNOT CRAWL THE OWN SERVER
    let ipnet: IpNet = "52.222.182.36/32".parse().unwrap();

    for interface in interfaces.iter() {
        if interface.ips.is_empty() {
            continue;
        }
        if interface.name == "lo" && ipnet.network() != Ipv4Addr::new(127, 0, 0, 1) {
            continue;
        }
        send_tcp_packets(ipnet, interface.name.clone(), 1, 443).await;
    }
    Ok(())
}
