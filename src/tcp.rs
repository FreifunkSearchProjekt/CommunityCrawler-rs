use std::net::{IpAddr, Ipv4Addr};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::crawler::Crawler;
use ipnet::IpNet;
use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket};
use pnet_macros_support::packet::Packet;

pub struct PartialTCPPacketData<'a> {
    pub destination_ip: Ipv4Addr,
    pub iface_ip: Ipv4Addr,
    pub iface_name: &'a String,
    pub iface_src_mac: &'a MacAddr,
}

pub fn build_random_packet(
    partial_packet: &PartialTCPPacketData,
    tmp_packet: &mut [u8],
    destination_port: u16,
    src_port: u16,
) {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;

    // Setup Ethernet header
    {
        let mut eth_header =
            MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

        eth_header.set_destination(MacAddr::broadcast());
        eth_header.set_source(*partial_packet.iface_src_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    // Setup IP header
    {
        let mut ip_header = MutableIpv4Packet::new(
            &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
        )
        .unwrap();
        ip_header.set_header_length(69);
        ip_header.set_total_length(52);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(partial_packet.iface_ip);
        ip_header.set_destination(partial_packet.destination_ip);
        ip_header.set_identification(rand::random::<u16>());
        ip_header.set_ttl(64);
        ip_header.set_version(4);
        ip_header.set_flags(Ipv4Flags::DontFragment);

        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    // Setup TCP header
    {
        let mut tcp_header =
            MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..])
                .unwrap();

        println!(
            "Target IP: {}; SourcePort: {}",
            partial_packet.destination_ip, src_port
        );
        tcp_header.set_source(src_port);
        tcp_header.set_destination(destination_port);

        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(64240);
        tcp_header.set_data_offset(8);
        tcp_header.set_urgent_ptr(0);
        tcp_header.set_sequence(0);

        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);

        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &partial_packet.iface_ip,
            &partial_packet.destination_ip,
        );
        tcp_header.set_checksum(checksum);
    }
}

fn handle_icmp_packet(interface_name: String, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::DestinationUnreachable => {
                println!(
                    "[{}]: ICMP destination unreachable {} -> {}",
                    interface_name, source, destination
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

async fn handle_tcp_packet(
    interface_name: String,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    port: u16,
    src_port: u16,
    mut crawler: Crawler,
) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        if tcp.get_destination() != port {
            return;
        }
        if tcp.get_source() != src_port {
            return;
        }
        match tcp.get_flags() {
            2 => {
                println!(
                    "[{}]: TCP SYN Packet: {}:{} > {}:{}; length: {}; Flags: {}",
                    interface_name,
                    source,
                    tcp.get_source(),
                    destination,
                    tcp.get_destination(),
                    packet.len(),
                    tcp.get_flags()
                );
            }
            4 => {
                println!(
                    "[{}]: TCP RESET Packet: {}:{} > {}:{}; length: {}; Flags: {}",
                    interface_name,
                    source,
                    tcp.get_source(),
                    destination,
                    tcp.get_destination(),
                    packet.len(),
                    tcp.get_flags()
                );

                crawler.start(destination, tcp.get_destination()).await;
            }
            18 => {
                println!(
                    "[{}]: TCP SYN ACK Packet: {}:{} > {}:{}; length: {}; Flags: {}",
                    interface_name,
                    source,
                    tcp.get_source(),
                    destination,
                    tcp.get_destination(),
                    packet.len(),
                    tcp.get_flags()
                );
            }
            6 => {
                println!(
                    "[{}]: TCP SYN RESET Packet: {}:{} > {}:{}; length: {}; Flags: {}",
                    interface_name,
                    source,
                    tcp.get_source(),
                    destination,
                    tcp.get_destination(),
                    packet.len(),
                    tcp.get_flags()
                );
            }
            20 => {
                println!(
                    "[{}]: TCP ACK RESET Packet: {}:{} > {}:{}; length: {}; Flags: {}",
                    interface_name,
                    source,
                    tcp.get_source(),
                    destination,
                    tcp.get_destination(),
                    packet.len(),
                    tcp.get_flags()
                );
            }
            _ => {
                println!(
                    "[{}]: TCP Packet: {}:{} > {}:{}; length: {}; Flags: {}",
                    interface_name,
                    source,
                    tcp.get_source(),
                    destination,
                    tcp.get_destination(),
                    packet.len(),
                    tcp.get_flags()
                );
            }
        }
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_transport_protocol(
    destination_ip_net: IpNet,
    interface_name: String,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    port: u16,
    src_port: u16,
    crawler: Crawler,
) {
    if destination_ip_net.hosts().any(|x| x == source)
        || destination_ip_net.hosts().any(|x| x == destination)
    {
        match protocol {
            IpNextHeaderProtocols::Icmp => {
                handle_icmp_packet(interface_name, source, destination, packet)
            }
            IpNextHeaderProtocols::Tcp => {
                handle_tcp_packet(
                    interface_name,
                    source,
                    destination,
                    packet,
                    port,
                    src_port,
                    crawler,
                )
                .await
            }
            _ => {}
        }
    }
}

async fn handle_ipv4_packet(
    destination_ip_net: IpNet,
    interface_name: String,
    ethernet: &EthernetPacket<'_>,
    port: u16,
    src_port: u16,
    crawler: Crawler,
) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            destination_ip_net,
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            port,
            src_port,
            crawler,
        )
        .await;
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

async fn handle_ethernet_frame(
    destination_ip_net: IpNet,
    interface_name: String,
    ethernet: &EthernetPacket<'_>,
    port: u16,
    src_port: u16,
    crawler: Crawler,
) {
    if let EtherTypes::Ipv4 = ethernet.get_ethertype() {
        handle_ipv4_packet(
            destination_ip_net,
            interface_name,
            ethernet,
            port,
            src_port,
            crawler,
        )
        .await
    }
}

pub async fn send_tcp_packets(
    destination_ip_net: IpNet,
    interface_selected: String,
    count: u32,
    destination_port: u16,
) {
    let interfaces = pnet::datalink::interfaces();
    println!(
        "IP_NET: {:?}, Interface: {:?}",
        destination_ip_net, interface_selected
    );

    let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface_selected;
    let interface = interfaces
        .into_iter()
        .find(interfaces_name_match)
        .unwrap_or_else(|| panic!("could not find interface by name {}", interface_selected));

    let iface_ip = match interface
        .ips
        .get(0)
        .unwrap_or_else(|| panic!("the interface {} does not have any IP addresses", interface))
        .ip()
    {
        IpAddr::V4(ipv4) => ipv4,
        _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
    };

    let (mut tx, mut rx) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    let interface_name = interface.name.clone();
    let interface_mac = interface.mac.unwrap();
    let src_port = rand::random::<u16>();
    tokio::spawn(async move {
        for host in destination_ip_net.clone().hosts() {
            if host.is_ipv4() {
                match host {
                    IpAddr::V4(destination_ip) => {
                        let partial_packet: PartialTCPPacketData = PartialTCPPacketData {
                            destination_ip,
                            iface_ip,
                            iface_name: &(interface_name.clone()),
                            iface_src_mac: &interface_mac.clone(),
                        };

                        for i in 0..count {
                            println!("Sent {:?} packets to: {:?}", i + 1, destination_ip);

                            let error = tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                                build_random_packet(
                                    &partial_packet,
                                    packet,
                                    destination_port,
                                    src_port,
                                );
                            });

                            if let Some(result) = error {
                                if let Err(e) = result {
                                    panic!(e)
                                }
                            }
                        }
                    }
                    IpAddr::V6(_) => { /*NOOP*/ }
                }
            }
        }
    });
    println!("Waiting for responses...");
    let now = Instant::now();
    let crawler = Crawler::new();
    loop {
        let new_now = Instant::now();
        if new_now.duration_since(now) >= Duration::new(30, 0) {
            return;
        }
        match rx.next() {
            Ok(packet) => {
                handle_ethernet_frame(
                    destination_ip_net,
                    interface_selected.clone(),
                    &EthernetPacket::new(packet).unwrap(),
                    destination_port,
                    src_port,
                    crawler.clone(),
                )
                .await;
                sleep(Duration::new(0, 250_000_000));
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
