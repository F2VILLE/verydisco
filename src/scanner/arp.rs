use pnet::datalink::NetworkInterface;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{Packet, MutablePacket};
use pnet::util::MacAddr;
use std::net::{Ipv4Addr};
use std::thread;
use std::time::Duration;

// A function to create and send ARP requests
fn send_arp_request(
    interface_name: &str,
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
) {
    // Find the network interface
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Failed to find the interface.");

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    // Create ARP packet
    let mut buffer = [0u8; 42]; // ARP packet is 42 bytes in total
    let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
    // Set the Ethernet header
    ethernet_packet.set_destination(MacAddr::broadcast()); // Broadcast MAC address
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();

    // Set the ARP header
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6); // MAC address length
    arp_packet.set_proto_addr_len(4); // IPv4 length
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero()); // Unknown at this point
    arp_packet.set_target_proto_addr(target_ip);

    // Send the ARP request
    tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();

    // Receive ARP responses
    let timeout = Duration::from_secs(1);
    thread::sleep(timeout);

    while let Ok(packet) = rx.next() {
        // Parse the packet and check if it's an ARP reply
        if let Some(ethernet) = EthernetPacket::new(packet) {
            if ethernet.get_ethertype() == EtherTypes::Arp {
                if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                    if arp.get_operation() == ArpOperations::Reply {
                        // Match the target IP and source MAC
                        println!(
                            "IP: {} -> MAC: {}",
                            arp.get_sender_proto_addr(),
                            arp.get_sender_hw_addr()
                        );
                    }
                }
            }
        }
    }
}

pub fn discover_devices(interface_name: &str, target_ip: Ipv4Addr, source_ip: Ipv4Addr, source_mac: MacAddr) {
    let interface_name = "eth0";

    for i in 1..=254 {
        let target_ip = Ipv4Addr::new(192, 168, 1, i);
        send_arp_request(interface_name, target_ip, source_ip, source_mac);
    }
}

pub fn list_interfaces() -> Vec<NetworkInterface> {
    let available_interfaces = datalink::interfaces().iter().filter(|iface| {
         !iface.ips.is_empty()
    }).cloned().collect();
    available_interfaces
}