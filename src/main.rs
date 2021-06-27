use std::collections::HashMap;

use etherparse::{InternetSlice, SlicedPacket};
use pcap::{Capture, Device};

fn main() {
    let device = Device::lookup().unwrap();
    println!("Device: {:?}", device);

    let mut capture = Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    capture.filter("ip dst host 10.0.2.15").unwrap();
    let mut data: HashMap<String, usize> = HashMap::new();

    while let Ok(packet) = capture.next() {
        let packet = SlicedPacket::from_ethernet(packet.data).unwrap();
        let addr = match packet.ip.unwrap() {
            InternetSlice::Ipv4(ip) => ip.source_addr().to_string(),
            InternetSlice::Ipv6(ip, _) => ip.source_addr().to_string(),
        };

        let v = data.entry(addr).or_insert(0);
        *v += 1;

        println!("----");
        for (addr, count) in &data {
            println!("{}\t{}", addr, count);
        }
    }
}
