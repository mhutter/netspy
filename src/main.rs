#[macro_use]
extern crate clap;

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
    usize,
};

use etherparse::{InternetSlice, SlicedPacket};
use pcap::{Capture, Device, Packet};

mod app;

type Row = HashMap<String, usize>;
type DB = Vec<Row>;

fn main() {
    let app = app::usage();

    let device = match app.interface {
        Some(iface) => find_device(iface.as_str()),
        None => Device::lookup().unwrap(),
    };

    println!("Listening on: {:?}", device.name);

    let mut capture = Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    capture.filter(&app.filter).unwrap();
    let mut data: DB = vec![Row::new(); app.window];
    let mut last_index = get_index(app.window.into());

    while let Ok(packet) = capture.next() {
        let addr = get_addr(packet);
        // Skip non-IP packages that don't have an address
        if addr.is_empty() {
            continue;
        }
        let index = get_index(app.window.into());

        // If we moved on to a new timeframe, reset existing data
        if index != last_index {
            data[index] = Row::new();
        }

        let row = data.get_mut(index).unwrap();
        let v = (*row).entry(addr).or_insert(0);
        *v += 1;

        print_data(&data);

        last_index = index;
    }
}

fn find_device(name: &str) -> Device {
    Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == name)
        .expect("Could not find device")
}

fn get_index(window: usize) -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        % window
}

fn get_addr(packet: Packet) -> String {
    let packet = SlicedPacket::from_ethernet(packet.data).unwrap();

    packet
        .ip
        .map(|ip| match ip {
            InternetSlice::Ipv4(ip) => ip.source_addr().to_string(),
            InternetSlice::Ipv6(ip, _) => ip.source_addr().to_string(),
        })
        .unwrap_or_default()
}

fn print_data(data: &DB) {
    let mut counters = Row::new();
    for row in data {
        for (addr, count) in row {
            let v = counters.entry(addr.clone()).or_insert(0);
            *v += count;
        }
    }

    let mut entries: Vec<_> = counters.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1));
    println!("----");
    for (addr, count) in entries {
        println!("{}\t{}", addr, count);
    }
}
