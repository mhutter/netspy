use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
    usize,
};

use clap::{App, Arg};
use etherparse::{InternetSlice, SlicedPacket};
use pcap::{Capture, Device, Packet};

#[macro_use]
extern crate clap;

type Row = HashMap<String, usize>;
type DB = Vec<Row>;

fn main() {
    let app = App::new("netspy")
        .author("Manuel Hutter (https://github.com/mhutter/netspy)")
        .version(crate_version!())
        .about("Display real time traffic stats")
        .arg(
            Arg::with_name("window")
                .short("w")
                .value_name("SECS")
                .help("observed time window in seconds")
                .takes_value(true)
                .default_value("10"),
        )
        .arg(
            Arg::with_name("interface")
                .short("i")
                .value_name("IFACE")
                .help("Interface to use, defaults to the 'default' interface")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("query")
                .multiple(true)
                .last(true)
                .value_name("QUERY")
                .help(
                    "Optional filter query in BPF syntax (see http://biot.com/capstats/bpf.html)",
                ),
        )
        .get_matches();

    let window = value_t!(app, "window", usize).unwrap();

    let device = match app.value_of("interface") {
        Some(iface) => find_device(iface),
        None => Device::lookup().unwrap(),
    };

    println!("Listening on: {:?}", device);

    let program = app
        .values_of("query")
        .map(|vals| vals.collect::<Vec<_>>())
        .unwrap_or_default()
        .join(" ");

    let mut capture = Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    capture.filter(&program).unwrap();
    let mut data: DB = vec![Row::new(); window];
    let mut last_index = get_index(window.into());

    while let Ok(packet) = capture.next() {
        let addr = get_addr(packet);
        let index = get_index(window.into());

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

    match packet.ip.unwrap() {
        InternetSlice::Ipv4(ip) => ip.source_addr().to_string(),
        InternetSlice::Ipv6(ip, _) => ip.source_addr().to_string(),
    }
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
