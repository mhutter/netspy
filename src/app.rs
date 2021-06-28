use clap::Arg;

pub struct App {
    pub window: usize,
    pub interface: Option<String>,
    pub filter: String,
}

const ABOUT: &'static str = "Display real time traffic stats.

This tool counts the number of packages matched against FILTER over a moving \
window of SECS seconds.

FILTER can be any vali BPF filter, but it's suggested to use at least 'ip'

Example:

    netspy -i enp0s3 -- ip dst host 10.0.2.15\
";

pub fn usage() -> App {
    let matches = clap::App::new("netspy")
        .author("Manuel Hutter (https://github.com/mhutter/netspy)")
        .version(crate_version!())
        .about("Display real time traffic stats")
        .long_about(ABOUT)
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
            Arg::with_name("filter")
                .multiple(true)
                .last(true)
                .value_name("FILTER")
                .help(
                    "Optional filter query in BPF syntax (see http://biot.com/capstats/bpf.html)",
                ),
        )
        .get_matches();

    let window = value_t!(matches, "window", usize).unwrap();
    let interface: Option<String> = matches.value_of("interface").map(str::to_string);
    let filter = match matches.values_of("filter") {
        Some(v) => v.collect::<Vec<_>>().join(" "),
        None => String::new(),
    };

    App {
        window,
        interface,
        filter,
    }
}
