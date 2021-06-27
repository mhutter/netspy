# netspy


## Development

Build dependencies:

* `libpcap-dev`

Since root permissions are required to run pcap filter, do this for testing:

```sh
cargo build && sudo ./target/debug/netspy
```

## License

MIT (see [LICENSE](LICENSE))