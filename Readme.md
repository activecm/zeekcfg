Zeekcfg is a node.cfg file generator for zeekctl.

## Usage

You can run this in 3 different modes:
* Interactive mode - This is the default mode when you run it with no flags. The program will analyze your system and prompt you for different information, while suggesting sane defaults.
* Semi-interactive mode - If you already know some of the settings you want, instead of being prompted for that information you can specify them on the command line via flags. You will be prompted for any pieces of information you did not specify via flags.
* Automated mode - This mode will not prompt you for any information, relying either on what you provide via flags or by the default values based on your system. Trigger this mode with the `--auto` flag.

```
Usage:
  zeekcfg [flags]

Flags:
      --auto                    Automatically determine the best settings rather than prompting.
  -h, --help                    help for zeekcfg
  -i, --interface stringArray   Capture interface(s) to use. Specify multiple times for more than one interface.
      --no-pin                  Do not pin worker processes to CPU cores. (default)
  -o, --output string           Path to write output file. (default: stdout)
      --pin                     Pin worker processes to CPU cores.
  -p, --processes uint16        Max number of processes to use. Set to 0 to auto-determine based on the number of CPU cores.
  -t, --type string             Socket type to use. Must be "raw" or "afpacket". (default "raw")
```

### Examples

Interactive mode:
```bash
zeekcfg
# can also save output to a file
zeekcfg --output node.cfg
```

Semi-interactive mode:
```bash
# prompts for interfaces
zeekcfg --no-pin --processes 0 --type afpacket
```

Automated mode:
```bash
# accept all the default calculated values
zeekcfg --auto
# supply some custom values and accept defaults for the rest
zeekcfg --auto --interface eth1 --processes 4
# auto mode can be implied since all arguments are manually specified
zeekcfg --interface ens0 --interface ens1 --interface ens2 --processes 30 --pin --type afpacket
```

## Defaults Rationale

* Interfaces - Assumes that sniffing interfaces are in an UP state and do not have an IP address (neither v4 or v6). Additionally, interfaces matching common naming schemes (e.g. bridging, virtualization) are ignored by default.
* Processes - The best advice I've seen is to dedicate one CPU core for the kernel and the rest for Zeek processes, one process per core. This means that besides one core for the kernel, one for the Zeek manager, and one for the Zeek proxy, the remaining cores will be allocated as worker processes for each interface.
* Socket type - AF_Packet provides the best performance but requires you to have the appropriate [plugin](https://github.com/J-Gras/zeek-af_packet-plugin) installed to use. This it is safer to assume using regular raw sockets for the capture.
* Pin CPU - Pinning processes to certain CPU cores can improve performance, but can also degrade performance if over allocated. Therefore, we leave it disabled unless you know you need this.

## Further Tuning

* Critically important to performance is the hardware capabilities enabled/disabled on your network card. By default these are enabled because they are useful for normal netowrking behavior. However, if your capture interface(s) are dedicated for sniffing and do not have an IP address assigned then you can see a massive performance improvement by disabling these capabilities. Unfortunately, this needs to be done outside of the node.cfg file. It can be done with a Zeek [plugin](https://github.com/ncsa/bro-interface-setup) or is also commonly accomplished by adding a line like [this](https://github.com/Security-Onion-Solutions/securityonion-setup/blob/8a729d389338fbeb770a817b3b7c93fbb4dd4f72/bin/sosetup-network#L443) to your `/etc/network/interfaces` file.
* With dedicated capture interfaces you can also disable IPv6. I believe this can be disabled unconditionally since the inteface will be sniffing in promiscuous mode and Zeek should handle processing IPv6 packets. Similar to the previous point, this is commmonly done in the [`/etc/network/interfaces`](https://github.com/Security-Onion-Solutions/securityonion-setup/blob/8a729d389338fbeb770a817b3b7c93fbb4dd4f72/bin/sosetup-network#L444) file.
* The worker processes are split evenly between the interfaces. However, if the traffic each interface receives is not distributed evenly you will likely benefit from re-allocating the processes accordingly, giving more processes to the interfaces that receive the most traffic.
* You may need to adjust your interface's MTU settings if your network supports jumbo frames. The aforementioned Zeek [plugin](https://github.com/ncsa/bro-interface-setup) can handle this as well.
* The `af_packet_buffer_size=128*1024*1024` setting likely has some effect on performance, but I'm not sure in which cases it needs to be modified.
* This generator assumes a single system cluster configuration. If you need to capture using multiple Zeek worker sensors then you will likely need to manually change much of the generated config.

## TODO

- [ ] Generator command for networks file that uses ethtool and IPv6
- [ ] Allow using `lb_procs` with raw sockets (i.e. not with AF_Packet). [Example]](https://github.com/zeek/zeekctl/blob/master/testing/initialization/node-lb-interfaces.test).
- [ ] When to have more than one proxy node?

## Credits

- [Bill Stearns](https://github.com/william-stearns) for his initial [node.cfg generator script](https://github.com/activecm/bro-install/blob/master/gen-node-cfg.sh)
- [Doug Burks](https://github.com/dougburks) for the Security Onion configuration wizard inspiration and the performance tuning tweaks in `/etc/network/interfaces`
- [J-Gras](https://github.com/J-Gras) for the [zeek-af_packet-plugin](https://github.com/J-Gras/zeek-af_packet-plugin#usage-with-zeekctl) and zeekctl usage examples

