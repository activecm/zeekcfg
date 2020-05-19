package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
)

type (
	nodeInfo struct {
		Interfaces []string
		SocketType string
		Processes  uint16
		PinCPU     bool
	}

	interfaceInfo struct {
		Name      string
		Loopback  bool
		Up        bool
		HasIP     bool
		IPv4Addrs []string
		IPv6Addrs []string
	}
)

const (
	sockRaw      = "none"
	sockAfpacket = "af_packet"
	// sockPfring   = "pf_ring"
)

// nodeCmd represents the node command
var nodeCmd = &cobra.Command{
	Use:   "zeekcfg",
	Short: "Generates a node.cfg file for zeekctl",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: ctrl-c to quit
		var info nodeInfo
		var questions []*survey.Question

		info, questions = parseFlags(cmd)

		// if there are flags provided we'll use those and prompt for interfaces if needed
		// TODO: need a different method. --output is very useful for interactive but it won't prompt for everything if used
		// https://godoc.org/github.com/spf13/pflag#Flag can determine if it was changed
		if len(questions) == 0 && len(info.Interfaces) == 0 {
			// if user selected to auto-determine capture interfaces
			// but none were found we have to error
			return errors.New("unable to determine capture interface")
		} else if len(questions) != 0 {
			// ask the remainder of the questions
			err := survey.Ask(questions, &info)
			if err != nil {
				return err
			}
		}

		out := os.Stdout
		// if --output was specified write to that file instead
		if filepath, err := cmd.Flags().GetString("output"); err == nil && filepath != "" {
			var err error
			out, err = os.OpenFile(filepath, os.O_WRONLY|os.O_TRUNC, 0664)
			if err != nil {
				return fmt.Errorf("could not open file: %s", filepath)
			}
			defer out.Close()
		}

		fmt.Fprint(out, generateNodeCfg(info))

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := nodeCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

	// TODO: allow custom host value

	nodeCmd.Flags().Bool("auto", false, "Automatically determine the best settings rather than prompting.")

	nodeCmd.Flags().StringArrayP("interface", "i", []string{}, "Capture interface(s) to use. Specify multiple times for more than one interface.")
	// TODO: make this a string so they can specify auto and still prompt for interfaces
	nodeCmd.Flags().Uint16P("processes", "p", 0, "Max number of processes to use. Set to 0 to auto-determine based on the number of CPU cores.")
	nodeCmd.Flags().Bool("pin", false, "Pin worker processes to CPU cores.")
	nodeCmd.Flags().Bool("no-pin", false, "Do not pin worker processes to CPU cores. (default)")
	// TODO: add validation
	nodeCmd.Flags().StringP("type", "t", "raw", `Socket type to use. Must be "raw" or "afpacket".`)
	// nodeCmd.Flags().Bool("afpacket", false, "Configure to use AF_Packet.")
	// nodeCmd.Flags().Bool("pfring", false, "Configure to use PF_Ring.")

	nodeCmd.Flags().StringP("output", "o", "", "Path to write output file. (default: stdout)")
}

// returns a populated NodeInfo and remaining questions to be asked
func parseFlags(cmd *cobra.Command) (nodeInfo, []*survey.Question) {
	var questions []*survey.Question

	auto, _ := cmd.Flags().GetBool("auto")
	interfaces, _ := cmd.Flags().GetStringArray("interface")
	processes, _ := cmd.Flags().GetUint16("processes")
	pin, _ := cmd.Flags().GetBool("pin")
	nopin, _ := cmd.Flags().GetBool("no-pin")
	sockType, _ := cmd.Flags().GetString("type")
	// afpacket, _ := cmd.Flags().GetBool("afpacket")
	// pfring, _ := cmd.Flags().GetBool("pfring")

	info := nodeInfo{
		Interfaces: interfaces,
		Processes:  processes,
		PinCPU:     pin && !nopin,
		SocketType: sockRaw,
	}

	switch sockType {
	case "raw":
		info.SocketType = sockRaw
	case "afpacket":
		info.SocketType = sockAfpacket
	}

	if processes == 0 {
		info.Processes = suggestedProcesses()
	}

	// auto fill unspecified values
	if auto {
		if len(info.Interfaces) == 0 {
			info.Interfaces = suggestedInterfaces(gatherInterfaces())
		}
	} else {
		// write the survey for any non-specified questions
		if !cmd.Flag("interface").Changed {
			questions = append(questions, qInterfaces())
		}
		if !cmd.Flag("type").Changed {
			questions = append(questions, qSocketType())
		}
		if !cmd.Flag("processes").Changed {
			questions = append(questions, qProcesses())
		}
		if !pin && !nopin {
			questions = append(questions, qPinCPU())
		}
	}

	return info, questions
}

func qInterfaces() *survey.Question {
	interfaceMap := gatherInterfaces()
	suggested := suggestedInterfaces(interfaceMap)
	var displayNames sort.StringSlice
	var suggestedNames []string
	// construct the items to display in the multi-select
	// add additional information to each line to give context to the interfaces
	for name, info := range interfaceMap {
		state := "DOWN"
		if info.Up {
			state = "UP"
		}
		ipv4 := "-"
		if len(info.IPv4Addrs) > 0 {
			ipv4 = info.IPv4Addrs[0]
		}
		ipv6 := ""
		if len(info.IPv6Addrs) > 0 {
			ipv6 = info.IPv6Addrs[0]
		}

		displayName := fmt.Sprintf("%-17s %5s %15s  %s", name, state, ipv4, ipv6)
		displayNames = append(displayNames, displayName)
		if stringInSlice(name, suggested) {
			suggestedNames = append(suggestedNames, displayName)
		}
	}
	displayNames.Sort()

	return &survey.Question{
		Name: "interfaces",
		Prompt: &survey.MultiSelect{
			Message: "Choose your capture interface(s):",
			Help: `The interfaces you most likely want to use for capturing start 
		with "eth" or "en" (e.g. eth0, eno1, enp1s0, enx78e7d1ea46da). You will generally NOT 
		want to use loopback, bridged, or virtual interfaces (e.g. lo, br-c446eb08dde, veth582437d).
		If you choose to select interfaces belonging to the latter category, proceed at your own risk.`,
			Options:  displayNames,
			Default:  suggestedNames,
			PageSize: 20,
		},
		Validate: survey.Required,
		Transform: func(val interface{}) interface{} {
			answers, ok := val.([]survey.OptionAnswer)
			if ok {
				for i, answer := range answers {
					// the actual interface name is the first word
					answers[i].Value = strings.Split(answer.Value, " ")[0]
				}
			}
			return answers
		},
	}
}

func qProcesses() *survey.Question {
	return &survey.Question{
		Name: "processes",
		Prompt: &survey.Input{
			Message: "How many total Zeek processes do you want?",
			Help: `You will generally get the best performance by making your total number of Zeek processes
	one less than the number of CPU cores your system has. If your system is used for something
	in addition to Zeek you may want to reduce the number of processes further.`,
			Default: strconv.Itoa(int(suggestedProcesses())),
		},
		// Only numbers up to how many cores there are
		// Validate: func(val interface{}) error {
		// 	if str, ok := val.(string); ok {
		// 		if procs, err := strconv.Atoi(str); err == nil && procs >= 3 {
		// 			return nil
		// 		}
		// 	}
		// 	return errors.New("you must have at least 3 processeses")
		// },
	}
}

func qSocketType() *survey.Question {
	return &survey.Question{
		Name: "socketType",
		Prompt: &survey.Select{
			Message: "What type of network socket do you want to use?",
			Help: `Choosing a custom option here can help improve performance. However, you must have 
    the corresponding driver, kernel module or support, and zeek plugin to use it.`,
			Options: []string{sockRaw, sockAfpacket},
			Default: sockRaw,
		},
	}
}

func qPinCPU() *survey.Question {
	return &survey.Question{
		Name: "pinCPU",
		Prompt: &survey.Confirm{
			Message: "Would you like to pin Zeek worker processes to specific CPUs?",
			Help: `Pinning CPUs can improve capture performance. However, it is likely unnecessary unless you
    discover your capture bottlenecked by your CPU.`,
			Default: false,
		},
	}
}

// func qEthtool(interfaces, withIP []string) *survey.Question {
// 	// if any selected interface is configured with an IP address we shouldn't use ethtool
// 	suggestedEthtool := true

// 	for _, intf := range interfaces {
// 		if stringInSlice(intf, withIP) {
// 			suggestedEthtool = false
// 		}
// 	}

// 	return &survey.Question{
// 		Name: "ethtool",
// 		Prompt: &survey.Confirm{
// 			Message: "Do you wish to disable network device checksumming and offloading using ethtool?",
// 			Help: `Disabling hardware features improves capture performance. You should answer "no"
//     if any of your selected capture interfaces will have an IP address or be used for anything but sniffing traffic.`,
// 			Default: suggestedEthtool,
// 		},
// 	}
// 	// TODO: this needs to go in a separate file (zeekctl.cfg) or /etc/network/interfaces
// }

func gatherInterfaces() map[string]interfaceInfo {
	interfaces, _ := net.Interfaces()
	infos := make(map[string]interfaceInfo)

	for _, intf := range interfaces {
		name := intf.Name
		info := interfaceInfo{
			Loopback: (intf.Flags&net.FlagLoopback != 0),
			Up:       (intf.Flags&net.FlagUp != 0),
		}

		addrs, _ := intf.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil {
				info.IPv4Addrs = append(info.IPv4Addrs, ip.String())
				info.HasIP = true
			} else {
				info.IPv6Addrs = append(info.IPv6Addrs, ip.String())
				info.HasIP = true
			}
		}
		infos[name] = info
	}
	return infos
}

func stringInSlice(str string, slc []string) bool {
	for _, s := range slc {
		if str == s {
			return true
		}
	}
	return false
}

// number of total workers based on the total CPU cores available
func suggestedProcesses() uint16 {
	// suggest one process for every core save one for the kernel
	procs := uint16(runtime.NumCPU() - 1)
	if procs < 3 {
		procs = 3
	}
	return procs
}

// number of worker processes for each interface
func suggestedWorkers(totalProcesses, numInterfaces int) uint16 {
	if numInterfaces == 0 {
		return 0
	}

	// reserve processes for the manager and proxy
	reserved := 2

	// minimum of one worker per interface
	if (totalProcesses - reserved) < numInterfaces {
		return 1
	}

	return uint16((totalProcesses - reserved) / numInterfaces)
}

func suggestedInterfaces(interfaces map[string]interfaceInfo) []string {
	suggested := []string{}

	for name, info := range interfaces {
		if strings.HasPrefix(name, "br-") { // bridged
			continue
		}
		if strings.HasPrefix(name, "veth") { // virtual
			continue
		}
		if strings.HasPrefix(name, "virb") { // libvirt
			continue
		}
		if strings.HasPrefix(name, "docker") { // docker
			continue
		}
		if !info.Up { // inactive
			continue
		}
		if info.Loopback { // loopback
			continue
		}
		if info.HasIP { // interface with an IP
			continue
		}
		suggested = append(suggested, name)
	}

	return suggested
}

func generateNodeCfg(info nodeInfo) string {
	var cfg strings.Builder
	var currCPU int
	workers := suggestedWorkers(int(info.Processes), len(info.Interfaces))

	f := func(format string, a ...interface{}) {
		fmt.Fprintf(&cfg, format, a...)
	}
	l := func(format string) {
		fmt.Fprintln(&cfg, format)
	}

	l("[manager]")
	l("type=manager")
	l("host=localhost")
	l("")
	l("[proxy-1]")
	l("type=proxy")
	l("host=localhost")
	l("")

	for i, intf := range info.Interfaces {
		f("[worker-%s]\n", intf)
		l("type=worker")
		l("host=localhost")

		switch info.SocketType {
		case sockAfpacket:
			l("# See https://github.com/J-Gras/zeek-af_packet-plugin for plugin installation and further configuration")
			f("interface=af_packet::%s\n", intf)
			f("lb_procs=%d\n", workers)
			l("lb_method=custom")
			f("af_packet_fanout_id=%d\n", i)
			l("af_packet_fanout_mode=AF_Packet::FANOUT_HASH")
			l("af_packet_buffer_size=128*1024*1024")
		// case sockPfring:
		// 	l("# See https://github.com/ntop/bro-pf_ring for plugin installation")
		// 	l("# See https://github.com/ntop/bro-pf_ring for plugin installation")
		// 	f("interface=%s\n", intf)
		// 	l("lb_method=pf_ring")
		case sockRaw:
			f("interface=%s\n", intf)
		}

		if info.PinCPU {
			f("pin_cpus=")
			for i := uint16(0); i < workers; i++ {
				f(strconv.Itoa(currCPU))
				if i < workers-1 {
					f(",")
				}
				currCPU++
			}
			l("")
		}

		l("")
	}

	return cfg.String()
}
