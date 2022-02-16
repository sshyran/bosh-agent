//go:build !windows
// +build !windows

package net

import (
	"fmt"
	"net"
	gonetURL "net/url"

	bosherr "github.com/cloudfoundry/bosh-utils/errors"

	"github.com/coreos/go-iptables/iptables"
)

// This is the integer value of the argument "0xb0540002", which is
// b054:0002 . The major number (the left-hand side) is "BOSH", leet-ified.
// The minor number (the right-hand side) is 2, indicating that this is the
// second thing in our "BOSH" classid namespace.
//
// _Hopefully_ noone uses a major number of "b054", and we avoid collisions _forever_!
// If you need to select new classids for firewall rules or traffic control rules, keep
// the major number "b054" for bosh stuff, unless there's a good reason to not.
//
// The net_cls.classid structure is described in more detail here:
// https://www.kernel.org/doc/Documentation/cgroup-v1/net_cls.txt
const NATS_ISOLATION_CLASS_ID = "2958295042"

func SetupNatsFirewall(mbus string) error {
	mbusURL, err := gonetURL.Parse(mbus)
	if err != nil || mbusURL.Hostname() == "" {
		return bosherr.WrapError(err, "Error parsing MbusURL")
	}

	host, port, err := net.SplitHostPort(mbusURL.Host)
	if err != nil {
		return bosherr.WrapError(err, "Error Getting Port")
	}
	fmt.Printf("%v:%v", host, port)
	ipt, err := iptables.New()
	if err != nil {
		return bosherr.WrapError(err, "Iptables Error:")
	}
	exists, err := ipt.Exists("mangle", "POSTROUTING",
		"-d", "127.0.0.1",
		"-p", "tcp",
		"--dport", "2822",
		"-m", "cgroup",
		"--cgroup", NATS_ISOLATION_CLASS_ID,
		"-j", "ACCEPT",
	)
	if err != nil {
		return bosherr.WrapError(err, "Iptables Error Checking for monit rule")
	}
	if !exists {
		err = ipt.Insert("mangle", "POSTROUTING", 1,
			"-d", "127.0.0.1",
			"-p", "tcp",
			"--dport", "2822",
			"-m", "cgroup",
			"--cgroup", NATS_ISOLATION_CLASS_ID,
			"-j", "ACCEPT",
		)
		if err != nil {
			return bosherr.WrapError(err, "Iptables Error Inersting for monit rule")
		}
	}
	err = ipt.AppendUnique("mangle", "POSTROUTING",
		"-d", host,
		"-p", "tcp",
		"--dport", port,
		"-m", "cgroup",
		"--cgroup", NATS_ISOLATION_CLASS_ID,
		"-j", "ACCEPT",
	)
	if err != nil {
		return bosherr.WrapError(err, "Iptables Error Inersting for agent ACCEPT rule")
	}
	err = ipt.AppendUnique("mangle", "POSTROUTING",
		"-d", host,
		"-p", "tcp",
		"--dport", port,
		"-j", "DROP",
	)
	if err != nil {
		return bosherr.WrapError(err, "Iptables Error Inersting for non-agent DROP rule")
	}
	return nil
}
