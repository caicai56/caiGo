package cmd

import (
	"github.com/urfave/cli"
	"xia_sql/util"
)

// ./main --iplist ip_list --port port_list --mode syn  --timeout 2 --concurrency 10
var Scan = cli.Command{
	Name:   "scan",
	Usage:  "start to scan sql",
	Action: util.Scan,
	Flags: []cli.Flag{
		stringFlag("url, u", "", "single url"),
		stringFlag("file, r", "", "multiple urls"),
		stringFlag("whitelist,w", "", "add whitelist"),
		stringFlag("mode,m", "", "scan mode"),
		stringFlag("payloads,p", "", "add payload"),
	},
}

func stringFlag(name, value, usage string) cli.StringFlag {
	return cli.StringFlag{
		Name:  name,
		Value: value,
		Usage: usage,
	}
}
