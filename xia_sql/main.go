package main

import (
	"github.com/urfave/cli"
	"os"
	"runtime"
	"xia_sql/cmd"
)

func main() {
	app := cli.NewApp()
	app.Name = "sql_scanner"
	app.Version = "2024-03-31"
	app.Usage = "Quick detection of SQL vulnerabilities"
	app.Commands = []cli.Command{cmd.Scan}
	app.Flags = append(app.Flags, cmd.Scan.Flags...)
	err := app.Run(os.Args)
	_ = err
}
func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
