package vars

import "sync"

var (
	ThreadNum    = 1000
	HashesMux    sync.Mutex
	Url          string
	WhiteSection []string
	Hashes       = make(map[string]struct{})
	UrlSection   []string
	Mode         = "get"
	Payloads     = []string{
		"%df'",
		"sleep(3)%23\n",
		"'and '1'='1",
		"’",
		"''",
		"-1",
		"0",
	}
)
