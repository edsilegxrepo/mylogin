package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/edsilegxrepo/myloginpath"
)

func main() {
	var database string
	flag.StringVar(&database, "database", "", "database name")
	flag.Parse()

	var sections []string
	if len(os.Args) <= 1 {
		sections = []string{mylogin.DefaultSection}
	} else {
		sections = os.Args[1:]
	}
	login, err := mylogin.ReadLogin(mylogin.DefaultFile(), sections)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	fmt.Println(login.DSN() + database)
}
