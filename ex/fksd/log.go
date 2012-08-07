package main

import "log"

const NAME = "fksd: "

func logPrintf(format string, a ...interface{}) {
	if *flaglog {
		log.Printf(NAME + format, a...)
	}
}
