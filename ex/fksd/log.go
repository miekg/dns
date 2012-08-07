package main

import "log"

const NAME = "fksd: "

func logPrintf(format string, a ...interface{}) {
	if *l {
		log.Printf(NAME + format, a...)
	}
}
