package main

import "dns/strconv"
import "testing"
import __regexp__ "regexp"

var tests = []testing.InternalTest{
	{"strconv.TestConversion", strconv.TestConversion},
}
var benchmarks = []testing.InternalBenchmark{}

func main() {
	testing.Main(__regexp__.MatchString, tests)
	testing.RunBenchmarks(__regexp__.MatchString, benchmarks)
}
