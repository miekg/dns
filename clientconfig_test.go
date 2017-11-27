package dns

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const normal string = `
# Comment
domain somedomain.com
nameserver 10.28.10.2
nameserver 11.28.10.1
`

const missingNewline string = `
domain somedomain.com
nameserver 10.28.10.2
nameserver 11.28.10.1` // <- NOTE: NO newline.

func testConfig(t *testing.T, data string) {
	cc, err := ClientConfigFromReader(strings.NewReader(data))
	if err != nil {
		t.Errorf("error parsing resolv.conf: %v", err)
	}
	if l := len(cc.Servers); l != 2 {
		t.Errorf("incorrect number of nameservers detected: %d", l)
	}
	if l := len(cc.Search); l != 1 {
		t.Errorf("domain directive not parsed correctly: %v", cc.Search)
	} else {
		if cc.Search[0] != "somedomain.com" {
			t.Errorf("domain is unexpected: %v", cc.Search[0])
		}
	}
}

func TestNameserver(t *testing.T)          { testConfig(t, normal) }
func TestMissingFinalNewLine(t *testing.T) { testConfig(t, missingNewline) }

func testNdotsConfig(t *testing.T, data string, expectedNdots int) {
	cc, err := ClientConfigFromReader(strings.NewReader(data))
	if err != nil {
		t.Errorf("error parsing resolv.conf: %v", err)
	}
	if cc.Ndots != expectedNdots {
		t.Errorf("Ndots not properly parsed: (Expected: %d / Was: %d)", expectedNdots, cc.Ndots)
	}
}

func TestNdots(t *testing.T) {
	var ndotsVariants map[string]int = make(map[string]int)
	ndotsVariants["options ndots:0"] = 0
	ndotsVariants["options ndots:1"] = 1
	ndotsVariants["options ndots:15"] = 15
	ndotsVariants["options ndots:16"] = 15
	ndotsVariants["options ndots:-1"] = 0
	ndotsVariants[""] = 1

	for key := range ndotsVariants {
		testNdotsConfig(t, key, ndotsVariants[key])
	}

}

func TestReadFromFile(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("tempDir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "resolv.conf")
	if err := ioutil.WriteFile(path, []byte(normal), 0644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	cc, err := ClientConfigFromFile(path)
	if err != nil {
		t.Errorf("error parsing resolv.conf: %v", err)
	}
	if l := len(cc.Servers); l != 2 {
		t.Errorf("incorrect number of nameservers detected: %d", l)
	}
	if l := len(cc.Search); l != 1 {
		t.Errorf("domain directive not parsed correctly: %v", cc.Search)
	} else {
		if cc.Search[0] != "somedomain.com" {
			t.Errorf("domain is unexpected: %v", cc.Search[0])
		}
	}
}

func TestNameList_Ndots1(t *testing.T) {
	cfg := ClientConfig{
		Ndots: 1,
	}
	// fqdn should be only result returned
	names := cfg.NameList("miek.nl.")
	if len(names) != 1 {
		t.Errorf("NameList returned != 1 names: %v", names)
	} else if names[0] != "miek.nl." {
		t.Errorf("NameList didn't return sent fqdn domain: %v", names[0])
	}

	cfg.Search = []string{
		"test",
	}
	// Sent domain has NDots and search
	names = cfg.NameList("miek.nl")
	if len(names) != 2 {
		t.Errorf("NameList returned != 2 names: %v", names)
	} else if names[0] != "miek.nl." {
		t.Errorf("NameList didn't return sent domain first: %v", names[0])
	} else if names[1] != "miek.nl.test." {
		t.Errorf("NameList didn't return search last: %v", names[1])
	}
}
func TestNameList_Ndots2(t *testing.T) {
	cfg := ClientConfig{
		Ndots: 2,
	}

	// Sent domain has less than NDots and search
	cfg.Search = []string{
		"test",
	}
	names := cfg.NameList("miek.nl")

	if len(names) != 2 {
		t.Errorf("NameList returned != 2 names: %v", names)
	} else if names[0] != "miek.nl.test." {
		t.Errorf("NameList didn't return search first: %v", names[0])
	} else if names[1] != "miek.nl." {
		t.Errorf("NameList didn't return sent domain last: %v", names[1])
	}
}

func TestNameList_Ndots0(t *testing.T) {
	cfg := ClientConfig{
		Ndots: 0,
	}
	cfg.Search = []string{
		"test",
	}
	// Sent domain has less than NDots and search
	names := cfg.NameList("miek")
	if len(names) != 2 {
		t.Errorf("NameList returned != 2 names: %v", names)
	} else if names[0] != "miek." {
		t.Errorf("NameList didn't return search first: %v", names[0])
	} else if names[1] != "miek.test." {
		t.Errorf("NameList didn't return sent domain last: %v", names[1])
	}
}
