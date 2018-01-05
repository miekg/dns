package dns

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type bindHarnessInfo struct {
	port       int
	hmacKeys   map[string]string
	dnssecKeys map[uint8]string
}

var bindHarness *bindHarnessInfo

func bindHaveExecutables() bool {
	bindExecutables := []string{"named", "dnssec-keygen", "dnssec-signzone"}
	for _, b := range bindExecutables {
		if _, err := exec.LookPath(b); err != nil {
			return false
		}
	}
	return true
}

func bindGenerateDnssecKeys(tempdir string) map[uint8]string {
	keys := map[uint8]string{}
	baseArgs := []string{"-q", "-K", tempdir, "-A", "-30s", "-n", "ZONE", "-T", "DNSKEY", "-f", "KSK"}
	for alg := range AlgorithmToString {
		args := append(baseArgs, "-a", fmt.Sprintf("%d", alg))
		switch alg {
		case DH, DSANSEC3SHA1, RSASHA1NSEC3SHA1, INDIRECT, PRIVATEDNS, PRIVATEOID:
			continue
		case DSA, RSAMD5, RSASHA1, RSASHA256, RSASHA512:
			args = append(args, "-b")
			args = append(args, "1024")
		}
		args = append(args, "example")
		cmd := exec.Command("dnssec-keygen", args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			switch alg {
			// TODO: remove when more generally available
			case ED448, ED25519:
			default:
				log.Printf(`dnssec-keygen failed: %s"
args: %s
stderr:
%s`, err, strings.Join(args, " "), stderr.String())
			}
		} else {
			keys[alg] = strings.TrimSpace(stdout.String())
		}
	}
	return keys
}

func bindGenerateHmacKeys(tempdir string) map[string]string {
	keys := map[string]string{}
	specs := map[string]string{
		"hmac-sha1":   "160",
		"hmac-sha256": "256",
		"hmac-sha512": "512",
	}
	baseArgs := []string{"-q", "-K", tempdir, "-A", "-30s", "-n", "HOST", "-T", "KEY", "-a"}
	for alg, bits := range specs {
		name := fmt.Sprintf("%s.example", alg)
		args := append(baseArgs, alg, "-b", bits, name)
		cmd := exec.Command("dnssec-keygen", args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			log.Printf(`dnssec-keygen failed: %s"
args: %s
stderr:
%s`, err, strings.Join(args, " "), stderr.String())
		} else {
			filename := filepath.Join(tempdir, strings.TrimSpace(stdout.String())+".key")
			contents, err := ioutil.ReadFile(filename)
			if err != nil {
				panic(err)
			}
			fields := strings.Split(string(contents), " ")
			secret := strings.TrimSpace(fields[len(fields)-1])
			keys[alg] = secret
		}
	}
	return keys
}

func bindBuildZone(tempdir string, dnssecKeys map[uint8]string, hmacKeys map[string]string) (string, error) {
	zonefilePath := filepath.Join(tempdir, "example.db")
	signedzonefilePath := zonefilePath + ".signed"
	zonefile, err := os.Create(zonefilePath)
	if err != nil {
		return "", err
	}
	_, err = zonefile.WriteString(`
$TTL 60
@ SOA mname rname 10 20 30 40 50
    NS localhost
localhost A 127.0.0.1
    `)
	if err != nil {
		return "", err
	}
	for _, k := range dnssecKeys {
		_, err = zonefile.WriteString(fmt.Sprintf("\n$INCLUDE %s.key\n", filepath.Join(tempdir, k)))
		if err != nil {
			return "", err
		}
	}
	if err = zonefile.Close(); err != nil {
		return "", err
	}
	signArgs := []string{"-z", "-S", "-N", "keep", "-o", "example", "-K", tempdir, "-d", tempdir, "-f", signedzonefilePath, zonefilePath}
	cmd := exec.Command("dnssec-signzone", signArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return signedzonefilePath, nil
}

func bindStart(tempdir string) (*os.Process, chan struct{}, error) {
	dnssecKeys := bindGenerateDnssecKeys(tempdir)
	hmacKeys := bindGenerateHmacKeys(tempdir)
	zonefile, err := bindBuildZone(tempdir, dnssecKeys, hmacKeys)
	if err != nil {
		return nil, nil, err
	}
	conffilePath := filepath.Join(tempdir, "bind.conf")
	conffile, err := os.Create(conffilePath)
	if err != nil {
		return nil, nil, err
	}
	var updatePolicy, hmacKeyStatements string
	for alg, secret := range hmacKeys {
		updatePolicy += fmt.Sprintf(`grant "%s.example." selfwild any;`, alg)
		hmacKeyStatements += fmt.Sprintf(`key %s.example. { algorithm %s; secret "%s"; };
`, alg, alg, secret)
	}
	_, err = conffile.WriteString(fmt.Sprintf(`
controls { };
options {
    allow-query-cache { none; };
    allow-query { any; };
    allow-transfer { any; };
    notify no;
    recursion no;
    listen-on { 127.0.0.1; };
};
zone "example." {
    type master;
    file "%s";
    allow-transfer { any; };
    update-policy { %s };
};
%s
`, zonefile, updatePolicy, hmacKeyStatements))
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command("named", "-p", "55033", "-g", "-c", conffilePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		log.Printf("bind stderr:\n%s", stderr.String())
		return nil, nil, err
	}
	ch := make(chan struct{})
	go func() {
		_, err := cmd.Process.Wait()
		if _, open := <-ch; !open {
			return
		}
		if err != nil {
			panic(err)
		}
		log.Fatalf("bind exited unexpectedly:\n%s", stderr.String())
	}()
	bindHarness = new(bindHarnessInfo)
	bindHarness.port = 55033
	bindHarness.hmacKeys = hmacKeys
	bindHarness.dnssecKeys = dnssecKeys
	// TODO: BIND doesn't start quick enough, should test liveness with TCP
	time.Sleep(100 * time.Millisecond)
	return cmd.Process, ch, nil
}

func TestMain(m *testing.M) {
	if !bindHaveExecutables() {
		os.Exit(m.Run())
	}
	tempfrag := fmt.Sprintf("miekg-dns-bind-%d", os.Getpid())
	tempdir := filepath.Join(os.TempDir(), tempfrag)
	if err := os.Mkdir(tempdir, 0755); err != nil {
		panic(err)
	}
	bindprocess, ch, err := bindStart(tempdir)
	if err != nil {
		log.Printf("failed to start bind: %s", err)
	}
	code := m.Run()
	close(ch)
	if bindprocess != nil {
		if err = bindprocess.Kill(); err != nil {
			log.Printf("failed to kill bind: %s", err)
		}
	}
	if err := os.RemoveAll(tempdir); err != nil {
		fmt.Printf("failed to remove tempdir: %s", err)
	}
	os.Exit(code)
}
