//go:build ignore
// +build ignore

// types_generate.go is meant to run with go generate. It will use
// go/{importer,types} to track down all the RR struct types. Then for each type
// it will generate conversion tables (TypeToRR and TypeToString) and banal
// methods (len, Header, copy) based on the struct tags. The generated source is
// written to ztypes.go, and is meant to be checked into git.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/types"
	"log"
	"os"
	"strings"
	"text/template"

	"golang.org/x/tools/go/packages"
)

var skipLen = map[string]struct{}{
	"NSEC":  {},
	"NSEC3": {},
	"OPT":   {},
	"CSYNC": {},
}

var packageHdr = `
// Code generated by "go run types_generate.go"; DO NOT EDIT.

package dns

import (
	"encoding/base64"
	"net"
)

`

var TypeToRR = template.Must(template.New("TypeToRR").Parse(`
// TypeToRR is a map of constructors for each RR type.
var TypeToRR = map[uint16]func() RR{
{{range .}}{{if ne . "RFC3597"}}  Type{{.}}:  func() RR { return new({{.}}) },
{{end}}{{end}}                    }

`))

var typeToString = template.Must(template.New("typeToString").Parse(`
// TypeToString is a map of strings for each RR type.
var TypeToString = map[uint16]string{
{{range .}}{{if ne . "NSAPPTR"}}  Type{{.}}: "{{.}}",
{{end}}{{end}}                    TypeNSAPPTR:    "NSAP-PTR",
}

`))

var headerFunc = template.Must(template.New("headerFunc").Parse(`
{{range .}}  func (rr *{{.}}) Header() *RR_Header { return &rr.Hdr }
{{end}}

`))

// getTypeStruct will take a type and the package scope, and return the
// (innermost) struct if the type is considered a RR type (currently defined as
// those structs beginning with a RR_Header, could be redefined as implementing
// the RR interface). The bool return value indicates if embedded structs were
// resolved.
func getTypeStruct(t types.Type, scope *types.Scope) (*types.Struct, bool) {
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return nil, false
	}
	if st.NumFields() == 0 {
		return nil, false
	}
	if st.Field(0).Type() == scope.Lookup("RR_Header").Type() {
		return st, false
	}
	if st.Field(0).Anonymous() {
		st, _ := getTypeStruct(st.Field(0).Type(), scope)
		return st, true
	}
	return nil, false
}

// loadModule retrieves package description for a given module.
func loadModule(name string) (*types.Package, error) {
	conf := packages.Config{Mode: packages.NeedTypes | packages.NeedTypesInfo}
	pkgs, err := packages.Load(&conf, name)
	if err != nil {
		return nil, err
	}
	return pkgs[0].Types, nil
}

func main() {
	// Import and type-check the package
	pkg, err := loadModule("github.com/miekg/dns")
	fatalIfErr(err)
	scope := pkg.Scope()

	// Collect constants like TypeX
	var numberedTypes []string
	for _, name := range scope.Names() {
		o := scope.Lookup(name)
		if o == nil || !o.Exported() {
			continue
		}
		b, ok := o.Type().(*types.Basic)
		if !ok || b.Kind() != types.Uint16 {
			continue
		}
		if !strings.HasPrefix(o.Name(), "Type") {
			continue
		}
		name := strings.TrimPrefix(o.Name(), "Type")
		if name == "PrivateRR" {
			continue
		}
		numberedTypes = append(numberedTypes, name)
	}

	// Collect actual types (*X)
	var namedTypes []string
	for _, name := range scope.Names() {
		o := scope.Lookup(name)
		if o == nil || !o.Exported() {
			continue
		}
		if st, _ := getTypeStruct(o.Type(), scope); st == nil {
			continue
		}
		if name == "PrivateRR" {
			continue
		}

		// Check if corresponding TypeX exists
		if scope.Lookup("Type"+o.Name()) == nil && o.Name() != "RFC3597" {
			log.Fatalf("Constant Type%s does not exist.", o.Name())
		}

		namedTypes = append(namedTypes, o.Name())
	}

	b := &bytes.Buffer{}
	b.WriteString(packageHdr)

	// Generate TypeToRR
	fatalIfErr(TypeToRR.Execute(b, namedTypes))

	// Generate typeToString
	fatalIfErr(typeToString.Execute(b, numberedTypes))

	// Generate headerFunc
	fatalIfErr(headerFunc.Execute(b, namedTypes))

	// Generate len()
	fmt.Fprint(b, "// len() functions\n")
	for _, name := range namedTypes {
		if _, ok := skipLen[name]; ok {
			continue
		}
		o := scope.Lookup(name)
		st, isEmbedded := getTypeStruct(o.Type(), scope)
		if isEmbedded {
			continue
		}
		fmt.Fprintf(b, "func (rr *%s) len(off int, compression map[string]struct{}) int {\n", name)
		fmt.Fprintf(b, "l := rr.Hdr.len(off, compression)\n")
		for i := 1; i < st.NumFields(); i++ {
			o := func(s string) { fmt.Fprintf(b, s, st.Field(i).Name()) }

			if _, ok := st.Field(i).Type().(*types.Slice); ok {
				switch st.Tag(i) {
				case `dns:"-"`:
					// ignored
				case `dns:"cdomain-name"`:
					o("for _, x := range rr.%s { l += domainNameLen(x, off+l, compression, true) }\n")
				case `dns:"domain-name"`:
					o("for _, x := range rr.%s { l += domainNameLen(x, off+l, compression, false) }\n")
				case `dns:"txt"`:
					o("for _, x := range rr.%s { l += len(x) + 1 }\n")
				case `dns:"apl"`:
					o("for _, x := range rr.%s { l += x.len() }\n")
				case `dns:"pairs"`:
					o("for _, x := range rr.%s { l += 4 + int(x.len()) }\n")
				default:
					log.Fatalln(name, st.Field(i).Name(), st.Tag(i))
				}
				continue
			}

			switch {
			case st.Tag(i) == `dns:"-"`:
				// ignored
			case st.Tag(i) == `dns:"cdomain-name"`:
				o("l += domainNameLen(rr.%s, off+l, compression, true)\n")
			case st.Tag(i) == `dns:"domain-name"`:
				o("l += domainNameLen(rr.%s, off+l, compression, false)\n")
			case st.Tag(i) == `dns:"octet"`:
				o("l += len(rr.%s)\n")
			case strings.HasPrefix(st.Tag(i), `dns:"size-base64`):
				fallthrough
			case st.Tag(i) == `dns:"base64"`:
				o("l += base64.StdEncoding.DecodedLen(len(rr.%s))\n")
			case strings.HasPrefix(st.Tag(i), `dns:"size-hex:`): // this has an extra field where the length is stored
				o("l += len(rr.%s)/2\n")
			case st.Tag(i) == `dns:"hex"`:
				o("l += len(rr.%s)/2\n")
			case st.Tag(i) == `dns:"any"`:
				o("l += len(rr.%s)\n")
			case st.Tag(i) == `dns:"a"`:
				o("if len(rr.%s) != 0 { l += net.IPv4len }\n")
			case st.Tag(i) == `dns:"aaaa"`:
				o("if len(rr.%s) != 0 { l += net.IPv6len }\n")
			case st.Tag(i) == `dns:"txt"`:
				o("for _, t := range rr.%s { l += len(t) + 1 }\n")
			case st.Tag(i) == `dns:"uint48"`:
				o("l += 6 // %s\n")
			case st.Tag(i) == `dns:"ipsechost"`:
				o(`switch rr.GatewayType {
				case IPSECGatewayIPv4:
					l += net.IPv4len
				case IPSECGatewayIPv6:
					l += net.IPv6len
				case IPSECGatewayHost:
					l += len(rr.%s) + 1
				}
				`)
			case st.Tag(i) == `dns:"amtrelayhost"`:
				o(`switch rr.GatewayType {
				case AMTRELAYIPv4:
					l += net.IPv4len
				case AMTRELAYIPv6:
					l += net.IPv6len
				case AMTRELAYHost:
					l += len(rr.%s) + 1
				}
				`)
			case st.Tag(i) == `dns:"amtrelaytype"`:
				o("l++ // %s\n")
			case st.Tag(i) == "":
				switch st.Field(i).Type().(*types.Basic).Kind() {
				case types.Uint8:
					o("l++ // %s\n")
				case types.Uint16:
					o("l += 2 // %s\n")
				case types.Uint32:
					o("l += 4 // %s\n")
				case types.Uint64:
					o("l += 8 // %s\n")
				case types.String:
					o("l += len(rr.%s) + 1\n")
				default:
					log.Fatalln(name, st.Field(i).Name())
				}
			default:
				log.Fatalln(name, st.Field(i).Name(), st.Tag(i))
			}
		}
		fmt.Fprint(b, "return l }\n\n")
	}

	// Generate copy()
	fmt.Fprint(b, "// copy() functions\n")
	for _, name := range namedTypes {
		o := scope.Lookup(name)
		st, isEmbedded := getTypeStruct(o.Type(), scope)
		fmt.Fprintf(b, "func (rr *%s) copy() RR {\n", name)
		fields := make([]string, 0, st.NumFields())
		if isEmbedded {
			a, _ := o.Type().Underlying().(*types.Struct)
			parent := a.Field(0).Name()
			fields = append(fields, "*rr."+parent+".copy().(*"+parent+")")
			goto WriteCopy
		}
		fields = append(fields, "rr.Hdr")
		for i := 1; i < st.NumFields(); i++ {
			f := st.Field(i).Name()
			if sl, ok := st.Field(i).Type().(*types.Slice); ok {
				t := sl.Underlying().String()
				t = strings.TrimPrefix(t, "[]")
				if strings.Contains(t, ".") {
					splits := strings.Split(t, ".")
					t = splits[len(splits)-1]
				}
				// For the EDNS0 interface (used in the OPT RR), we need to call the copy method on each element.
				if t == "EDNS0" {
					fmt.Fprintf(b, "%s := make([]%s, len(rr.%s));\nfor i,e := range rr.%s {\n %s[i] = e.copy()\n}\n",
						f, t, f, f, f)
					fields = append(fields, f)
					continue
				}
				if t == "APLPrefix" {
					fmt.Fprintf(b, "%s := make([]%s, len(rr.%s));\nfor i,e := range rr.%s {\n %s[i] = e.copy()\n}\n",
						f, t, f, f, f)
					fields = append(fields, f)
					continue
				}
				if t == "SVCBKeyValue" {
					fmt.Fprintf(b, "%s := make([]%s, len(rr.%s));\nfor i,e := range rr.%s {\n %s[i] = e.copy()\n}\n",
						f, t, f, f, f)
					fields = append(fields, f)
					continue
				}
				fmt.Fprintf(b, "%s := make([]%s, len(rr.%s)); copy(%s, rr.%s)\n",
					f, t, f, f, f)
				fields = append(fields, f)
				continue
			}
			if st.Field(i).Type().String() == "net.IP" {
				fields = append(fields, "copyIP(rr."+f+")")
				continue
			}
			fields = append(fields, "rr."+f)
		}
	WriteCopy:
		fmt.Fprintf(b, "return &%s{%s}\n", name, strings.Join(fields, ","))
		fmt.Fprint(b, "}\n\n")
	}

	// gofmt
	res, err := format.Source(b.Bytes())
	if err != nil {
		b.WriteTo(os.Stderr)
		log.Fatal(err)
	}

	// write result
	f, err := os.Create("ztypes.go")
	fatalIfErr(err)
	defer f.Close()
	f.Write(res)
}

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
