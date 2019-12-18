//+build ignore

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
	"go/importer"
	"go/types"
	"log"
	"os"
)

var packageHdr = `
// Code generated by "go run duplicate_generate.go"; DO NOT EDIT.

package dns

`

func getTypeStruct(t types.Type, scope *types.Scope) (*types.Struct, bool) {
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
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

func main() {
	// Import and type-check the package
	pkg, err := importer.Default().Import("github.com/miekg/dns")
	fatalIfErr(err)
	scope := pkg.Scope()

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

		if name == "PrivateRR" || name == "OPT" {
			continue
		}

		namedTypes = append(namedTypes, o.Name())
	}

	b := &bytes.Buffer{}
	b.WriteString(packageHdr)

	// Generate the duplicate check for each type.
	fmt.Fprint(b, "// isDuplicate() functions\n\n")
	for _, name := range namedTypes {

		o := scope.Lookup(name)
		st, isEmbedded := getTypeStruct(o.Type(), scope)
		if isEmbedded {
			continue
		}
		fmt.Fprintf(b, "func (r1 *%s) isDuplicate(_r2 RR) bool {\n", name)
		fmt.Fprintf(b, "r2, ok := _r2.(*%s)\n", name)
		fmt.Fprint(b, "if !ok { return false }\n")
		fmt.Fprint(b, "_ = r2\n")
		for i := 1; i < st.NumFields(); i++ {
			field := st.Field(i).Name()
			o2 := func(s string) { fmt.Fprintf(b, s+"\n", field, field) }
			o3 := func(s string) { fmt.Fprintf(b, s+"\n", field, field, field) }

			// For some reason, a and aaaa don't pop up as *types.Slice here (mostly like because the are
			// *indirectly* defined as a slice in the net package).
			if _, ok := st.Field(i).Type().(*types.Slice); ok {
				o2("if len(r1.%s) != len(r2.%s) {\nreturn false\n}")

				if st.Tag(i) == `dns:"cdomain-name"` || st.Tag(i) == `dns:"domain-name"` {
					o3(`for i := 0; i < len(r1.%s); i++ {
						if !isDuplicateName(r1.%s[i], r2.%s[i]) {
							return false
						}
					}`)

					continue
				}

				if st.Tag(i) == `dns:"apl"` {
					o3(`for i := 0; i < len(r1.%s); i++ {
						if r1.%s[i].Equals(&r2.%s[i]) {
							return false
						}
					}`)

					continue
				}

				o3(`for i := 0; i < len(r1.%s); i++ {
					if r1.%s[i] != r2.%s[i] {
						return false
					}
				}`)

				continue
			}

			switch st.Tag(i) {
			case `dns:"-"`:
				// ignored
			case `dns:"a"`, `dns:"aaaa"`:
				o2("if !r1.%s.Equal(r2.%s) {\nreturn false\n}")
			case `dns:"cdomain-name"`, `dns:"domain-name"`:
				o2("if !isDuplicateName(r1.%s, r2.%s) {\nreturn false\n}")
			default:
				o2("if r1.%s != r2.%s {\nreturn false\n}")
			}
		}
		fmt.Fprintf(b, "return true\n}\n\n")
	}

	// gofmt
	res, err := format.Source(b.Bytes())
	if err != nil {
		b.WriteTo(os.Stderr)
		log.Fatal(err)
	}

	// write result
	f, err := os.Create("zduplicate.go")
	fatalIfErr(err)
	defer f.Close()
	f.Write(res)
}

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
