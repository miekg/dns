package dns

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"testing"
)

func TestParseZoneGenerate(t *testing.T) {
	zone := "$ORIGIN example.org.\n$GENERATE 10-12 foo${2,3,d} IN A 127.0.0.$"

	wantRRs := []RR{
		&A{Hdr: RR_Header{Name: "foo012.example.org."}, A: net.ParseIP("127.0.0.10")},
		&A{Hdr: RR_Header{Name: "foo013.example.org."}, A: net.ParseIP("127.0.0.11")},
		&A{Hdr: RR_Header{Name: "foo014.example.org."}, A: net.ParseIP("127.0.0.12")},
	}
	wantIdx := 0

	tok := ParseZone(strings.NewReader(zone), "", "")
	for x := range tok {
		if wantIdx >= len(wantRRs) {
			t.Fatalf("expected %d RRs, but got more", len(wantRRs))
		}
		if x.Error != nil {
			t.Fatalf("expected no error, but got %s", x.Error)
		}
		if got, want := x.RR.Header().Name, wantRRs[wantIdx].Header().Name; got != want {
			t.Fatalf("expected name %s, but got %s", want, got)
		}
		a, ok := x.RR.(*A)
		if !ok {
			t.Fatalf("expected *A RR, but got %T", x.RR)
		}
		if got, want := a.A, wantRRs[wantIdx].(*A).A; !got.Equal(want) {
			t.Fatalf("expected A with IP %v, but got %v", got, want)
		}
		wantIdx++
	}

	if wantIdx != len(wantRRs) {
		t.Errorf("too few records, expected %d, got %d", len(wantRRs), wantIdx)
	}
}

func TestParseZoneInclude(t *testing.T) {

	tmpfile, err := ioutil.TempFile("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zone := "$ORIGIN example.org.\n$INCLUDE " + tmpfile.Name() + "\nbar\tIN\tA\t127.0.0.2"

	var got int
	tok := ParseZone(strings.NewReader(zone), "", "")
	for x := range tok {
		if x.Error != nil {
			t.Fatalf("expected no error, but got %s", x.Error)
		}
		switch x.RR.Header().Name {
		case "foo.example.org.", "bar.example.org.":
		default:
			t.Fatalf("expected foo.example.org. or bar.example.org., but got %s", x.RR.Header().Name)
		}
		got++
	}

	if expected := 2; got != expected {
		t.Errorf("failed to parse zone after include, expected %d records, got %d", expected, got)
	}

	os.Remove(tmpfile.Name())

	tok = ParseZone(strings.NewReader(zone), "", "")
	for x := range tok {
		if x.Error == nil {
			t.Fatalf("expected first token to contain an error but it didn't")
		}
		if !strings.Contains(x.Error.Error(), "failed to open") ||
			!strings.Contains(x.Error.Error(), tmpfile.Name()) ||
			!strings.Contains(x.Error.Error(), "no such file or directory") {
			t.Fatalf(`expected error to contain: "failed to open", %q and "no such file or directory" but got: %s`,
				tmpfile.Name(), x.Error)
		}
	}
}

func TestZoneParserIncludeDisallowed(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zp := NewZoneParser(strings.NewReader("$INCLUDE "+tmpfile.Name()), "example.org.", "")

	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expect = "$INCLUDE directive not allowed"
	if err := zp.Err(); err == nil || !strings.Contains(err.Error(), expect) {
		t.Errorf("expected error to contain %q, got %v", expect, err)
	}
}

func TestZoneParserAddressAAAA(t *testing.T) {
	tests := []struct {
		record string
		want   *AAAA
	}{
		{
			record: "1.example.org. 600 IN AAAA ::1",
			want:   &AAAA{Hdr: RR_Header{Name: "1.example.org."}, AAAA: net.IPv6loopback},
		},
		{
			record: "2.example.org. 600 IN AAAA ::FFFF:127.0.0.1",
			want:   &AAAA{Hdr: RR_Header{Name: "2.example.org."}, AAAA: net.ParseIP("::FFFF:127.0.0.1")},
		},
	}

	for _, tc := range tests {
		got, err := NewRR(tc.record)
		if err != nil {
			t.Fatalf("expected no error, but got %s", err)
		}
		aaaa, ok := got.(*AAAA)
		if !ok {
			t.Fatalf("expected *AAAA RR, but got %T", aaaa)
		}
		if g, w := aaaa.AAAA, tc.want.AAAA; !g.Equal(w) {
			t.Fatalf("expected AAAA with IP %v, but got %v", g, w)
		}
	}
}

func TestZoneParserAddressBad(t *testing.T) {
	records := []string{
		"1.bad.example.org. 600 IN A ::1",
		"2.bad.example.org. 600 IN A ::FFFF:127.0.0.1",
		"3.bad.example.org. 600 IN AAAA 127.0.0.1",
	}

	for _, record := range records {
		const expect = "bad A"
		if got, err := NewRR(record); err == nil || !strings.Contains(err.Error(), expect) {
			t.Errorf("NewRR(%v) = %v, want err to contain %q", record, got, expect)
		}
	}
}

func TestParseTA(t *testing.T) {
	rr, err := NewRR(` Ta 0 0 0`)
	if err != nil {
		t.Fatalf("expected no error, but got %s", err)
	}
	if rr == nil {
		t.Fatal(`expected a normal RR, but got nil`)
	}
}

var errTestReadError = &Error{"test error"}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errTestReadError }

func TestParseZoneReadError(t *testing.T) {
	rr, err := ReadRR(errReader{}, "")
	if err == nil || !strings.Contains(err.Error(), errTestReadError.Error()) {
		t.Errorf("expected error to contain %q, but got %v", errTestReadError, err)
	}
	if rr != nil {
		t.Errorf("expected a nil RR, but got %v", rr)
	}
}

func TestUnexpectedNewline(t *testing.T) {
	zone := `
example.com. 60 PX
1000 TXT 1K
`
	zp := NewZoneParser(strings.NewReader(zone), "example.com.", "")
	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expect = `dns: unexpected newline: "\n" at line: 2:18`
	if err := zp.Err(); err == nil || err.Error() != expect {
		t.Errorf("expected error to contain %q, got %v", expect, err)
	}

	// Test that newlines inside braces still work.
	zone = `
example.com. 60 PX (
1000 TXT 1K )
`
	zp = NewZoneParser(strings.NewReader(zone), "example.com.", "")

	var count int
	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
		count++
	}

	if count != 1 {
		t.Errorf("expected 1 record, got %d", count)
	}

	if err := zp.Err(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func BenchmarkNewRR(b *testing.B) {
	const name1 = "12345678901234567890123456789012345.12345678.123."
	const s = name1 + " 3600 IN MX 10 " + name1

	for n := 0; n < b.N; n++ {
		_, err := NewRR(s)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadRR(b *testing.B) {
	const name1 = "12345678901234567890123456789012345.12345678.123."
	const s = name1 + " 3600 IN MX 10 " + name1 + "\n"

	for n := 0; n < b.N; n++ {
		r := struct{ io.Reader }{strings.NewReader(s)}
		// r is now only an io.Reader and won't benefit from the
		// io.ByteReader special-case in zlexer.Next.

		_, err := ReadRR(r, "")
		if err != nil {
			b.Fatal(err)
		}
	}
}

const benchZone = `
foo. IN A 10.0.0.1 ; this is comment 1
foo. IN A (
	10.0.0.2 ; this is comment 2
)
; this is comment 3
foo. IN A 10.0.0.3
foo. IN A ( 10.0.0.4 ); this is comment 4

foo. IN A 10.0.0.5
; this is comment 5

foo. IN A 10.0.0.6

foo. IN DNSKEY 256 3 5 AwEAAb+8l ; this is comment 6
foo. IN NSEC miek.nl. TXT RRSIG NSEC; this is comment 7
foo. IN TXT "THIS IS TEXT MAN"; this is comment 8
`

func BenchmarkParseZone(b *testing.B) {
	for n := 0; n < b.N; n++ {
		for tok := range ParseZone(strings.NewReader(benchZone), "example.org.", "") {
			if tok.Error != nil {
				b.Fatal(tok.Error)
			}
		}
	}
}

func BenchmarkZoneParser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		zp := NewZoneParser(strings.NewReader(benchZone), "example.org.", "")

		for _, ok := zp.Next(); ok; _, ok = zp.Next() {
		}

		if err := zp.Err(); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCommentLengthCrasherString test inputs to NewRR that generated crashes.
func TestCommentLengthCrasherString(t *testing.T) {
	tests := []struct {
		in  string
		err string
	}{

		{
			" HINFO ;;;;;;;;;;;;;" +
				";;;;;;;;\x00\x19;;;;;;;;;;" +
				";\u007f;;;;;;;;;;;;;;;;;;" +
				";;}mP_Qq_3sJ_1_84X_5" +
				"45iW_3K4p8J8_v9_LT3_" +
				"6_0l_3D4VT3xq6N_3K__" +
				"_U_xX2m;;;;;;(;;;;;;" +
				";;;;;;;;;;;;;;;\x1d;;;;" +
				";;;;;;-0x804dBDe8ba " +
				"\t \t\tr  HINFO \" \t\t\tve" +
				"k1xH11e__P6_dk1_51bo" +
				"g8gJK1V_O_v84_Bw4_1_" +
				"72jQ3_0J3V_S5iYn4h5X" +
				"R_2n___51J nN_  \t\tm " +
				"aa_XO4_5\t   \t\t \t\tg6b" +
				"p_KI_1_YWc_K8c2b___A" +
				"e_Y1m__4Y_R_avy6t08x" +
				"b5Cp9_7uS_yLa\t\t\t  d " +
				"EKe1Q83vS___ a  \t\t  " +
				"\tmP_Qq_3sJ_1_84X_545" +
				"iW_3K4p8J8_v9_LT3_6_" +
				"0l_3D4VT3xq6N_3K___U" +
				"_xX2\"\"   \t \t_fL Ogl5" +
				"_09i_9__3O7C__QMAG2U" +
				"35IO8RRU6aJ9_6_57_6_" +
				"b05BMoX5I__4833_____" +
				"yfD_2_OPs__sqzM_pqQi" +
				"_\t\t \tN__GuY4_Trath_0" +
				"yy___cAK_a__0J0q5 L_" +
				"p63Fzdva_Lb_29V7_R__" +
				"Go_H2_8m_4__FJM5B_Y5" +
				"Slw_ghp_55l_X2_Pnt6Y" +
				"_Wd_hM7jRZ_\t\t   \tm \t" +
				"  \t\ta md rK \x00 7_\"sr " +
				"- sg o  -0x804dBDe8b" +
				"a \t \t\tN_W6J3PBS_W__C" +
				"yJu__k6F_jY0INI_LC27" +
				"7x14b_1b___Y8f_K_3y_" +
				"0055yaP_LKu_72g_T_32" +
				"iBk1Zm_o  9i1P44_S0_" +
				"_4AXUpo2__H55tL_g78_" +
				"8V_8l0yg6bp_KI_1_YWc" +
				"_K8c2b  \t \tmaa_XO4_5" +
				"rg6bp_KI_1_YWc_K8c2b" +
				" _C20w i_4 \t\t  u_k d" +
				" rKsg09099 \"\"2335779" +
				"05047986112651e025 \t" +
				" \t\tN_W6J3PBS_W__CyJu" +
				"__k6F_jY0INI_LC277x1" +
				"4b_1b___Y8f_K_3y_005" +
				"5yaP_LKu_72g_T_32iBk" +
				"1Zm_o  9i1P44_S0__4A" +
				"XUpo2__H55tL_g78_8V_" +
				"8l0y_9K9_C__6af__wj_" +
				"UbSYy_ge29S_s_Qe259q" +
				"_kGod \t\t\t\t :0xb1AF1F" +
				"b71D2ACeaB3FEce2ssg " +
				"o dr-0x804dBDe8ba \t " +
				"\t\t$  Y5 _BzOc6S_Lk0K" +
				"y43j1TzV__9367tbX56_" +
				"6B3__q6_v8_4_0_t_2q_" +
				"nJ2gV3j9_tkOrx_H__a}" +
				"mT 0g6bp_KI_1_YWc_K8" +
				"c2b\t_ a\t \t54KM8f9_63" +
				"zJ2Q_c1_C_Zf4ICF4m0q" +
				"_RVm_3Zh4vr7yI_H2  a" +
				" m 0yq__TiqA_FQBv_SS" +
				"_Hm_8T8__M8F2_53TTo_" +
				"k_o2__u_W6Vr__524q9l" +
				"9CQsC_kOU___g_94   \"" +
				" ~a_j_16_6iUSu_96V1W" +
				"5r01j____gn157__8_LO" +
				"0y_08Jr6OR__WF8__JK_" +
				"N_wx_k_CGB_SjJ9R74i_" +
				"7_1t_6 m NULLNULLNUL" +
				"L \t \t\t\t drK\t\x00 7_\"\" 5" +
				"_5_y732S43__D_8U9FX2" +
				"27_k\t\tg6bp_KI_1_YWc_" +
				"K8c2b_J_wx8yw1CMw27j" +
				"___f_a8uw_ Er9gB_L2 " +
				"\t\t  \t\t\tm aa_XO4_5 Y_" +
				" I_T7762_zlMi_n8_FjH" +
				"vy62p__M4S_8__r092af" +
				"P_T_vhp6__SA_jVF13c5" +
				"2__8J48K__S4YcjoY91X" +
				"_iNf06  am aa_XO4_5\t" +
				" d _ am_SYY4G__2h4QL" +
				"iUIDd \t\t  \tXXp__KFjR" +
				"V__JU3o\"\" d  \t_Iks_ " +
				"aa_XO4_5<g6bp_KI_1_Y" +
				"Wc_K8c2b _BzOc6S_Lk0" +
				"Ky43j1TzV__9367tbX56" +
				"_6B3__q6_v8_4_0_t_2q" +
				"_nJ2gV3j9_tkOrx_H__ " +
				"a\t_Iks_ \\ ma 0_58_r1" +
				"y8jib_FaV_C_e \t \td\"\"" +
				" ^Dy_0  \t\t \t ;;;;;;;" +
				";;;;;;;;;;;",
			`dns: bad HINFO Fields: "comment length insufficient for parsing" at line: 1:1951`,
		},
		{
			";. oK_i_5_9o \"VT3xq6" +
				"N_3K___U_xP2o5gR -0x" +
				"804dBDe8ba ds1 o 8_7" +
				"i91i3SHGTyU_U_7E35y_" +
				"_o8S__1D3fp4_9___4r7" +
				"_0___QlJgq_C_8Q65FoQ" +
				"7C1_c_FN0x494.-01715" +
				"3 \t \t\ta_1_G5.4_F89HT" +
				"r _H _BzOc6S_Lk0Ky43" +
				"j1TzV__9367tbX56_6B3" +
				"__q6_v8_4_0_t_2q_nJ2" +
				"gV3j9_tkOrx_H__ 4530" +
				"MtN8BkQwZJNxz_7  D32" +
				" _v7m 3V0Uok 3GENERA" +
				"TEA53\t6e48562e0xF\tE\t" +
				"   -0xcFee-EZ_z \t\t-0" +
				"xb1AF1Fb71D2ACeaB3FE" +
				"ce2s   3Al 6e-5 \t \t\t" +
				"N_W6J3PBS_W__CyJu__k" +
				"6F_jY0INI_LC277x14b_" +
				"1b___Y8f_K_3y_0055ya" +
				"P_LKu_72g_T_32iBk1Zm" +
				"_o \x01 xOu __BzOc6S_Lk" +
				"0Ky43j1TzV__9367tbX5" +
				"6_6B3__q6_v8_4_0_t_2" +
				"q_nJ2gV3j9_tkOrx_H__" +
				"-0xb1AF1Fb71D2ACeaB3" +
				"FEce2s  xlT3KTf_dr 2" +
				"7 \t \t\tN_W6J3PBS_W__C" +
				"yJu__k6F_jY0INI_LC27" +
				"7x14b_1b___Y8f_K_3y_" +
				"0055yaP_LKu_72g_T_32" +
				"iBk1Zm_o  sQ_9_3\t \tm" +
				" aa_XO4_5-03575240.-" +
				"045353LOT_o_BzOc6S_L" +
				"k0Ky43j1TzV__9367tbX" +
				"56_6B3__q6_v8_4_0_t_" +
				"2q_nJ2gV3j9_tkOrx_H_" +
				"_  m aa_XO4_5  \t\t\t\t_" +
				"_gWZo90gm1sP9_BdL_5_" +
				"kY___U0S_J1iDk_o_h88" +
				"4o5_jn_085HZCnBj1b73" +
				"\t\t  m\t  \t\t\tsMPr0_r4L" +
				"rd362p_O_GN0_2_JWohR" +
				"WFEj7_DJi3oRq_6bGEln" +
				"KBl9tad_5Js5Ss8_PDrL" +
				"2nHnE90BqH24_QiMnY9 " +
				"-2371737156m 7e mP_Q" +
				"q_3sJ_1_84X_545iW_3K" +
				"4p8J8_v9_LT3_6_0l_3D" +
				"4VT3xq6N_3K___U_xX2 " +
				"Fv1_j yGgp_1E_Fb_t_3" +
				"__G02 _mgc_3G1X_7i_g" +
				"_7G4M25_lh__VR0____p" +
				"_R_x_AwC5CEfE_f_zjRt" +
				"7_p6c__1_fh_NJm6T7qA" +
				"_  ,1 0A5__S_xf7___0" +
				"XXp__KFjRV__JU3o,0xb" +
				"1AF1Fb71D2ACeaB3FEce" +
				"2s\tsg xlT3KTf_dr-6 \t" +
				" \t\tN_W6J3PBS_W__CyJu" +
				"__k6F_jY0INI_LC277x1" +
				"4b_1b___Y8f_K_3y_005" +
				"5yaP_LKu_72g_T_32iBk" +
				"1Zm_osQ_9_3\t a m aa_" +
				"XO4_5\t g6bp_KI_1_YWc" +
				"_K8c2b8_2_5k_BzOc6S_" +
				"Lk0Ky43j1TzV__9367tb" +
				"X56_6B3__q6_v8_4_0_t" +
				"_2q_nJ2gV3j9_tkOrx_H" +
				"__  m aa_XO4_5  \t\t\t\t" +
				"d\t\t  m sMPr0_r4Lrd36" +
				"2p_O_GN0_2_JWohRWFEj" +
				"7_DJi3oRq_6bGElnKBl9" +
				"tad_5Js5Ss8_PDrL2nHn" +
				"E90BqH24_QiMnY9 -783" +
				".03260xEd55d0Fe3Fe04" +
				"32 m 7e\\-16855948535" +
				"74011675064937138012" +
				"228 Fv1_j e x3es  ,Q" +
				"5519  _h4hQ_BzOc6S_L" +
				"d780k_z24_wF_gHD_m37" +
				"g_YWZ12W\"\"c_K8c2b _B" +
				"zOc6S_Lk0Ky43j1TzV__" +
				"9367tbX56_6B3__q6_v8" +
				"_4_0_t_2q_nJ2gV3j9_t" +
				"kOrx_H__\t\ta\t \t\t0A3_b" +
				"8_0I_GTKL_LC_pQ2MN_G" +
				"Y9YKp6H_cL_0V Rsg6bp" +
				"_KI_1_YWc_K8c2b _BzO" +
				"c6S_Lk0Ky43j1TzV__93" +
				"67tbX56_6B3__q6_v8_4" +
				"_0_t_2q_nJ2gV3j9_tkO" +
				"rx_H__ a\tJ  \a\xfde s 60" +
				"itr s t td  M__6VU_S" +
				"B45BVM2i69 W__z0AEfP" +
				"_g6me \"\"2Z_qY05APO_0" +
				"SgAvjFYC_0__0riU_9K9" +
				"_C__6af__wj_UbSYy_ge" +
				"29S_s_Qe259q_kGoddr\t" +
				" \t\t^  \t\t \t ;;;;;;;;;" +
				";;;;;;;;;;",
			`dns: comment length insufficient for parsing: "comment length insufficient for parsing" at line: 1:2030`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			_, err := NewRR(tc.in)
			if err == nil {
				t.Errorf("Expecting error for crasher line %s", tc.in)
			}
			if tc.err != err.Error() {
				t.Errorf("Expecting error %s, got %s", tc.err, err.Error())
			}
		})
	}
}
