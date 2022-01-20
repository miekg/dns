package dns

import (
	"net"
	"testing"
)

// TestPackDataOpt tests generated using fuzz.go and with a message pack
// containing the following bytes:
// "0000\x00\x00000000\x00\x00/00000" +
// "0\x00\v\x00#\b00000000\x00\x00)000" +
// "000\x00\x1c00\x00\x0000\x00\x01000\x00\x00\x00\b" +
// "\x00\v\x00\x02\x0000000000"
// That bytes sequence created the overflow error.
func TestPackDataOpt(t *testing.T) {
	type args struct {
		option []EDNS0
		msg    []byte
		off    int
	}
	tests := []struct {
		name       string
		args       args
		want       int
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "overflow",
			args: args{
				option: []EDNS0{
					&EDNS0_LOCAL{Code: 0x3030, Data: []uint8{}},
					&EDNS0_LOCAL{Code: 0x3030, Data: []uint8{0x30}},
					&EDNS0_LOCAL{Code: 0x3030, Data: []uint8{}},
					&EDNS0_SUBNET{
						Code: 0x0, Family: 0x2,
						SourceNetmask: 0x0, SourceScope: 0x30,
						Address: net.IP{0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
				},
				msg: []byte{
					0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x2,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x30,
					0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x0b, 0x00,
					0x23, 0x08, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
					0x30, 0x30, 0x00, 0x00, 0x29, 0x30, 0x30, 0x30,
					0x30, 0x30, 0x30, 0x00, 0x00, 0x30, 0x30, 0x00,
					0x00, 0x30, 0x30, 0x00, 0x01, 0x30, 0x00, 0x00,
					0x00,
				},
				off: 54,
			},
			wantErr:    true,
			wantErrMsg: "dns: overflow packing opt",
			want:       57,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := packDataOpt(tt.args.option, tt.args.msg, tt.args.off)
			if (err != nil) != tt.wantErr {
				t.Errorf("packDataOpt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.wantErrMsg != err.Error() {
				t.Errorf("packDataOpt() error msg = %v, wantErrMsg %v", err.Error(), tt.wantErrMsg)
				return
			}
			if got != tt.want {
				t.Errorf("packDataOpt() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCrashNSEC tests generated using fuzz.go and with a message pack
// containing the following bytes:
// "0000\x00\x00000000\x00\x00/00000" +
// "0\x00\v\x00#\b00000\x00\x00\x00\x00\x00\x1a000" +
// "000\x00\x00\x00\x00\x1a000000\x00\x00\x00\x00\x1a0" +
// "00000\x00\v00\a0000000\x00"
// That byte sequence, when Unpack() and subsequent Pack() created a
// panic: runtime error: slice bounds out of range
// which was attributed to the fact that NSEC RR length computation was different (and smaller)
// then when within packDataNsec.
func TestCrashNSEC(t *testing.T) {
	compression := make(map[string]struct{})
	nsec := &NSEC{
		Hdr: RR_Header{
			Name:     ".",
			Rrtype:   0x2f,
			Class:    0x3030,
			Ttl:      0x30303030,
			Rdlength: 0xb,
		},
		NextDomain: ".",
		TypeBitMap: []uint16{
			0x2302, 0x2303, 0x230a, 0x230b,
			0x2312, 0x2313, 0x231a, 0x231b,
			0x2322, 0x2323,
		},
	}
	expectedLength := 19
	l := nsec.len(0, compression)
	if l != expectedLength {
		t.Fatalf("expected length of %d, got %d", expectedLength, l)
	}
}

// TestCrashNSEC3 tests generated using fuzz.go and with a message pack
// containing the following bytes:
// "0000\x00\x00000000\x00\x00200000" +
// "0\x00\v0000\x00\x00#\x0300\x00\x00\x00\x1a000" +
// "000\x00\v00\x0200\x00\x03000\x00"
// That byte sequence, when Unpack() and subsequent Pack() created a
// panic: runtime error: slice bounds out of range
// which was attributed to the fact that NSEC3 RR length computation was
// different (and smaller) then within NSEC3.pack (which relies on
// packDataNsec).
func TestCrashNSEC3(t *testing.T) {
	compression := make(map[string]struct{})
	nsec3 := &NSEC3{
		Hdr: RR_Header{
			Name:     ".",
			Rrtype:   0x32,
			Class:    0x3030,
			Ttl:      0x30303030,
			Rdlength: 0xb,
		},
		Hash:       0x30,
		Flags:      0x30,
		Iterations: 0x3030,
		SaltLength: 0x0,
		Salt:       "",
		HashLength: 0x0,
		NextDomain: ".",
		TypeBitMap: []uint16{
			0x2302, 0x2303, 0x230a, 0x230b,
		},
	}
	expectedLength := 24
	l := nsec3.len(0, compression)
	if l != expectedLength {
		t.Fatalf("expected length of %d, got %d", expectedLength, l)
	}
}

// TestNewRRCommentLengthCrasherString test inputs to NewRR that generated crashes.
func TestNewRRCommentLengthCrasherString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		err  string
	}{

		{
			"HINFO1", " HINFO ;;;;;;;;;;;;;" +
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
