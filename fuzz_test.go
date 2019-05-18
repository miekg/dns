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
