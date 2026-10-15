package main

import (
	"encoding/hex"
	"testing"
)

// Vectors produced by the previous server, whose encodings the 1.0.4 client accepted.
func TestEncodingMatchesKnownGood(t *testing.T) {
	cases := map[string]struct {
		got  tdfBuf
		want string
	}{
		"int":     {*new(tdfBuf).Int("UID", 1800012345).Int("NEG", -5).Int("Z", 0), "d6990000b988d0b40dba59c00045e800000000"},
		"str":     {*new(tdfBuf).Str("NAME", "Ward"), "ba1b6501055761726400"},
		"struct":  {*new(tdfBuf).Struct("PDTL", new(tdfBuf).Str("DSNM", "A").Int("STAS", 2)), "c24d2c03933bad01024100cf4873000200"},
		"intlist": {*new(tdfBuf).IntList("CIDS", []int64{1, 61448, 126978}), "8e99330400030188c00782c00f"},
		"strmap":  {*new(tdfBuf).StringMap("CONF", []string{"a", "bb"}, map[string]string{"a": "1", "bb": "22"}), "8efba6050101020261000231000362620003323200"},
		"sril":    {*new(tdfBuf).EmptyStructList("SRIL"), "cf2a6c040300"},
		"settings": {*new(tdfBuf).StructList("GENS", []*tdfBuf{
			new(tdfBuf).Str("IDEN", "Online.MandatedVersion.Required").Str("VALU", "0"),
			new(tdfBuf).Str("IDEN", "Online.MandatedVersion.ExactMatch").Str("VALU", "false"),
		}).Struct("PACF", new(tdfBuf).Str("LCUV", "").Str("PRSF", "").Int("PSTA", 0).Str("PURL", "")), "9e5bb3040302a6496e01204f6e6c696e652e4d616e646174656456657273696f6e2e526571756972656400da1b350102300000a6496e01224f6e6c696e652e4d616e646174656456657273696f6e2e45786163744d6174636800da1b35010666616c73650000c218e603b23d76010100c32ce6010100c33d210000c35cac01010000"},
	}
	for name, c := range cases {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, c.want)
		}
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	b := new(tdfBuf).Str("AUTH", "NXPabc").Int("CTYP", -3).
		Struct("AIDS", new(tdfBuf).Struct("EXID", new(tdfBuf).Int("NXID", 7)).Int("PLAT", 14)).
		IntList("LIST", []int64{1, 2})
	f, err := decodeTDF(*b)
	if err != nil {
		t.Fatal(err)
	}
	if f["AUTH"].Str != "NXPabc" || f["CTYP"].Int != -3 || f["AIDS"].Members["PLAT"].Int != 14 ||
		f["AIDS"].Members["EXID"].Members["NXID"].Int != 7 || len(f["LIST"].List) != 2 {
		t.Fatalf("decoded %+v", f)
	}
	if hex.EncodeToString(f["AIDS"].Members["EXID"].Raw) != hex.EncodeToString(*new(tdfBuf).Struct("EXID", new(tdfBuf).Int("NXID", 7))) {
		t.Fatal("EXID raw member not preserved")
	}
}
