package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// Verify the seo_spam signatures flag dropped pharma/gambling pages but not
// legitimate government/health content.
func TestSeoSpamDetection(t *testing.T) {
	db := defaultSignatures()
	db.compile()
	ws := NewWebshellScanner(db)

	cases := []struct {
		name    string
		file    string
		content string
		wantSig string // "" = expect no seo_spam match
	}{
		{
			name:    "pharma html drop",
			file:    "daftar-obat.html",
			content: `<html><title>Daftar 7 Obat Penggugur Kandungan</title><body>Jual Cytotec 400 mcg asli, obat aborsi ready WA 0812.</body></html>`,
			wantSig: "spam_pharma_abortion",
		},
		{
			name:    "gambling php drop",
			file:    "slot.php",
			content: `<?php echo "Slot Gacor Maxwin Situs Terpercaya"; ?> gates of olympus sweet bonanza pragmatic play`,
			wantSig: "spam_gambling",
		},
		{
			name:    "legit health article (no flag)",
			file:    "postpartum.html",
			content: `<html><title>Penanganan Perdarahan Pascapersalinan</title><body>Misoprostol digunakan dalam tatalaksana perdarahan postpartum sesuai protokol WHO. Aborsi spontan dibahas dalam edukasi ibu hamil.</body></html>`,
			wantSig: "",
		},
		{
			name:    "legit gov page (no flag)",
			file:    "layanan.html",
			content: `<html><title>Jadwal Pelayanan Puskesmas</title><body>Layanan imunisasi dan KIA tersedia setiap hari kerja.</body></html>`,
			wantSig: "",
		},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.file)
			if err := os.WriteFile(p, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			results, err := ws.ScanFile(p)
			if err != nil {
				t.Fatal(err)
			}

			var seoHit string
			for _, r := range results {
				if r.Category == "seo_spam" {
					seoHit = r.SignatureID
				}
			}

			if tc.wantSig == "" && seoHit != "" {
				t.Errorf("FALSE POSITIVE: %s flagged as %s, expected clean", tc.file, seoHit)
			}
			if tc.wantSig != "" && seoHit == "" {
				t.Errorf("MISSED: %s expected %s, got no seo_spam match", tc.file, tc.wantSig)
			}
			if tc.wantSig != "" && seoHit == tc.wantSig {
				t.Logf("OK: %s -> %s", tc.file, seoHit)
			}
		})
	}
}
