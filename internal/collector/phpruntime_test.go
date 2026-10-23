package collector

import "testing"

func TestHandlerFromPath(t *testing.T) {
	cases := map[string]string{
		"/opt/cpanel/ea-php81/root/usr/bin/php": "ea-php81",
		"/opt/cpanel/ea-php85/root/usr/bin/php": "ea-php85",
		"/opt/alt/php74/usr/bin/php":            "alt-php74",
	}
	for in, want := range cases {
		if got := handlerFromPath(in); got != want {
			t.Errorf("handlerFromPath(%q) = %q, harusnya %q", in, got, want)
		}
	}
}

func TestPhpVersionRegexKeepsOnlyVersion(t *testing.T) {
	for in, want := range map[string]string{
		"8.4.27":            "8.4.27",
		"8.1.34-cpanel":     "8.1.34",
		"Warning: x\n8.2.1": "",
	} {
		if got := phpVersionRe.FindString(in); got != want {
			t.Errorf("%q → %q, harusnya %q", in, got, want)
		}
	}
}
