package oui

import "testing"

func TestLookupCisco(t *testing.T) {
	got := Lookup("00:00:0c:11:22:33")
	if got == "" || !contains(got, "Cisco") {
		t.Fatalf("Lookup = %q", got)
	}
}

func TestLookupMulticast(t *testing.T) {
	if got := Lookup("01:00:5e:00:00:01"); got != "Multicast" {
		t.Fatalf("Lookup = %q", got)
	}
}

func contains(s, part string) bool {
	return len(s) >= len(part) && (s == part || len(part) == 0 || indexOf(s, part) >= 0)
}

func indexOf(s, part string) int {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return i
		}
	}
	return -1
}
