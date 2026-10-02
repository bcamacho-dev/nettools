package stability

import (
	"testing"
	"time"
)

func TestJitter(t *testing.T) {
	rtts := []time.Duration{10 * time.Millisecond, 12 * time.Millisecond, 9 * time.Millisecond}
	got := Jitter(rtts)
	want := 2500 * time.Microsecond
	if got != want {
		t.Fatalf("jitter = %s, want %s", got, want)
	}
	if Jitter(nil) != 0 {
		t.Fatal("empty jitter")
	}
}
