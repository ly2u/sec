package version

import "testing"

func TestCompareNative(t *testing.T) {
	cases := []struct {
		kind Kind
		a, b string
		want int
	}{
		// dpkg: epoch dominates, tilde sorts before everything.
		{Deb, "1:9.2p1-2+deb12u3", "9.8p1-1", 1},
		{Deb, "3.0.15-1~deb12u1", "3.0.15-1", -1},
		{Deb, "2.36-9+deb12u7", "2.36-9+deb12u10", -1},
		// rpm: epoch prefix and .el release segments.
		{RPM, "1:3.2.2-6.el9_5.1", "1:3.2.2-6.el9_5", 1},
		{RPM, "3.2.2-6.el9_5.1", "1:3.0.0-1.el9", -1},
		// apk: -rN revisions.
		{APK, "1.12.12-r0", "1.12.12-r1", -1},
		{APK, "3.3.2-r0", "3.3.10-r0", -1},
		// OSV sentinel.
		{Deb, "0", "0.0.1-1", -1},
	}
	for _, c := range cases {
		got, err := Compare(c.kind, c.a, c.b)
		if err != nil {
			t.Fatalf("%s %q vs %q: %v", c.kind, c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("%s %q vs %q = %d, want %d", c.kind, c.a, c.b, got, c.want)
		}
	}
}

func TestCompareRejectsGarbage(t *testing.T) {
	if _, err := Compare(Deb, "not a version!", "1.0-1"); err == nil {
		t.Fatal("expected error for unparsable deb version")
	}
	if _, err := Compare(Kind("pip"), "1", "2"); err == nil {
		t.Fatal("expected error for unsupported kind")
	}
}

// The regreSSHion case: Debian 12 fixed CVE-2024-6387 in openssh
// 1:9.2p1-2+deb12u3 (DSA-5724-1) while upstream fixed it in 9.8p1.
// Comparing upstream numbers would wrongly flag the patched 9.2p1 package.
func TestBackportedFixIsNotAffected(t *testing.T) {
	events := []Event{{Introduced: "0"}, {Fixed: "1:9.2p1-2+deb12u3"}}
	for v, want := range map[string]bool{
		"1:9.2p1-2+deb12u2": true,
		"1:9.2p1-2+deb12u3": false,
		"1:9.2p1-2+deb12u5": false,
	} {
		got, err := Affected(Deb, v, events)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("openssh %s affected=%v, want %v", v, got, want)
		}
	}
}

func TestAffectedSemantics(t *testing.T) {
	cases := []struct {
		name   string
		v      string
		events []Event
		want   bool
	}{
		{"unfixed: introduced only", "2.0-1", []Event{{Introduced: "0"}}, true},
		{"before introduced", "1.0-1", []Event{{Introduced: "1.5-1"}, {Fixed: "2.0-1"}}, false},
		{"inside interval", "1.7-1", []Event{{Introduced: "1.5-1"}, {Fixed: "2.0-1"}}, true},
		{"last_affected inclusive", "1.9-1", []Event{{Introduced: "0"}, {LastAffected: "1.9-1"}}, true},
		{"after last_affected", "1.9-2", []Event{{Introduced: "0"}, {LastAffected: "1.9-1"}}, false},
		{"unsorted events", "1.7-1", []Event{{Fixed: "2.0-1"}, {Introduced: "1.5-1"}}, true},
		{
			"two intervals, between them",
			"2.5-1",
			[]Event{{Introduced: "1.0-1"}, {Fixed: "2.0-1"}, {Introduced: "3.0-1"}, {Fixed: "3.2-1"}},
			false,
		},
		{
			"two intervals, second",
			"3.1-1",
			[]Event{{Introduced: "1.0-1"}, {Fixed: "2.0-1"}, {Introduced: "3.0-1"}, {Fixed: "3.2-1"}},
			true,
		},
		{"limit excludes", "5.0-1", []Event{{Introduced: "0"}, {Limit: "4.0-1"}}, false},
	}
	for _, c := range cases {
		got, err := Affected(Deb, c.v, c.events)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFirstFixAbove(t *testing.T) {
	events := []Event{{Introduced: "1.0-1"}, {Fixed: "2.0-1"}, {Introduced: "3.0-1"}, {Fixed: "3.2-1"}}
	got, err := FirstFixAbove(Deb, "3.1-1", events)
	if err != nil || got != "3.2-1" {
		t.Fatalf("got %q, %v; want 3.2-1", got, err)
	}
	got, _ = FirstFixAbove(Deb, "9.0-1", events)
	if got != "" {
		t.Fatalf("no fix above 9.0-1, got %q", got)
	}
}

func TestUpstreamCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.24.0", "1.30.6", -1},
		{"1.30.6", "1.30.6", 0},
		{"9.8p1", "9.10p1", -1},
		{"9.8p1", "9.8p2", -1},
		{"1.1.1w", "1.1.1v", 1},
		{"3.0.15", "3.0.9", 1},
		{"24.22.1", "24.9.0", 1},
		{"8.3.36", "8.3.4", 1},
	}
	for _, c := range cases {
		got, err := Compare(Upstream, c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("%s vs %s = %d (%v), want %d", c.a, c.b, got, err, c.want)
		}
	}
	if _, err := Compare(Upstream, "1.2-3", "1.2"); err == nil {
		t.Error("a dash would be read as an rpm release; upstream versions must not contain one")
	}
	// nginx: 1.25–1.29 affected without fix, 1.30.x fixed at 1.30.6.
	open := []Event{{Introduced: "1.25.0"}, {Limit: "1.30.0"}}
	if a, _ := Affected(Upstream, "1.28.0", open); !a {
		t.Error("1.28.0 is in the end-of-life range")
	}
	if a, _ := Affected(Upstream, "1.30.6", open); a {
		t.Error("1.30.6 is outside the end-of-life range")
	}
}
