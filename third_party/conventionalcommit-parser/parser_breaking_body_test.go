package parser

import "testing"

// Regression tests for the upstream v0.8.0 panic ("index out of range [-1]"
// in bodyState) on messages that have both a body and a BREAKING CHANGE
// footer. See README.md.

func TestParseBodyWithBreakingChangeFooter(t *testing.T) {
	msg := "type: description message\n\nThis is the body.\n\nBREAKING CHANGE: reason"

	c, err := New().Parse(msg)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if got := c.Type(); got != "type" {
		t.Errorf("Type() = %q, want %q", got, "type")
	}
	if got := c.Description(); got != "description message" {
		t.Errorf("Description() = %q, want %q", got, "description message")
	}
	if got := c.Body(); got != "This is the body." {
		t.Errorf("Body() = %q, want %q", got, "This is the body.")
	}
	if !c.IsBreakingChange() {
		t.Error("IsBreakingChange() = false, want true")
	}

	notes := c.Notes()
	if len(notes) != 1 {
		t.Fatalf("len(Notes()) = %d, want 1: %+v", len(notes), notes)
	}
	if notes[0].Token() != "BREAKING CHANGE" {
		t.Errorf("Notes()[0].Token() = %q, want %q", notes[0].Token(), "BREAKING CHANGE")
	}
	if notes[0].Value() != "reason" {
		t.Errorf("Notes()[0].Value() = %q, want %q", notes[0].Value(), "reason")
	}
}

func TestParseBodyWithBreakingChangeHyphenFooterAndTrailer(t *testing.T) {
	msg := "fix: correct rotation\n\nbody text\n\nBREAKING-CHANGE: why\n\nSigned-off-by: Dev <dev@example.com>"

	c, err := New().Parse(msg)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if got := c.Body(); got != "body text" {
		t.Errorf("Body() = %q, want %q", got, "body text")
	}
	if !c.IsBreakingChange() {
		t.Error("IsBreakingChange() = false, want true")
	}

	notes := c.Notes()
	if len(notes) != 2 {
		t.Fatalf("len(Notes()) = %d, want 2: %+v", len(notes), notes)
	}
	if notes[0].Token() != "BREAKING-CHANGE" || notes[0].Value() != "why" {
		t.Errorf("Notes()[0] = %q:%q, want %q:%q", notes[0].Token(), notes[0].Value(), "BREAKING-CHANGE", "why")
	}
	if notes[1].Token() != "Signed-off-by" || notes[1].Value() != "Dev <dev@example.com>" {
		t.Errorf("Notes()[1] = %q:%q, want %q:%q", notes[1].Token(), notes[1].Value(), "Signed-off-by", "Dev <dev@example.com>")
	}
}

func TestParseFooterValueBeforeBreakingChangeFooter(t *testing.T) {
	msg := "type: description message\n\nfooter: simple\n\nBREAKING CHANGE: reason"

	c, err := New().Parse(msg)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	notes := c.Notes()
	if len(notes) != 2 {
		t.Fatalf("len(Notes()) = %d, want 2: %+v", len(notes), notes)
	}
	if notes[0].Token() != "footer" || notes[0].Value() != "simple" {
		t.Errorf("Notes()[0] = %q:%q, want %q:%q", notes[0].Token(), notes[0].Value(), "footer", "simple")
	}
	if notes[1].Token() != "BREAKING CHANGE" || notes[1].Value() != "reason" {
		t.Errorf("Notes()[1] = %q:%q, want %q:%q", notes[1].Token(), notes[1].Value(), "BREAKING CHANGE", "reason")
	}
}
