package claims

import "testing"

func values() Values {
	return Values{
		IDToken: map[string]any{
			"sub":   "user-1",
			"grp":   "admin",
			"areas": []any{"office", "lab"},
			"scope": "openid profile writer",
			"realm_access": map[string]any{
				"roles": []any{"admin", "media"},
			},
			"referrer": "http://example.com/page",
			"active":   true,
		},
		AccessToken: map[string]any{
			"grp": []any{"reader", "admin"},
		},
	}
}

func TestParseAndEval(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{"Equals(`grp`, `admin`)", true},
		{"Equals(`grp`, `user`)", false},
		{"Equals(`grp`, `admin`) && Equals(`active`, `true`)", true},
		{"Equals(`grp`, `admin`) && Equals(`active`, `false`)", false},
		{"Equals(`grp`, `admin`) || Equals(`grp`, `user`)", true},
		// The reference also documents the single-character operands `|` and `&`.
		{"Equals(`grp`, `admin`) | Equals(`grp`, `user`)", true},
		{"Equals(`grp`, `nope`) | Equals(`grp`, `user`)", false},
		{"Equals(`grp`, `admin`) & Equals(`active`, `true`)", true},
		{"Equals(`grp`, `nope`) & Equals(`active`, `true`)", false},
		{"!Equals(`grp`, `user`)", true},
		{"!Equals(`grp`, `admin`)", false},
		{"Prefix(`referrer`, `http://example.com`)", true},
		{"Prefix(`referrer`, `https://example.com`)", false},
		{"Contains(`referrer`, `/page`)", true},
		{"Contains(`areas`, `home`)", false},
		{"Contains(`areas`, `office`)", true},
		{"SplitContains(`scope`, ` `, `writer`)", true},
		{"SplitContains(`scope`, ` `, `reader`)", false},
		{"OneOf(`areas`, `office`, `lab`)", true},
		{"OneOf(`areas`, `home`, `garage`)", false},
		{"OneOf(`grp`, `admin`)", true},
		{"OneOf(`grp`, `reader`)", false},
		// Nested claim (Keycloak realm roles).
		{"OneOf(`realm_access.roles`, `admin`, `media`)", true},
		{"Equals(`realm_access.roles`, `media`)", true},
		// Token prefix selection.
		{"Equals(`access_token.grp`, `admin`)", true},
		{"Equals(`id_token.grp`, `admin`)", true},
		{"Equals(`access_token.grp`, `admin`) && !Equals(`grp`, `reader`)", true},
		// Parentheses and precedence.
		{"(Equals(`grp`, `admin`) || Equals(`grp`, `x`)) && Equals(`active`, `true`)", true},
		{"!(Equals(`grp`, `admin`) && Equals(`active`, `false`))", true},
		// Missing claims evaluate to false.
		{"Equals(`nope`, `x`)", false},
		{"!Equals(`nope`, `x`)", true},
	}

	for _, tc := range cases {
		expr, err := Parse(tc.expr)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.expr, err)
		}
		if got := expr.Eval(values()); got != tc.want {
			t.Errorf("Eval(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, expr := range []string{
		"Bogus(`grp`, `admin`)",
		"Equals(`grp`",
		"Equals(`grp`, `admin`) &&",
		"Equals()",
		"Equals(`grp`, `admin`, `extra`) && true",
	} {
		if _, err := Parse(expr); err == nil {
			t.Errorf("Parse(%q) expected an error", expr)
		}
	}
}

func TestEmptyExpressionIsAuthorized(t *testing.T) {
	expr, err := Parse("")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !expr.Eval(Values{}) {
		t.Fatal("an empty expression must evaluate to true")
	}
}

func TestMissingTokenSide(t *testing.T) {
	expr, err := Parse("Equals(`access_token.grp`, `admin`)")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if expr.Eval(Values{IDToken: map[string]any{"grp": "admin"}}) {
		t.Fatal("an access_token claim must not resolve from the ID token")
	}
}

func TestEscapedDotInClaimKey(t *testing.T) {
	values := Values{IDToken: map[string]any{"a.b": "x", "nested": map[string]any{"b": "y"}}}

	cases := []struct {
		expr string
		want bool
	}{
		{`Equals(` + "`a\\.b`" + `, ` + "`x`" + `)`, true},
		{`Equals(` + "`a.b`" + `, ` + "`x`" + `)`, false},
		{`Equals(` + "`nested.b`" + `, ` + "`y`" + `)`, true},
	}

	for _, tc := range cases {
		expr, err := Parse(tc.expr)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.expr, err)
		}
		if got := expr.Eval(values); got != tc.want {
			t.Errorf("Eval(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}
