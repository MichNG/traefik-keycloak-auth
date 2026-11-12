// Package claims implements the authorization expression language of the
// Traefik Hub OIDC middleware `claims` option.
//
// Grammar (as documented):
//
//	expr     = or
//	or       = and { "||" and }
//	and      = unary { "&&" unary }
//	unary    = "!" unary | primary
//	primary  = call | "(" expr ")"
//	call     = Name "(" [ arg { "," arg } ] ")"
//	arg      = "`" ... "`" | ident | number
//
// Functions: Equals, Prefix, Contains, SplitContains, OneOf.
//
// The first argument is the claim key. It may be prefixed with `id_token.` or
// `access_token.` to select the token; without a prefix the ID token is used.
// A key may be a dot path to reach nested claims (`realm_access.roles`). A
// missing claim makes its predicate evaluate to false.
package claims

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Values holds the resolved claims of both tokens. Either map may be nil, in
// which case any claim of that token is considered missing.
type Values struct {
	IDToken     map[string]any
	AccessToken map[string]any
}

// Expr is a parsed authorization expression.
type Expr struct {
	root node
	src  string
}

// String returns the original expression.
func (e *Expr) String() string { return e.src }

// Eval evaluates the expression against the given claims.
func (e *Expr) Eval(v Values) bool {
	if e == nil || e.root == nil {
		return true
	}
	return e.root.eval(v)
}

// Parse parses an authorization expression. An empty expression parses to an
// Expr that always evaluates to true.
func Parse(src string) (*Expr, error) {
	if strings.TrimSpace(src) == "" {
		return &Expr{src: src}, nil
	}

	p := &parser{tokens: tokenize(src)}
	p.next()
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.cur.kind != tokEOF {
		return nil, fmt.Errorf("claims: unexpected %q at position %d", p.cur.text, p.cur.pos)
	}
	return &Expr{root: root, src: src}, nil
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

type node interface {
	eval(v Values) bool
}

type orNode struct{ l, r node }

func (n orNode) eval(v Values) bool { return n.l.eval(v) || n.r.eval(v) }

type andNode struct{ l, r node }

func (n andNode) eval(v Values) bool { return n.l.eval(v) && n.r.eval(v) }

type notNode struct{ x node }

func (n notNode) eval(v Values) bool { return !n.x.eval(v) }

type callNode struct {
	name string
	args []string
}

func (n callNode) eval(v Values) bool {
	resolved, ok := resolve(v, n.args[0])
	if !ok {
		return false
	}

	// The matching is delegated to package-level helpers on purpose: yaegi
	// 0.16.1 (the interpreter Traefik uses to load a plugin) mis-evaluates a
	// `for` loop written directly in a method body over a slice returned by a
	// multi-value call, while the same loop in a plain function is correct.
	switch strings.ToLower(n.name) {
	case "equals":
		if len(n.args) != 2 {
			return false
		}
		return anyEquals(resolved, n.args[1])
	case "prefix":
		if len(n.args) != 2 {
			return false
		}
		return anyPrefix(resolved, n.args[1])
	case "contains":
		if len(n.args) != 2 {
			return false
		}
		// "Contains (array)": the array contains the value.
		// "Contains (string)": the value contains the substring.
		return anyEquals(resolved, n.args[1]) || anyContains(resolved, n.args[1])
	case "splitcontains":
		if len(n.args) != 3 {
			return false
		}
		return anySplitContains(resolved, n.args[1], n.args[2])
	case "oneof":
		// OneOf(key, v1 [, v2, ...]): at least one allowed value.
		if len(n.args) < 2 {
			return false
		}
		return anyOneOf(resolved, n.args[1:])
	default:
		return false
	}
}

// resolve returns the flattened values of the (possibly nested, possibly
// prefixed) claim key.
func resolve(v Values, key string) ([]any, bool) {
	var source map[string]any
	path := key

	// Written with explicit if/else and one assignment per statement on
	// purpose: yaegi 0.16.1 (the interpreter Traefik uses to load a plugin)
	// mis-executes a tagless switch whose cases call a function when the case
	// body uses a parallel assignment (`source, path = v.AccessToken, ...`),
	// and reads the ID token where the access token was requested.
	if strings.HasPrefix(key, "id_token.") {
		source = v.IDToken
		path = strings.TrimPrefix(key, "id_token.")
	} else if strings.HasPrefix(key, "access_token.") {
		source = v.AccessToken
		path = strings.TrimPrefix(key, "access_token.")
	} else {
		source = v.IDToken
	}

	if source == nil {
		return nil, false
	}

	var current any = source
	for _, segment := range splitClaimPath(path) {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[segment]
		if !ok {
			return nil, false
		}
	}

	return flatten(current), true
}

// splitClaimPath splits a claim key into its path segments. A dot inside a
// claim name is escaped as `\.` and a backslash as `\\`, as documented by
// the reference.
func splitClaimPath(path string) []string {
	var parts []string
	var current strings.Builder

	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '\\' && i+1 < len(path) {
			next := path[i+1]
			if next == '.' || next == '\\' {
				current.WriteByte(next)
				i++
				continue
			}
		}
		if c == '.' {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(c)
	}

	parts = append(parts, current.String())
	return parts
}

// flatten turns a claim value into a flat list of scalar values: an array is
// expanded, everything else becomes a single element.
func flatten(value any) []any {
	switch v := value.(type) {
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, flatten(item)...)
		}
		return out
	case []string:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, item)
		}
		return out
	default:
		return []any{value}
	}
}

func scalarString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func anyEquals(values []any, want string) bool {
	for _, value := range values {
		if scalarString(value) == want {
			return true
		}
	}
	return false
}

// anyPrefix reports whether any value has the given prefix.
func anyPrefix(values []any, want string) bool {
	for _, value := range values {
		if strings.HasPrefix(scalarString(value), want) {
			return true
		}
	}
	return false
}

// anyContains reports whether any value contains the given substring.
func anyContains(values []any, want string) bool {
	for _, value := range values {
		if strings.Contains(scalarString(value), want) {
			return true
		}
	}
	return false
}

// anySplitContains reports whether splitting any value by sep yields the given
// element.
func anySplitContains(values []any, sep, want string) bool {
	for _, value := range values {
		parts := strings.Split(scalarString(value), sep)
		for i := 0; i < len(parts); i++ {
			if parts[i] == want {
				return true
			}
		}
	}
	return false
}

// anyOneOf reports whether any value is one of the allowed ones.
func anyOneOf(values []any, wants []string) bool {
	for i := 0; i < len(wants); i++ {
		if anyEquals(values, wants[i]) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokLParen
	tokRParen
	tokComma
	tokAnd
	tokOr
	tokNot
)

type token struct {
	kind tokenKind
	text string
	pos  int
}

func tokenize(src string) []token {
	var tokens []token
	runes := []rune(src)

	for i := 0; i < len(runes); {
		r := runes[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '(':
			tokens = append(tokens, token{tokLParen, "(", i})
			i++
		case r == ')':
			tokens = append(tokens, token{tokRParen, ")", i})
			i++
		case r == ',':
			tokens = append(tokens, token{tokComma, ",", i})
			i++
		case r == '&':
			// `&&` is documented; a single `&` is accepted as well.
			if i+1 < len(runes) && runes[i+1] == '&' {
				i += 2
			} else {
				i++
			}
			tokens = append(tokens, token{tokAnd, "&&", i})
		case r == '|':
			// `|` and `||` are both documented as the OR operand.
			if i+1 < len(runes) && runes[i+1] == '|' {
				i += 2
			} else {
				i++
			}
			tokens = append(tokens, token{tokOr, "||", i})
		case r == '!':
			tokens = append(tokens, token{tokNot, "!", i})
			i++
		case r == '`':
			start := i + 1
			j := start
			for j < len(runes) && runes[j] != '`' {
				j++
			}
			tokens = append(tokens, token{tokString, string(runes[start:j]), i})
			i = j + 1
		default:
			start := i
			for i < len(runes) && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) || runes[i] == '_' || runes[i] == '.' || runes[i] == '-') {
				i++
			}
			if start == i {
				// Unknown rune: skip it so the parser reports the real problem
				// (an operator) instead of looping forever.
				i++
				continue
			}
			tokens = append(tokens, token{tokIdent, string(runes[start:i]), start})
		}
	}

	tokens = append(tokens, token{tokEOF, "", len(runes)})
	return tokens
}

type parser struct {
	tokens []token
	pos    int
	cur    token
}

func (p *parser) next() {
	p.cur = p.tokens[p.pos]
	if p.pos < len(p.tokens)-1 {
		p.pos++
	}
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.cur.kind == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.cur.kind == tokAnd {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *parser) parseUnary() (node, error) {
	if p.cur.kind == tokNot {
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	switch p.cur.kind {
	case tokLParen:
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.cur.kind != tokRParen {
			return nil, fmt.Errorf("claims: missing closing parenthesis at position %d", p.cur.pos)
		}
		p.next()
		return inner, nil
	case tokIdent:
		name := p.cur.text
		p.next()
		if p.cur.kind != tokLParen {
			return nil, fmt.Errorf("claims: expected ( after %q at position %d", name, p.cur.pos)
		}
		if !isKnownFunction(name) {
			return nil, fmt.Errorf("claims: unknown function %q", name)
		}
		p.next()

		var args []string
		for p.cur.kind != tokRParen {
			if len(args) > 0 {
				if p.cur.kind != tokComma {
					return nil, fmt.Errorf("claims: expected , at position %d", p.cur.pos)
				}
				p.next()
			}
			switch p.cur.kind {
			case tokString, tokIdent:
				args = append(args, p.cur.text)
				p.next()
			default:
				return nil, fmt.Errorf("claims: expected an argument at position %d", p.cur.pos)
			}
		}
		p.next()

		if len(args) == 0 {
			return nil, fmt.Errorf("claims: %s requires a claim key", name)
		}
		return callNode{name: name, args: args}, nil
	default:
		return nil, fmt.Errorf("claims: unexpected %q at position %d", p.cur.text, p.cur.pos)
	}
}

func isKnownFunction(name string) bool {
	switch strings.ToLower(name) {
	case "equals", "prefix", "contains", "splitcontains", "oneof":
		return true
	default:
		return false
	}
}
