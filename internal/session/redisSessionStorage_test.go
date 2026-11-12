package session

// Unit tests for the Redis-backed session storage.
//
// They run against a minimal in-process TCP mock speaking just enough RESP2
// (SET/GET/DEL/PING/AUTH/SELECT) to exercise the real redis.Client. The RESP
// parser is re-implemented here on purpose: the helpers in
// src/internal/redis are `_test`-only and unexported, so they cannot be
// imported from another package's test binary.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/MichNG/traefik-keycloak-auth/internal/utils"
)

// testSecret is exactly 32 characters long, as required by the encryption.
const testSecret = "0123456789abcdef0123456789abcdef"

func testLogger() *logging.Logger { return logging.CreateLogger(logging.LevelError) }

// ---------------------------------------------------------------------------
// Minimal RESP2 mock Redis server.
// ---------------------------------------------------------------------------

type mockRedis struct {
	ln net.Listener

	mu   sync.Mutex
	data map[string]string
	sets map[string]map[string]bool
	cmds []string
	// readonlyWrites answers that many upcoming write commands with READONLY,
	// modelling a demoted master during a failover.
	readonlyWrites int
}

func newMockRedis(t *testing.T) *mockRedis {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock redis: listen: %v", err)
	}

	m := &mockRedis{ln: ln, data: map[string]string{}, sets: map[string]map[string]bool{}}
	go m.serve()
	t.Cleanup(func() { _ = ln.Close() })

	return m
}

func (m *mockRedis) addr() string { return m.ln.Addr().String() }

func (m *mockRedis) serve() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.handle(conn)
	}
}

func (m *mockRedis) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	rd := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(rd)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}

		name := strings.ToUpper(args[0])

		m.mu.Lock()
		m.cmds = append(m.cmds, strings.Join(args, " "))
		readonly := false
		if m.readonlyWrites > 0 && (name == "SET" || name == "SADD" || name == "SREM") {
			m.readonlyWrites--
			readonly = true
		}
		m.mu.Unlock()

		if readonly {
			writeError(conn, "READONLY You can't write against a read only replica.")
			continue
		}

		switch name {
		case "PING":
			writeSimple(conn, "PONG")
		case "AUTH", "SELECT":
			writeSimple(conn, "OK")
		case "SET":
			if len(args) < 3 {
				writeError(conn, "ERR wrong number of arguments for 'set' command")
				continue
			}
			m.mu.Lock()
			m.data[args[1]] = args[2]
			delete(m.sets, args[1])
			m.mu.Unlock()
			writeSimple(conn, "OK")
		case "GET":
			if len(args) < 2 {
				writeError(conn, "ERR wrong number of arguments for 'get' command")
				continue
			}
			m.mu.Lock()
			_, isSet := m.sets[args[1]]
			v, ok := m.data[args[1]]
			m.mu.Unlock()
			if isSet {
				writeError(conn, "WRONGTYPE Operation against a key holding the wrong kind of value")
				continue
			}
			if !ok {
				writeNil(conn)
				continue
			}
			writeBulk(conn, v)
		case "SADD":
			if len(args) < 3 {
				writeError(conn, "ERR wrong number of arguments for 'sadd' command")
				continue
			}
			m.mu.Lock()
			_, isString := m.data[args[1]]
			m.mu.Unlock()
			if isString {
				writeError(conn, "WRONGTYPE Operation against a key holding the wrong kind of value")
				continue
			}
			m.mu.Lock()
			set := m.sets[args[1]]
			if set == nil {
				set = map[string]bool{}
				m.sets[args[1]] = set
			}
			added := 0
			for _, member := range args[2:] {
				if !set[member] {
					set[member] = true
					added++
				}
			}
			m.mu.Unlock()
			writeInteger(conn, added)
		case "SREM":
			m.mu.Lock()
			_, isString := m.data[args[1]]
			m.mu.Unlock()
			if isString {
				writeError(conn, "WRONGTYPE Operation against a key holding the wrong kind of value")
				continue
			}
			m.mu.Lock()
			set := m.sets[args[1]]
			removed := 0
			for _, member := range args[2:] {
				if set[member] {
					delete(set, member)
					removed++
				}
			}
			m.mu.Unlock()
			writeInteger(conn, removed)
		case "SMEMBERS":
			m.mu.Lock()
			_, isString := m.data[args[1]]
			m.mu.Unlock()
			if isString {
				writeError(conn, "WRONGTYPE Operation against a key holding the wrong kind of value")
				continue
			}
			m.mu.Lock()
			set := m.sets[args[1]]
			members := make([]string, 0, len(set))
			for member := range set {
				members = append(members, member)
			}
			m.mu.Unlock()
			writeArray(conn, members)
		case "EXPIRE":
			writeInteger(conn, 1)
		case "DEL":
			deleted := 0
			m.mu.Lock()
			for _, key := range args[1:] {
				if _, ok := m.data[key]; ok {
					delete(m.data, key)
					deleted++
				}
				if _, ok := m.sets[key]; ok {
					delete(m.sets, key)
					deleted++
				}
			}
			m.mu.Unlock()
			writeInteger(conn, deleted)
		default:
			writeError(conn, "ERR unknown command '"+args[0]+"'")
		}
	}
}

func writeArray(conn net.Conn, items []string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(items))
	for _, item := range items {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(item), item)
	}
	_, _ = conn.Write([]byte(sb.String()))
}

func (m *mockRedis) commandLog() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.cmds...)
}

func (m *mockRedis) setContains(key, member string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sets[key][member]
}

func (m *mockRedis) get(key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	return v, ok
}

// put writes a raw value, bypassing the RESP protocol, so a test can corrupt a
// stored blob without going through the storage under test.
func (m *mockRedis) put(key, value string) {
	m.mu.Lock()
	m.data[key] = value
	m.mu.Unlock()
}

// putSet stores a raw set, bypassing the RESP protocol, so a test can create a
// type conflict (a set where a string is expected) without going through SADD.
func (m *mockRedis) putSet(key string, members ...string) {
	m.mu.Lock()
	set := map[string]bool{}
	for _, member := range members {
		set[member] = true
	}
	m.sets[key] = set
	m.mu.Unlock()
}

// failWritesWithReadonly makes the mock answer the next n write commands with
// READONLY, like a demoted master just after a Sentinel failover.
func (m *mockRedis) failWritesWithReadonly(n int) {
	m.mu.Lock()
	m.readonlyWrites = n
	m.mu.Unlock()
}

// findCommand returns the first logged command starting with prefix.
func (m *mockRedis) findCommand(prefix string) (string, bool) {
	for _, cmd := range m.commandLog() {
		if strings.HasPrefix(cmd, prefix) {
			return cmd, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// RESP2 codec used by the mock.
// ---------------------------------------------------------------------------

func readRESPCommand(rd *bufio.Reader) ([]string, error) {
	line, err := readRESPLine(rd)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("mock redis: expected an array, got %q", line)
	}

	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, fmt.Errorf("mock redis: malformed array length %q: %w", line, err)
	}

	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := readRESPLine(rd)
		if err != nil {
			return nil, err
		}
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, fmt.Errorf("mock redis: expected a bulk string, got %q", hdr)
		}

		length, err := strconv.Atoi(hdr[1:])
		if err != nil {
			return nil, fmt.Errorf("mock redis: malformed bulk length %q: %w", hdr, err)
		}

		buf := make([]byte, length+2) // payload + CRLF
		if _, err := io.ReadFull(rd, buf); err != nil {
			return nil, fmt.Errorf("mock redis: reading bulk payload: %w", err)
		}
		args = append(args, string(buf[:length]))
	}

	return args, nil
}

func readRESPLine(rd *bufio.Reader) (string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func writeSimple(w io.Writer, s string) { _, _ = fmt.Fprintf(w, "+%s\r\n", s) }

func writeError(w io.Writer, s string) { _, _ = fmt.Fprintf(w, "-%s\r\n", s) }

func writeInteger(w io.Writer, n int) { _, _ = fmt.Fprintf(w, ":%d\r\n", n) }

func writeBulk(w io.Writer, s string) { _, _ = fmt.Fprintf(w, "$%d\r\n%s\r\n", len(s), s) }

func writeNil(w io.Writer) { _, _ = io.WriteString(w, "$-1\r\n") }

// ---------------------------------------------------------------------------
// Store helpers.
// ---------------------------------------------------------------------------

func newTestStore(t *testing.T, m *mockRedis, prefix string) *RedisSessionStorage {
	t.Helper()

	store, err := CreateRedisSessionStorage(context.Background(), testLogger(), RedisOptions{
		Endpoints: []string{m.addr()},
		TTL:       90 * time.Second,
		Secret:    testSecret,
		KeyPrefix: prefix,
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateRedisSessionStorage: %v", err)
	}
	t.Cleanup(store.Close)

	return store
}

func testState() *SessionState {
	return &SessionState{
		Id:                 "session-id-1",
		RefreshedAt:        time.Now().UTC().Truncate(time.Second),
		AccessToken:        "access-token-value",
		IdToken:            "id-token-value",
		RefreshToken:       "refresh-token-value",
		IsAuthorized:       true,
		TokenExpiresIn:     3600,
		AuthenticatedAt:    time.Now().UTC().Truncate(time.Second),
		OidcSid:            "sid-value",
		Sub:                "sub-value",
		ChallengeAttempted: true,
	}
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

func TestRedisSessionStorage_StoreAndGetRoundTrip(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	state := testState()
	id := GenerateSessionId()

	ticket, err := store.StoreSession(testLogger(), nil, id, state)
	if err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	if ticket != id {
		t.Fatalf("ticket = %q, want the session id %q", ticket, id)
	}

	got, err := store.TryGetSession(testLogger(), nil, ticket)
	if err != nil {
		t.Fatalf("TryGetSession: %v", err)
	}
	if got == nil {
		t.Fatal("TryGetSession returned nil for a stored session")
	}
	if !reflect.DeepEqual(got, state) {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v", got, state)
	}

	// The stored blob must be encrypted, not the plaintext JSON.
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	stored, ok := m.get(store.sessionKey(id))
	if !ok {
		t.Fatalf("session key %q not found in the mock store", store.sessionKey(id))
	}
	if stored == string(raw) {
		t.Fatal("the stored value is the plaintext JSON; it must be encrypted")
	}
	if strings.Contains(stored, "access_token") || strings.Contains(stored, state.AccessToken) {
		t.Fatalf("the stored value leaks the session content: %q", stored)
	}
	plain, err := utils.Decrypt(stored, testSecret)
	if err != nil {
		t.Fatalf("the stored value is not decryptable with the secret: %v", err)
	}
	if plain != string(raw) {
		t.Fatalf("decrypted value mismatch:\n got: %s\nwant: %s", plain, raw)
	}

	// The mock must have received: SET <key> <val> EX <ttl>.
	setCmd, ok := m.findCommand("SET " + store.sessionKey(id) + " ")
	if !ok {
		t.Fatalf("no SET command for the session key; commands: %v", m.commandLog())
	}
	wantTTL := " EX " + strconv.Itoa(int((90 * time.Second).Seconds()))
	if !strings.HasSuffix(setCmd, wantTTL) {
		t.Fatalf("SET command %q does not end with %q", setCmd, wantTTL)
	}
}

func TestRedisSessionStorage_TryGetSessionMiss(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	got, err := store.TryGetSession(testLogger(), nil, "unknown-ticket")
	if err != nil {
		t.Fatalf("TryGetSession: %v", err)
	}
	if got != nil {
		t.Fatalf("TryGetSession on a miss = %+v, want nil", got)
	}

	// An empty ticket is a miss too and must not hit Redis.
	got, err = store.TryGetSession(testLogger(), nil, "")
	if err != nil || got != nil {
		t.Fatalf("TryGetSession with an empty ticket = (%+v, %v), want (nil, nil)", got, err)
	}
}

func TestRedisSessionStorage_RevokeBySidAndSub(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	stateA := testState()
	stateA.OidcSid = "sid-a"
	stateA.Sub = "sub-a"
	idA := GenerateSessionId()

	stateB := testState()
	stateB.OidcSid = "sid-b"
	stateB.Sub = "sub-b"
	idB := GenerateSessionId()

	if _, err := store.StoreSession(testLogger(), nil, idA, stateA); err != nil {
		t.Fatalf("StoreSession A: %v", err)
	}
	if _, err := store.StoreSession(testLogger(), nil, idB, stateB); err != nil {
		t.Fatalf("StoreSession B: %v", err)
	}

	// RevokeBySid.
	n, err := store.RevokeBySid("sid-a")
	if err != nil {
		t.Fatalf("RevokeBySid: %v", err)
	}
	if n != 1 {
		t.Fatalf("RevokeBySid = %d, want 1", n)
	}
	if got, err := store.TryGetSession(testLogger(), nil, idA); err != nil || got != nil {
		t.Fatalf("session A after RevokeBySid = (%+v, %v), want (nil, nil)", got, err)
	}
	if _, ok := m.get(store.indexKey("sid", "sid-a")); ok {
		t.Fatal("the sid index was not deleted")
	}

	// RevokeBySub.
	n, err = store.RevokeBySub("sub-b")
	if err != nil {
		t.Fatalf("RevokeBySub: %v", err)
	}
	if n != 1 {
		t.Fatalf("RevokeBySub = %d, want 1", n)
	}
	if got, err := store.TryGetSession(testLogger(), nil, idB); err != nil || got != nil {
		t.Fatalf("session B after RevokeBySub = (%+v, %v), want (nil, nil)", got, err)
	}

	// Unknown sid / sub: 0 and no error.
	if n, err := store.RevokeBySid("unknown-sid"); err != nil || n != 0 {
		t.Fatalf("RevokeBySid(unknown) = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := store.RevokeBySub("unknown-sub"); err != nil || n != 0 {
		t.Fatalf("RevokeBySub(unknown) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestCreateRedisSessionStorage_ValidationErrors(t *testing.T) {
	valid := RedisOptions{
		Endpoints: []string{"127.0.0.1:6379"},
		TTL:       time.Minute,
		Secret:    testSecret,
	}

	tests := []struct {
		name    string
		mutate  func(o *RedisOptions)
		wantMsg string
	}{
		{
			name:    "no endpoints",
			mutate:  func(o *RedisOptions) { o.Endpoints = nil },
			wantMsg: "endpoints is required",
		},
		{
			name:    "non-positive TTL",
			mutate:  func(o *RedisOptions) { o.TTL = 0 },
			wantMsg: "session.expiry must be > 0",
		},
		{
			name:    "wrong-length secret",
			mutate:  func(o *RedisOptions) { o.Secret = "too-short" },
			wantMsg: "exactly 32 characters",
		},
		{
			name:    "sentinel without masterSet",
			mutate:  func(o *RedisOptions) { o.Sentinel = &RedisSentinel{} },
			wantMsg: "masterSet is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := valid
			tc.mutate(&opts)

			store, err := CreateRedisSessionStorage(context.Background(), testLogger(), opts)
			if err == nil {
				store.Close()
				t.Fatalf("expected an error containing %q, got nil", tc.wantMsg)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestRedisSessionStorage_CorruptedBlobFailsDecryption(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	state := testState()
	id := GenerateSessionId()

	if _, err := store.StoreSession(testLogger(), nil, id, state); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}

	key := store.sessionKey(id)
	stored, ok := m.get(key)
	if !ok {
		t.Fatalf("session key %q not found", key)
	}

	blob, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		t.Fatalf("the stored value is not valid base64: %v", err)
	}
	if len(blob) < 2 {
		t.Fatalf("the stored blob is too short to corrupt: %d bytes", len(blob))
	}
	blob[len(blob)-1] ^= 0xff // flip a byte inside the GCM tag/ciphertext

	m.put(key, base64.StdEncoding.EncodeToString(blob))

	got, err := store.TryGetSession(testLogger(), nil, id)
	if err == nil {
		t.Fatalf("TryGetSession on a corrupted blob = %+v, want a decryption error", got)
	}
	if got != nil {
		t.Fatalf("TryGetSession on a corrupted blob returned a session: %+v", got)
	}
}

func TestRedisSessionStorage_KeyLayoutAndPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{name: "default prefix", prefix: ""},
		{name: "custom prefix", prefix: "myapp:"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockRedis(t)
			store := newTestStore(t, m, tc.prefix)

			wantPrefix := tc.prefix
			if wantPrefix == "" {
				wantPrefix = DefaultKeyPrefix
			}

			state := testState()
			id := GenerateSessionId()
			if _, err := store.StoreSession(testLogger(), nil, id, state); err != nil {
				t.Fatalf("StoreSession: %v", err)
			}

			for _, key := range []string{
				wantPrefix + "session:" + id,
				wantPrefix + "sid:" + state.OidcSid,
			} {
				if _, ok := m.get(key); !ok {
					t.Fatalf("key %q not stored; store contents: %v", key, m.commandLog())
				}
			}

			// The sub index is a Redis set, so it is not a string key.
			if !m.setContains(wantPrefix+"sub:"+state.Sub, id) {
				t.Fatalf("sub index %q does not contain %q; commands: %v", wantPrefix+"sub:"+state.Sub, id, m.commandLog())
			}
		})
	}
}

func TestRedisSessionStorage_SingleInstanceStore(t *testing.T) {
	m := newMockRedis(t)

	store, err := CreateRedisSessionStorage(context.Background(), testLogger(), RedisOptions{
		Endpoints:      []string{m.addr()},
		TTL:            5 * time.Minute,
		Secret:         testSecret,
		Timeout:        time.Second,
		PoolSize:       2,
		MaxActiveConns: 2,
	})
	if err != nil {
		t.Fatalf("CreateRedisSessionStorage: %v", err)
	}
	defer store.Close()

	if got, want := store.Node(), m.addr(); got != want {
		t.Fatalf("Node() = %q, want %q", got, want)
	}

	id := GenerateSessionId()
	if _, err := store.StoreSession(testLogger(), nil, id, testState()); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	if got, err := store.TryGetSession(testLogger(), nil, id); err != nil || got == nil {
		t.Fatalf("TryGetSession = (%+v, %v), want a session and no error", got, err)
	}

	// Close is idempotent.
	store.Close()
	store.Close()
}

// The sub index must hold every session of the same user: a second login used
// to overwrite the first one, so a back-channel logout would leave a session
// alive.
func TestRedisSessionStorage_RevokeBySubMultipleSessions(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	const sub = "shared-sub"

	var ids []string
	for i := 0; i < 2; i++ {
		state := testState()
		state.OidcSid = ""
		state.Sub = sub
		id := GenerateSessionId()
		ids = append(ids, id)

		if _, err := store.StoreSession(testLogger(), nil, id, state); err != nil {
			t.Fatalf("StoreSession %d: %v", i, err)
		}
	}

	n, err := store.RevokeBySub(sub)
	if err != nil {
		t.Fatalf("RevokeBySub: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeBySub = %d, want 2", n)
	}

	for _, id := range ids {
		if got, err := store.TryGetSession(testLogger(), nil, id); err != nil || got != nil {
			t.Fatalf("session %s after RevokeBySub = (%+v, %v), want (nil, nil)", id, got, err)
		}
	}

	if m.setContains(store.indexKey("sub", sub), ids[0]) || m.setContains(store.indexKey("sub", sub), ids[1]) {
		t.Fatal("the sub index still lists revoked sessions")
	}
}

// A legacy string sub index must be healed as a data problem, not open the
// breaker (which would turn one bad key into a 503 for every user).
func TestRedisSessionStorage_LegacyStringSubIndexIsHealed(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	legacyKey := store.indexKey("sub", "legacy-sub")
	m.put(legacyKey, "old-session-id")

	n, err := store.RevokeBySub("legacy-sub")
	if err != nil || n != 0 {
		t.Fatalf("RevokeBySub on a legacy index = (%d, %v), want (0, nil)", n, err)
	}

	if _, ok := m.get(legacyKey); ok {
		t.Fatal("the legacy index was not healed (deleted)")
	}

	// The breaker must still be closed: a normal miss is not an outage.
	if _, err := store.TryGetSession(testLogger(), nil, "unknown"); err != nil {
		t.Fatalf("the breaker opened after a WRONGTYPE index: %v", err)
	}
}

// A legacy string sub index must be replaced by a set on the store path too:
// SADD against the stale key used to feed the breaker (503 for every user) and
// silently leave the session unindexed (N8').
func TestRedisSessionStorage_StoreHealsLegacyStringSubIndex(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	indexKey := store.indexKey("sub", "legacy-sub")
	m.put(indexKey, "old-session-id")

	state := testState()
	state.Sub = "legacy-sub"
	id := GenerateSessionId()

	if _, err := store.StoreSession(testLogger(), nil, id, state); err != nil {
		t.Fatalf("StoreSession over a legacy string index: %v", err)
	}

	if _, ok := m.get(indexKey); ok {
		t.Fatal("the legacy string index was not healed (replaced by a set)")
	}
	if !m.setContains(indexKey, id) {
		t.Fatalf("the session %q was not indexed after healing; commands: %v", id, m.commandLog())
	}

	// The breaker must still be closed: a bad key is not an outage.
	if _, err := store.TryGetSession(testLogger(), nil, "unknown"); err != nil {
		t.Fatalf("the breaker opened after a WRONGTYPE SADD: %v", err)
	}

	// Healing the index keeps the session revocable by sub.
	n, err := store.RevokeBySub("legacy-sub")
	if err != nil || n != 1 {
		t.Fatalf("RevokeBySub after healing = (%d, %v), want (1, nil)", n, err)
	}
}

// SREM against a legacy string sub index is a removal that must not open the
// breaker: the stale key is simply dropped (N8').
func TestRedisSessionStorage_RevokeBySidHealsLegacyStringSubIndex(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	state := testState()
	id := GenerateSessionId()
	if _, err := store.StoreSession(testLogger(), nil, id, state); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}

	// Corrupt the sub index into the legacy string form.
	subKey := store.indexKey("sub", state.Sub)
	m.put(subKey, "old-session-id")

	n, err := store.RevokeBySid(state.OidcSid)
	if err != nil || n != 1 {
		t.Fatalf("RevokeBySid = (%d, %v), want (1, nil)", n, err)
	}
	if _, ok := m.get(subKey); ok {
		t.Fatal("the legacy sub index was not healed (deleted) during the sid revoke")
	}

	if _, err := store.TryGetSession(testLogger(), nil, "unknown"); err != nil {
		t.Fatalf("the breaker opened after a WRONGTYPE SREM: %v", err)
	}
}

// A demoted master (READONLY during a Sentinel failover) must not open the
// shared breaker: the store answered, and opening the breaker would take the
// read path down for the whole window instead of letting the discovery switch
// to the new master (mirrors the E2E failover check).
func TestRedisSessionStorage_ReadOnlyFailoverDoesNotOpenBreaker(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	// The client retries a topology change once, so two READONLY replies
	// exhaust the write attempts of one StoreSession. Three failing stores are
	// enough to open the breaker (threshold 3) if the topology change were
	// mistaken for an outage.
	m.failWritesWithReadonly(6)

	for i := 0; i < 3; i++ {
		if _, err := store.StoreSession(testLogger(), nil, GenerateSessionId(), testState()); err == nil {
			t.Fatalf("StoreSession #%d on a read-only node must report the failover", i+1)
		}
	}

	// The breaker must still be closed: the very next read has to reach Redis.
	got, err := store.TryGetSession(testLogger(), nil, "absent")
	if err != nil || got != nil {
		t.Fatalf("the breaker opened after READONLY replies: (%+v, %v)", got, err)
	}
}

// A set stored where a session string is expected must be treated as an absent
// session and healed, without failing the request or the store (N9').
func TestRedisSessionStorage_SetWhereStringExpectedIsHealed(t *testing.T) {
	m := newMockRedis(t)
	store := newTestStore(t, m, "")

	id := GenerateSessionId()
	sessionKey := store.sessionKey(id)
	m.putSet(sessionKey, "junk")

	got, err := store.TryGetSession(testLogger(), nil, id)
	if err != nil || got != nil {
		t.Fatalf("TryGetSession over a set = (%+v, %v), want (nil, nil)", got, err)
	}
	if m.setContains(sessionKey, "junk") {
		t.Fatal("the wrong-typed session key was not healed (deleted)")
	}

	if _, err := store.TryGetSession(testLogger(), nil, "unknown"); err != nil {
		t.Fatalf("the breaker opened after a WRONGTYPE GET: %v", err)
	}
}

// A store outage must surface as ErrSessionStoreUnavailable, so the middleware
// can fail closed with a 503 instead of forcing a re-login.
func TestRedisSessionStorage_StoreUnavailable(t *testing.T) {
	store, err := CreateRedisSessionStorage(context.Background(), testLogger(), RedisOptions{
		Endpoints: []string{"127.0.0.1:1"},
		TTL:       time.Minute,
		Secret:    testSecret,
		Timeout:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("CreateRedisSessionStorage: %v", err)
	}
	defer store.Close()

	for i := 0; i < 4; i++ {
		if _, err := store.TryGetSession(testLogger(), nil, "ticket"); !errors.Is(err, ErrSessionStoreUnavailable) {
			t.Fatalf("attempt %d: err = %v, want ErrSessionStoreUnavailable", i, err)
		}
	}
}
