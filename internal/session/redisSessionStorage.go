package session

// Redis-backed session storage.
//
// It reuses the Redis data-plane package of the distributed rate limiter
// (src/internal/redis): RESP client with connection pooling, circuit breaker,
// automatic master discovery through Redis Sentinel, transparent retry on a
// topology change and TLS/mTLS. The session state is stored as one encrypted
// blob, so the Redis content is not readable without the middleware secret.
//
// The session cookie only carries an opaque session id: the tokens never leave
// the server, which removes the ~16 cookie-chunk ceiling of the cookie storage
// and makes the session revocable (back-channel logout).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/MichNG/traefik-keycloak-auth/internal/config"
	"github.com/MichNG/traefik-keycloak-auth/internal/logging"
	"github.com/MichNG/traefik-keycloak-auth/internal/redis"
	"github.com/MichNG/traefik-keycloak-auth/internal/utils"
)

// DefaultKeyPrefix prefixes every Redis key when store.keyPrefix is not set.
const DefaultKeyPrefix = "traefik-keycloak-auth:"

// ErrSessionStoreUnavailable is returned when the session store cannot be
// reached (or is short-circuited by the circuit breaker). The caller can then
// fail closed instead of treating the request as unauthenticated.
var ErrSessionStoreUnavailable = errors.New("session store is unavailable")

// errWrongTypeKey signals that a key holds a value of the wrong Redis type. It
// is a data problem (e.g. a legacy string index where the current build writes
// a set), not a store outage, so it must never open the circuit breaker.
var errWrongTypeKey = errors.New("redis key holds the wrong type")

// minSwitchInterval is the anti-flapping delay of the static endpoint provider.
const minSwitchInterval = time.Second

// RedisTLS is the `store.redis.tls` section.
type RedisTLS struct {
	CABundle           string
	Cert               string
	Key                string
	InsecureSkipVerify bool
}

// RedisSentinel is the `store.redis.sentinel` section.
type RedisSentinel struct {
	MasterSet string
	Username  string
	Password  string
}

// RedisOptions is everything needed to build the session store.
type RedisOptions struct {
	Endpoints []string
	Username  string
	Password  string
	Database  int

	TLS      *RedisTLS
	Sentinel *RedisSentinel

	// KeyPrefix is `store.keyPrefix`.
	KeyPrefix string
	// TTL is the session lifetime (`session.expiry`).
	TTL time.Duration
	// Secret encrypts the stored session blob.
	Secret string

	// Timeout bounds the dial and the commands; PoolSize and MaxActiveConns
	// size the connection pool; IdleTimeout suspends the discovery after that
	// much inactivity (0 disables it).
	Timeout        time.Duration
	PoolSize       int
	MaxActiveConns int
	IdleTimeout    time.Duration
}

// validate checks the options that cannot be silently defaulted.
func (o RedisOptions) validate() error {
	if len(o.Endpoints) == 0 {
		return errors.New("session.store.redis.endpoints is required")
	}
	if o.TTL <= 0 {
		return errors.New("session.expiry must be > 0")
	}
	if len(o.Secret) != 32 {
		return errors.New("the secret must be exactly 32 characters long to encrypt the stored sessions")
	}
	if o.Sentinel != nil && o.Sentinel.MasterSet == "" {
		return errors.New("session.store.redis.sentinel.masterSet is required in Sentinel mode")
	}
	return nil
}

// RedisSessionStorage keeps the sessions in a Redis store (single instance or
// Sentinel).
type RedisSessionStorage struct {
	client  *redis.Client
	prefix  string
	ttl     time.Duration
	secret  string
	breaker *redis.Breaker
	logger  *logging.Logger
}

// CreateRedisSessionStorage builds the storage and starts the (lazy) client.
func CreateRedisSessionStorage(ctx context.Context, logger *logging.Logger, opts RedisOptions) (*RedisSessionStorage, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	var tlsCfg *redis.TLSConfig
	if t := opts.TLS; t != nil && (t.CABundle != "" || t.Cert != "" || t.Key != "" || t.InsecureSkipVerify) {
		tlsCfg = &redis.TLSConfig{
			CA:                 t.CABundle,
			Cert:               t.Cert,
			Key:                t.Key,
			InsecureSkipVerify: t.InsecureSkipVerify,
		}
	}

	var provider redis.NodeProvider

	if opts.Sentinel != nil {
		tlsClientConfig, err := tlsCfg.CreateTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("invalid store.redis.tls configuration: %w", err)
		}

		resolver, err := redis.NewSentinelResolver(redis.SentinelConfig{
			Endpoints:   opts.Endpoints,
			MasterSet:   opts.Sentinel.MasterSet,
			Username:    opts.Sentinel.Username,
			Password:    opts.Sentinel.Password,
			DialTimeout: timeout,
			ReadTimeout: timeout,
		}, &redis.Dialer{TLS: tlsClientConfig, DialTimeout: timeout}, redisLogger{logger})
		if err != nil {
			return nil, fmt.Errorf("configuring Redis Sentinel: %w", err)
		}

		sentinelProvider, err := redis.NewSentinelProvider(resolver, true)
		if err != nil {
			return nil, err
		}

		logger.Log(logging.LevelInfo, "Session store: Redis Sentinel, master set %q, endpoints %v", opts.Sentinel.MasterSet, opts.Endpoints)

		provider = sentinelProvider
	} else {
		staticProvider, err := redis.NewStaticProvider(opts.Endpoints, minSwitchInterval)
		if err != nil {
			return nil, err
		}
		provider = staticProvider

		logger.Log(logging.LevelInfo, "Session store: Redis, endpoints %v", opts.Endpoints)
	}

	client, err := redis.NewClient(ctx, redis.ClientConfig{
		Username:       opts.Username,
		Password:       opts.Password,
		Database:       opts.Database,
		ConnectTimeout: timeout,
		CommandTimeout: timeout,
		PoolSize:       opts.PoolSize,
		MaxActiveConns: opts.MaxActiveConns,
		IdleTimeout:    opts.IdleTimeout,
	}, tlsCfg, provider, redisLogger{logger})
	if err != nil {
		return nil, err
	}

	prefix := opts.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}

	return &RedisSessionStorage{
		client:  client,
		prefix:  prefix,
		ttl:     opts.TTL,
		secret:  opts.Secret,
		breaker: redis.NewBreaker(redis.BreakerConfig{}),
		logger:  logger,
	}, nil
}

// logHealedWrongType reports that a key holding the wrong Redis type was
// dropped. It is a data anomaly (e.g. a legacy index), so the operator must be
// able to see it even though the request itself succeeds.
func (s *RedisSessionStorage) logHealedWrongType(key string) {
	if s.logger == nil {
		return
	}
	s.logger.Log(logging.LevelWarn, "Dropped the Redis key %q: it held the wrong data type (legacy or corrupt index)", key)
}

// StoreSession implements SessionStorage. The returned ticket is the session
// id, which is what the session cookie carries.
func (s *RedisSessionStorage) StoreSession(logger *logging.Logger, cfg *config.Config, sessionId string, state *SessionState) (string, error) {
	if sessionId == "" {
		return "", errors.New("cannot store a session without an id")
	}

	raw, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	encrypted, err := utils.Encrypt(string(raw), s.secret)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.commandTimeout())
	defer cancel()

	if err := s.set(ctx, s.sessionKey(sessionId), encrypted); err != nil {
		return "", err
	}

	// Secondary indexes make the session revocable from a back-channel logout
	// token, which only carries the OIDC sid and sub. The sid identifies one
	// session; the sub may own several (multiple logins of the same user), so
	// the sub index holds a list of session ids.
	if state.OidcSid != "" {
		if err := s.set(ctx, s.indexKey("sid", state.OidcSid), sessionId); err != nil {
			logger.Log(logging.LevelError, "Failed to write the sid index: %s", err.Error())
		}
	}
	if state.Sub != "" {
		if err := s.addToSet(ctx, s.indexKey("sub", state.Sub), sessionId); err != nil {
			logger.Log(logging.LevelError, "Failed to write the sub index: %s", err.Error())
		}
	}

	return sessionId, nil
}

// TryGetSession implements SessionStorage. A missing session returns nil, nil.
func (s *RedisSessionStorage) TryGetSession(logger *logging.Logger, cfg *config.Config, sessionTicket string) (*SessionState, error) {
	if sessionTicket == "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.commandTimeout())
	defer cancel()

	stored, found, err := s.get(ctx, s.sessionKey(sessionTicket))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	plain, err := utils.Decrypt(stored, s.secret)
	if err != nil {
		logger.Log(logging.LevelError, "Failed to decrypt the stored session: %s", err.Error())
		return nil, err
	}

	state := &SessionState{}
	if err := json.Unmarshal([]byte(plain), state); err != nil {
		return nil, err
	}

	return state, nil
}

// RevokeBySid deletes the session whose OIDC sid matches, if any. It returns
// the number of sessions removed.
func (s *RedisSessionStorage) RevokeBySid(sid string) (int, error) {
	return s.revokeIndexOf("sid", sid)
}

// RevokeBySub deletes every session whose OIDC sub matches.
func (s *RedisSessionStorage) RevokeBySub(sub string) (int, error) {
	if sub == "" {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.commandTimeout())
	defer cancel()

	indexKey := s.indexKey("sub", sub)
	members, err := s.setMembers(ctx, indexKey)
	if err != nil {
		return 0, err
	}

	revoked := 0
	for _, sessionId := range members {
		sessionId = strings.TrimSpace(sessionId)
		if sessionId == "" {
			continue
		}

		// Drop the sid index of the session too, so a later logout by sid
		// cannot resurrect a stale pointer.
		if state := s.loadSession(ctx, sessionId); state != nil && state.OidcSid != "" {
			_ = s.exec(ctx, "DEL", s.indexKey("sid", state.OidcSid))
		}

		if err := s.exec(ctx, "DEL", s.sessionKey(sessionId)); err != nil {
			return revoked, err
		}
		revoked++
	}

	if err := s.exec(ctx, "DEL", indexKey); err != nil {
		return revoked, err
	}

	return revoked, nil
}

// addToSet adds a session id to a Redis set (atomic, unlike a GET/SET
// read-modify-write) and refreshes its TTL.
func (s *RedisSessionStorage) addToSet(ctx context.Context, key, sessionId string) error {
	err := s.execData(ctx, "SADD", key, sessionId)
	if errors.Is(err, errWrongTypeKey) {
		// A legacy build stored a string where this build keeps a set. Drop the
		// stale key and retry once: healing the index is preferable to tripping
		// the shared breaker (which would 503 every user) and to silently
		// leaving the session unindexed.
		s.logHealedWrongType(key)
		if delErr := s.exec(ctx, "DEL", key); delErr != nil {
			return delErr
		}
		err = s.execData(ctx, "SADD", key, sessionId)
	}
	if err != nil {
		return err
	}
	return s.exec(ctx, "EXPIRE", key, strconv.Itoa(int(s.ttl.Seconds())))
}

// removeFromSet removes a session id from an index set. A legacy string index
// cannot contain set members: dropping the stale key is the correct removal and
// must not count as a store failure.
func (s *RedisSessionStorage) removeFromSet(ctx context.Context, key, sessionId string) error {
	err := s.execData(ctx, "SREM", key, sessionId)
	if errors.Is(err, errWrongTypeKey) {
		s.logHealedWrongType(key)
		return s.exec(ctx, "DEL", key)
	}
	return err
}

// setMembers returns the members of a Redis set.
func (s *RedisSessionStorage) setMembers(ctx context.Context, key string) ([]string, error) {
	if !s.breaker.Allow() {
		return nil, ErrSessionStoreUnavailable
	}

	reply, err := s.client.Do(ctx, "SMEMBERS", key)
	if err != nil {
		if isWrongTypeError(err) {
			// A legacy string index (written by an older build) is a data
			// problem, not a store outage: heal it instead of opening the
			// breaker for every user.
			s.logHealedWrongType(key)
			_, _ = s.client.Do(ctx, "DEL", key)
			s.breaker.Success()
			return nil, nil
		}
		s.noteFailure(err)
		return nil, fmt.Errorf("%w: %v", ErrSessionStoreUnavailable, err)
	}

	s.breaker.Success()

	items := reply.Array()
	members := make([]string, 0, len(items))
	for i := 0; i < len(items); i++ {
		members = append(members, items[i].String())
	}

	return members, nil
}

// loadSession reads and decrypts a session without logging (used by the
// revocation paths, which have no logger at hand).
func (s *RedisSessionStorage) loadSession(ctx context.Context, sessionId string) *SessionState {
	stored, found, err := s.get(ctx, s.sessionKey(sessionId))
	if err != nil || !found {
		return nil
	}

	plain, err := utils.Decrypt(stored, s.secret)
	if err != nil {
		return nil
	}

	state := &SessionState{}
	if err := json.Unmarshal([]byte(plain), state); err != nil {
		return nil
	}
	return state
}

func (s *RedisSessionStorage) revokeIndexOf(kind, value string) (int, error) {
	if value == "" {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.commandTimeout())
	defer cancel()

	indexKey := s.indexKey(kind, value)
	sessionId, found, err := s.get(ctx, indexKey)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}

	if state := s.loadSession(ctx, sessionId); state != nil && state.Sub != "" {
		_ = s.removeFromSet(ctx, s.indexKey("sub", state.Sub), sessionId)
	}

	if err := s.exec(ctx, "DEL", s.sessionKey(sessionId)); err != nil {
		return 0, err
	}
	if err := s.exec(ctx, "DEL", indexKey); err != nil {
		return 0, err
	}

	return 1, nil
}

// Node returns the Redis node currently in use, for logging.
func (s *RedisSessionStorage) Node() string { return s.client.Node() }

// Close releases the client resources. It is idempotent.
func (s *RedisSessionStorage) Close() { s.client.Close() }

// isTopologyChangeError reports a server reply showing that the node answered
// but is no longer the master (a Sentinel failover is in progress). Unlike
// redis.IsMasterFailoverError it deliberately excludes transport failures: a
// connection error means the store really is unreachable and must still feed
// the breaker.
func isTopologyChangeError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToUpper(err.Error())
	for _, marker := range []string{"READONLY", "MASTERDOWN", "LOADING"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}

	return false
}

// noteFailure records a command failure for the breaker. A topology change is
// not an outage -- the provider is already re-resolving the master -- so it
// must not open the shared breaker: otherwise a single failover would 503 the
// read path as well, for the whole breaker window.
func (s *RedisSessionStorage) noteFailure(err error) {
	if isTopologyChangeError(err) {
		s.breaker.Success()
		return
	}
	s.breaker.Failure()
}

// exec runs a command through the circuit breaker. A failure opens the breaker
// after a few attempts, so a Redis outage does not turn every request into a
// multi-second wait.
func (s *RedisSessionStorage) exec(ctx context.Context, args ...string) error {
	if !s.breaker.Allow() {
		return ErrSessionStoreUnavailable
	}

	if _, err := s.client.Do(ctx, args...); err != nil {
		s.noteFailure(err)
		return fmt.Errorf("%w: %v", ErrSessionStoreUnavailable, err)
	}

	s.breaker.Success()
	return nil
}

// execData is like exec but distinguishes a wrong-type reply from an outage:
// the former is returned as errWrongTypeKey and leaves the breaker untouched.
func (s *RedisSessionStorage) execData(ctx context.Context, args ...string) error {
	if !s.breaker.Allow() {
		return ErrSessionStoreUnavailable
	}

	_, err := s.client.Do(ctx, args...)
	if err != nil {
		if isWrongTypeError(err) {
			s.breaker.Success()
			return fmt.Errorf("%w: %v", errWrongTypeKey, err)
		}
		s.noteFailure(err)
		return fmt.Errorf("%w: %v", ErrSessionStoreUnavailable, err)
	}

	s.breaker.Success()
	return nil
}

func (s *RedisSessionStorage) set(ctx context.Context, key, value string) error {
	return s.exec(ctx, "SET", key, value, "EX", strconv.Itoa(int(s.ttl.Seconds())))
}

// get runs GET through the breaker and returns (value, found, error).
func (s *RedisSessionStorage) get(ctx context.Context, key string) (string, bool, error) {
	if !s.breaker.Allow() {
		return "", false, ErrSessionStoreUnavailable
	}

	reply, err := s.client.Do(ctx, "GET", key)
	if err != nil {
		if isWrongTypeError(err) {
			// e.g. a set stored where a string is expected: heal the key and
			// treat it as absent instead of failing the request.
			s.logHealedWrongType(key)
			_, _ = s.client.Do(ctx, "DEL", key)
			s.breaker.Success()
			return "", false, nil
		}
		s.noteFailure(err)
		return "", false, fmt.Errorf("%w: %v", ErrSessionStoreUnavailable, err)
	}

	s.breaker.Success()

	if reply.IsNil() {
		return "", false, nil
	}
	return reply.String(), true, nil
}

func (s *RedisSessionStorage) commandTimeout() time.Duration {
	if s.ttl > 0 && s.ttl < time.Second {
		return s.ttl
	}
	return 2 * time.Second
}

func (s *RedisSessionStorage) sessionKey(sessionId string) string {
	return s.prefix + "session:" + sessionId
}

func (s *RedisSessionStorage) indexKey(kind, value string) string {
	return s.prefix + kind + ":" + value
}

// redisLogger adapts the plugin logger to the redis package seam.
type redisLogger struct {
	logger *logging.Logger
}

func (l redisLogger) Logf(format string, args ...interface{}) {
	if l.logger == nil {
		return
	}
	l.logger.Log(logging.LevelDebug, format, args...)
}

// ensure the storage satisfies the interface at compile time.
var _ SessionStorage = (*RedisSessionStorage)(nil)

// isWrongTypeError reports a Redis WRONGTYPE reply: the key exists with another
// data type. It is a data problem, not an outage, and must not open the breaker.
func isWrongTypeError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "WRONGTYPE")
}
