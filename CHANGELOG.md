# Changelog

## 1.0.2

* **Connection pool defaults**: the idle pool is now as large as the connection
  cap (was 5) instead of a fixed small value. A smaller idle pool closes
  connections under concurrency and re-dials them, which churns through the
  ephemeral ports until `connect: cannot assign requested address` opens the
  circuit breaker and the session store answers 503 (measured upstream in
  `traefik-distributed-rate-limit`, `docs/16-benchmark-p99.md`). Covered by
  `TestClientConfigDefaultsKeepIdleCapacity`.
* README: the Redis option table no longer lists connection options that the Hub
  OpenID Connect reference does not define; the data plane defaults are
  documented instead.

## 1.0.1

* **Readable store errors under Yaegi**: a RESP error reply is a concrete
  interpreted type, so formatting it with `%w` through the interpreter rendered
  `%!w(stdlib._fmt_Stringer=...)` instead of the server message. The Redis and
  Sentinel error paths (AUTH, `SELECT`, `SCRIPT LOAD`, Sentinel authentication,
  `SENTINEL get-master-addr-by-name`, `SUBSCRIBE`) now carry the real message
  (for instance `WRONGPASS invalid username-password pair`), which matters most
  when a deployment has the wrong credentials or a missing ACL user.
* `make yaegi-check` gained a guard for it (a mock Redis that fails `AUTH`) and
  `TestAuthenticationErrorIsReadable` covers the message content in Go.

## 1.0.0

Initial release of `traefik-keycloak-auth`, a standalone Traefik middleware
plugin: an OpenID Connect relying party for Keycloak.

* authorization code flow with optional PKCE, the Traefik Hub OpenID Connect
  Authentication configuration schema (`issuer`, `redirectUrl`,
  `clientID`/`clientSecret`, `claims`, `forwardHeaders`, `forwardIDTokenHeader`,
  `usernameClaim`, `clientConfig.*`, `authParams`, `discoveryParams`,
  `trustedIssuer`, `stateCookie.*`, `session.*`, `csrf`) and an explicit
  rejection of `session.store.redis.cluster`;
* `claims` expression language (`Equals`, `Prefix`, `Contains`, `SplitContains`,
  `OneOf`, `&&`, `||`, `!`, `id_token.`/`access_token.` prefixes, nested keys),
  with Keycloak access tokens parsed without an audience check;
* sessions in a chunked cookie (default) or **server-side in Redis** (single
  instance, endpoint list, **Redis Sentinel** with automatic master discovery
  and failover handling), encrypted with AES-256-GCM and revocable through
  `sid`/`sub` indexes;
* **back-channel logout** (OpenID Connect Back-Channel Logout 1.0): the Keycloak
  logout token revokes the sessions server-side;
* CSRF protection (signed double-submit cookie) and upstream header forwarding;
* stdlib-only runtime (required by Traefik's Yaegi interpreter), vendored
  third-party modules and `make yaegi-check` to catch interpreter
  incompatibilities before a release;
* Docker end-to-end test against a real Keycloak + Redis Sentinel (24 checks).
