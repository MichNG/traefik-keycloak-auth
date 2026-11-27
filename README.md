# traefik-keycloak-auth

[![CI](https://github.com/MichNG/traefik-keycloak-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/MichNG/traefik-keycloak-auth/actions/workflows/ci.yml) [![E2E](https://github.com/MichNG/traefik-keycloak-auth/actions/workflows/e2e.yml/badge.svg)](https://github.com/MichNG/traefik-keycloak-auth/actions/workflows/e2e.yml)

`github.com/MichNG/traefik-keycloak-auth` - a Traefik middleware plugin that
protects an upstream service with **OpenID Connect** (authorization code flow,
optional PKCE, Keycloak-tested), following the
[Traefik Hub OpenID Connect Authentication](https://doc.traefik.io/traefik-hub/api-gateway/reference/routing/http/middlewares/ref-oidc)
configuration schema.

Standalone project: module path and plugin name are its own.

Traefik OSS has no OIDC middleware (only `basicAuth`, `digestAuth`, `forwardAuth`);
this plugin implements the Hub schema for a **Keycloak** deployment and keeps the
sessions **server-side in Redis**, so a session can be revoked by a Keycloak
back-channel logout instead of living in a 4 KB cookie.

Supported session stores:

* **cookie** (default): the session is chunked across cookies, like the reference;
* **Redis** (single instance, endpoint list, or **Redis Sentinel** with automatic
  master discovery and failover handled without a 5xx on the data path), reusing
  the RESP data plane of
  [`MichNG/traefik-distributed-rate-limit`](https://github.com/MichNG/traefik-distributed-rate-limit)
  (`internal/redis`): connection pooling, circuit breaker, TLS/mTLS;
* **back-channel logout** (OpenID Connect Back-Channel Logout 1.0): the logout
  token sent by Keycloak revokes the session server-side (`sid` and `sub` indexes).

> **Redis Cluster** is not supported: configuring `session.store.redis.cluster`
> ("Enable Redis Cluster") fails the middleware creation with an explicit message.

## Installation

```yaml
# Static configuration
experimental:
  plugins:
    traefik-keycloak-auth:
      moduleName: "github.com/MichNG/traefik-keycloak-auth"
      version: "v1.0.1"
```

The plugin is a public repository with the `traefik-plugin` topic, a root
`.traefik.yml`, a root `go.mod`, vendored dependencies and a `v1.0.0` tag: it is
therefore eligible for the [Traefik Plugin Catalog](https://plugins.traefik.io/plugins),
which polls GitHub once a day (nothing to submit; a plugin is fetched from the Go
module proxy by tag).

Until the crawler has indexed this repository, `experimental.plugins` answers
`Unknown plugin: github.com/MichNG/traefik-keycloak-auth@v1.0.0`; use
`localPlugins` in the meantime.

For local development, mount the plugin directory and use `localPlugins`:

```yaml
experimental:
  localPlugins:
    traefik-keycloak-auth:
      moduleName: github.com/MichNG/traefik-keycloak-auth
```

## Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: keycloak-oidc
  namespace: traefik
spec:
  plugin:
    traefik-keycloak-auth:
      issuer: "https://keycloak.example.com/realms/myrealm"
      redirectUrl: "/callback"
      clientID: "traefik"
      clientSecret: "${CLIENT_SECRET}"
      secret: "${OIDC_SECRET}"          # 32 chars: encrypts the state and the sessions
      scopes: ["openid", "profile", "email"]
      pkce: true
      usernameClaim: preferred_username
      forwardHeaders:
        X-Auth-User: preferred_username
        X-Auth-Roles: realm_access.roles
      claims: "OneOf(`access_token.realm_access.roles`, `admin`)"
      loginUrl: "/login"
      logoutUrl: "/logout"
      backchannelLogoutUrl: "/backchannel-logout"
      session:
        expiry: 3600
        sliding: true
        refresh: true
        store:
          redis:
            endpoints: ["sentinel-0:26379", "sentinel-1:26379", "sentinel-2:26379"]
            sentinel:
              masterSet: mymaster
      csrf:
        headerName: "Hub-Csrf-Token"
```

A complete runnable pair of files is in
[`example/`](example/) (`traefik.yaml` + `dynamic.yaml` for the Sentinel store,
`dynamic-cookie.yaml` for the cookie store).

### Options

| Field | Description | Default |
| :--- | :--- | :--- |
| `issuer` | Issuer URL of the realm; the discovery document is fetched from `<issuer>/.well-known/openid-configuration`. | — (required) |
| `redirectUrl` | Callback path registered in Keycloak. | — (required) |
| `clientID` | OIDC client id. | — (required) |
| `clientSecret` | OIDC client secret. `$ENV_VAR` is expanded from the environment. | `""` |
| `secret` | 32-character secret used to encrypt the `state`, the browser binding and the stored sessions. | — (required) |
| `scopes` | Scopes requested at the authorization endpoint. | `["openid", "profile", "email"]` |
| `pkce` | Use PKCE (`S256`) for the authorization code flow. | `false` |
| `claims` | Authorization expression over the ID/access token claims (`Equals`, `Prefix`, `Contains`, `SplitContains`, `OneOf`, `&&`, `\|\|`, `!`, `id_token.`/`access_token.` prefixes). | `""` (no check) |
| `forwardHeaders` | Claims copied to upstream request headers (`X-Auth-User: preferred_username`). A missing claim removes the header. | — |
| `forwardIDTokenHeader` | Header receiving the raw ID token. | `""` |
| `forwardAccessToken` | Forward the access token as `Authorization: Bearer …` for an **authorized** session (never for an unauthorized one). | `false` |
| `usernameClaim` / `identity` | Claim used for logging the authenticated user / the caller identity. | `preferred_username` / `sub` |
| `loginUrl` / `logoutUrl` | Paths handled by the plugin (exact path or sub-path). | `/login` / `/logout` |
| `postLoginRedirectUrl` / `postLogoutRedirectUrl` | Redirect targets after login/logout. | `"/"` |
| `validPostLoginRedirectUris` / `validPostLogoutRedirectUris` | Extra allowed redirect targets (same-origin is always allowed). | — |
| `disableLogin` | Do not expose the login route (e.g. when another component starts the flow). | `false` |
| `authParams` | Extra query parameters sent to the authorization endpoint. | — |
| `discoveryParams` | Extra query parameters used for the discovery request. | — |
| `trustedIssuer` / `disableIssuerCheck` | Expected issuer when it differs from the discovery `issuer` / skip the comparison. | `""` / `false` |
| `clientConfig.*` | Private key JWT (`private_key_jwt`) client authentication, timeout/retries and TLS to the OIDC provider (`tls.ca`, `tls.cert`, `tls.key`, `tls.insecureSkipVerify`, path or PEM). | — |
| `backchannelLogoutUrl` | Path receiving the Keycloak back-channel logout token. | `""` (disabled) |
| `backchannelLogoutSessionsRequired` | Require a valid `sid`/`sub` to revoke at least one session. | `false` |
| `stateCookie.*` | `name`, `path`, `domain`, `secure`, `httpOnly`, `sameSite`, `maxAge` of the browser binding cookie. | `maxAge` `600` |
| `session.expiry` | Session lifetime in seconds. | `86400` |
| `session.maxAge` | Absolute lifetime of the end-user authentication (independent of the activity). | `0` (unbounded) |
| `session.sliding` | Renew the session on every authenticated request. A failed renewal is logged, never fatal. | `true` |
| `session.refresh` | Refresh the tokens with the refresh token when they expire. | `true` |
| `session.store.redis.endpoints` | Redis endpoints (or the Sentinel endpoints in Sentinel mode). | — (required) |
| `session.store.redis.username` / `.password` | Redis ACL credentials. `$ENV_VAR` is expanded from the environment. | `""` |
| `session.store.redis.database` | Database index (also valid in Sentinel mode). | `0` |
| `session.store.redis.timeout` | Timeout applied to dial, read and write operations. | `2s` |
| `session.store.redis.poolSize` / `.maxActiveConns` | Idle connections kept per node / hard cap of opened connections. | `5` / `10 * GOMAXPROCS` |
| `session.store.redis.idleTimeout` | Suspend the discovery and close the idle connections after that much inactivity (`0` disables it). | `0` |
| `session.store.redis.sentinel.masterSet` | Name of the Sentinel master set. | — (required with Sentinel) |
| `session.store.redis.sentinel.username` / `.password` | Credentials for the Sentinels themselves (may differ from the data-plane ones). | `""` |
| `session.store.redis.tls.caBundle` | CA bundle used to verify Redis **and** the Sentinels: a file path **or** the PEM content itself. The system bundle is used when empty. | `""` |
| `session.store.redis.tls.cert` | Client certificate (mTLS): a file path **or** the PEM content. Must be set together with `key`. | `""` |
| `session.store.redis.tls.key` | Client private key (mTLS): a file path **or** the PEM content. Must be set together with `cert`. | `""` |
| `session.store.redis.tls.insecureSkipVerify` | Skip the verification of the server certificate (development only). | `false` |
| `store.keyPrefix` | Prefix of the Redis keys. | `traefik-keycloak-auth:` |
| `csrf` | Signed double-submit cookie CSRF protection (`headerName`, `cookieName`, `secret`, `secure`, `sameSite`). | disabled |
| `unauthorizedBehavior` | `Unauthorized` (401) or `Forward` (let the request reach the backend unauthenticated). | `Unauthorized` |
| `session.store.redis.cluster` | **Rejected**: Redis Cluster is not supported. | — |

### Redis connections under `store.redis.*`

The whole Redis section is accepted both nested (`session.store.redis.*` and
`store.redis.*`) and in the flat form; when both are present, `session.store.*`
wins. The same TLS semantics apply to the data plane and to the Sentinels.

## TLS to Redis and to the Sentinels

`store.redis.tls` (or `session.store.redis.tls`) secures every connection the
plugin opens — the Redis data plane **and** the Sentinel connections used to
discover the master:

* `caBundle` — the CA bundle used to verify the server: either a **file path** or
  the **PEM content** itself (the same value- or file-based semantics as Traefik
  OSS `tls.ca`). When it is empty, the system bundle is used;
* `cert` + `key` — client certificate and key for mutual TLS (mTLS), each a file
  path or inline PEM; setting only one of them is an error;
* `insecureSkipVerify` — disables the server certificate verification. For local
  development only;
* `$ENV_VAR` references are expanded in all three string fields, so the key
  material can stay out of the configuration file.

```yaml
# custom CA + mTLS, for a Redis (or Sentinel) endpoint that checks the client
session:
  store:
    redis:
      endpoints: ["sentinel-0:26379", "sentinel-1:26379", "sentinel-2:26379"]
      sentinel:
        masterSet: mymaster
      tls:
        caBundle: "/etc/ssl/certs/redis-ca.pem"   # or the PEM content itself
        cert: "${REDIS_CLIENT_CERT_PEM}"          # or a file path
        key: "${REDIS_CLIENT_KEY_PEM}"            # or a file path
```

```yaml
# TLS without a custom CA (public/Let's Encrypt certificate)
    tls:
      insecureSkipVerify: false
```

```yaml
# development against a self-signed certificate
    tls:
      insecureSkipVerify: true
```

The connections to the **OIDC provider** are configured separately, with the same
path-or-PEM semantics, under `clientConfig.tls`
(`ca`, `cert`, `key`, `insecureSkipVerify`):

```yaml
clientConfig:
  tls:
    ca: "/etc/ssl/certs/keycloak-ca.pem"
    insecureSkipVerify: false
```

## Redis Sentinel

With `session.store.redis.sentinel.masterSet` the master is discovered through the
Sentinels and followed on a failover: a topology change (`READONLY`/`MASTERDOWN`)
is retried on the new master and never trips the circuit breaker, so a failover
does not take the read path down. Session keys are indexed by `sid` and `sub`
(Redis sets), which is what makes the back-channel logout able to revoke every
session of a user.

## Lifecycle and behavior on errors

* the discovery document, the JWKS and the Redis client are created lazily on the
  first request and released when Traefik retires the middleware instance;
* a session store **read** failure fails closed with `503` (it is neither an
  unauthenticated request nor an internal error);
* a **write** failure on the login/callback path also fails closed with `503`
  (a cookie pointing at a non-existent session would loop through the login);
* a write failure on the sliding renewal is only a warning: the request is served
  with the session that was just validated;
* the CSRF, session and browser-binding cookies are removed from the request
  before it reaches the upstream.

## Yaegi constraints

Traefik loads plugins with the Yaegi interpreter (v0.16.1), which is stricter
than the Go compiler. The plugin therefore:

* uses only the standard library at runtime (third-party modules are vendored for
  the Go build, and Yaegi resolves them from `vendor/`);
* avoids custom `http.RoundTripper` values, closures stored in variables, tagless
  `switch` with parallel assignment and named `jwt.MapClaims` type assertions;
* never formats a RESP error reply with `%w`: the reply is a concrete interpreted
  type, so the interpreter's `fmt` renders `%!w(stdlib._fmt_Stringer=...)` instead
  of the server message; `redisError()` passes the text explicitly;
* converts the JWT claim maps through `encoding/json` before evaluating a `claims`
  expression.

`make yaegi-check` loads the plugin with the same interpreter and fails on a
regression.

## Development

```bash
make test-race                    # gofmt + go vet + unit tests (-race)
make yaegi-check                  # Yaegi compatibility check
make integration                  # Keycloak + Redis Sentinel end-to-end (Docker)
make integration-down             # tear the stack down
```

CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `gofmt`, `go vet`,
`go test -race ./...` and the Yaegi check on every push and pull request; the
end-to-end stack is run by [`.github/workflows/e2e.yml`](.github/workflows/e2e.yml)
(manual `workflow_dispatch` and a weekly schedule). Dependencies are kept up to
date by [Dependabot](.github/dependabot.yml) (run `make vendor` after merging a
runtime dependency update).

The end-to-end stack ([`docker-compose.yaml`](docker-compose.yaml)) runs a real
Keycloak (26.2.5, realm `myrealm`), a Redis master/replica with three Sentinels,
Traefik 3.5 loading this working copy as a `localPlugins`, a `whoami` upstream and
an `alpine` tester that drives
[`docker/e2e.sh`](docker/e2e.sh) (24 checks: authorization code + PKCE, forwarded
headers, Redis session, CSRF, back-channel logout, Sentinel failover, cookie
middleware).

## Migration from `traefik-oidc-auth`

The project was renamed; see [`docs/MIGRATION.md`](docs/MIGRATION.md) for the
mapping of the module path, the plugin name, the configuration package and the
Redis key prefix.

## Credits

* [Traefik Hub OpenID Connect Authentication](https://doc.traefik.io/traefik-hub/api-gateway/reference/routing/http/middlewares/ref-oidc)
  — the configuration schema this plugin implements;
* [`MichNG/traefik-distributed-rate-limit`](https://github.com/MichNG/traefik-distributed-rate-limit)
  — the Redis/Sentinel data plane (`internal/redis`) and the Yaegi check tooling;
* [Traefik](https://github.com/traefik/traefik) — the plugin subsystem
  (`pkg/plugins`) and the auth middlewares used as a reference.
