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

Every option of the reference is listed here with the value this plugin applies.
Rows marked **extension** do not exist in the reference (they exist because a
middleware plugin has no Hub control plane, or to expose a behaviour the
reference hard-codes). `store.redis.*` is accepted as a synonym of
`session.store.redis.*` (the reference spells `store.keyPrefix` at the top level
and the Redis connection inside `session.store`) and the flat spelling wins when
both are present.

| Field | Description | Default |
| :--- | :--- | :--- |
| `issuer` | Issuer URL; the discovery document is fetched from `<issuer>/.well-known/openid-configuration`. | — (required) |
| `redirectUrl` | Callback path registered in the provider. | — (required) |
| `clientID` | OIDC client id. | — (required) |
| `clientSecret` | OIDC client secret. `$ENV_VAR` is expanded. | `""` |
| `secret` | **extension**: 32-character secret that encrypts the `state`, the browser binding and the stored sessions (Hub injects its own). | — (required) |
| `scopes` | Scopes requested at the authorization endpoint. | `["openid"]` |
| `pkce` | Use PKCE (`S256`) for the authorization code flow. | `false` |
| `loginUrl` / `logoutUrl` | Paths handled by the plugin (exact path or sub-path). | `/login` / `/logout` |
| `postLoginRedirectUrl` / `postLogoutRedirectUrl` | Redirect targets after login/logout. | `"/"` |
| `validPostLoginRedirectUris` / `validPostLogoutRedirectUris` | Extra allowed redirect targets; a same-origin URL is always allowed. | — |
| `allowRedirectUriWildcards` | **extension**: allow `*` in the redirect lists for this middleware instead of the process-wide `TOA_ENABLE_REDIRECT_URI_WILDCARDS`. | `false` |
| `disableLogin` | Do not expose the login route (another component starts the flow); unauthenticated requests then get a `401` instead of a redirect. | `false` |
| `trustedIssuer` / `disableIssuerCheck` | Expected issuer when it differs from the discovery `issuer` / skip the comparison. | `""` / `false` |
| `discoveryParams` | Extra query parameters for the discovery request. | — |
| `authParams` | Extra query parameters for the authorization request. | — |
| `claims` | Authorization expression (`Equals`, `Prefix`, `Contains`, `SplitContains`, `OneOf`, `&&`, `\|\|`, `!`, `id_token.`/`access_token.` prefixes). | `""` (no check) |
| `forwardHeaders` | Claim copied to an upstream header (`X-Auth-User: preferred_username`); a missing claim removes the header. | — |
| `forwardIDTokenHeader` | Header receiving the raw ID token. | `""` |
| `forwardAccessToken` | **extension**: forward the access token as `Authorization: Bearer …` for an authorized session. | `false` |
| `usernameClaim` | Claim used to log the authenticated user. | `preferred_username` |
| `identity` | Claim used as the caller identity in the logs (Hub uses it to partition its cache). | `sub` |
| `headers` | **extension**: upstream headers rendered from a Go template over the claims (`name`, `value`, `values`, `includeWhen`). | — |
| `logLevel` | **extension**: `TRACE`, `DEBUG`, `INFO`, `WARN` or `ERROR`. | `INFO` |
| `tokenValidation` | **extension**: token verified on each request: `IdToken`, `AccessToken` or `Introspection`. | `IdToken` |
| `tokenRenewalThreshold` | **extension**: fraction of the token lifetime after which a proactive refresh is attempted (0.5–1.0). | `0.75` |
| `useClaimsFromUserInfo` | **extension**: merge the UserInfo claims into the token claims. | `false` |
| `clientConfig.timeoutSeconds` | Time before giving up a request to the provider. | `5` |
| `clientConfig.maxRetries` | Retries for failing provider requests. | `3` |
| `clientConfig.tls.ca` | CA bundle for the provider connection: a file path or the PEM content. | `""` |
| `clientConfig.tls.cert` / `.key` | Client certificate and key (mTLS) to the provider: path or PEM; both are required together. | `""` |
| `clientConfig.tls.insecureSkipVerify` | Skip the provider certificate verification (development only). | `false` |
| `backchannelLogoutUrl` | Path receiving the back-channel logout token. | `""` (disabled) |
| `backchannelLogoutSessionsRequired` | Require a valid `sid`/`sub` to revoke at least one session. | `false` |
| `stateCookie.name` / `.path` / `.domain` / `.maxAge` / `.sameSite` / `.httpOnly` / `.secure` | Browser binding cookie of the login flow. | `toa-state` / `/` / `""` / `600` / `lax` / `true` / `false` |
| `session.name` | Name of the session cookie. | `toa-session` |
| `session.path` / `.domain` | Scope of the session cookie. | `/` / `""` |
| `session.expiry` | Session lifetime, in seconds. | `86400` |
| `session.maxAge` | Absolute lifetime of the end-user authentication, independent of the activity (`0` = unbounded). | `0` |
| `session.sliding` | Renew the session on every authenticated request; a failed renewal is logged, never fatal. | `true` |
| `session.refresh` | Refresh the tokens with the refresh token when they expire. | `true` |
| `session.sameSite` / `.httpOnly` / `.secure` | Flags of the session cookie. | `lax` / `true` / `false` |
| `session.store.redis.endpoints` | Redis endpoints, or the Sentinel endpoints in Sentinel mode. | — (cookie storage when unset) |
| `session.store.redis.username` / `.password` | Credentials of the data plane. `$ENV_VAR` is expanded. | `""` |
| `session.store.redis.database` | Database index (also in Sentinel mode). | `0` |
| `session.store.redis.sentinel.masterSet` | Name of the Sentinel master set. | — (required with Sentinel) |
| `session.store.redis.sentinel.username` / `.password` | Credentials for the Sentinels themselves (may differ from the data-plane ones). | `""` |
| `session.store.redis.tls.caBundle` | CA bundle used to verify Redis **and** the Sentinels: a file path or the PEM content; the system bundle is used when empty. | `""` |
| `session.store.redis.tls.cert` / `.key` | Client certificate and key (mTLS) to Redis and the Sentinels: path or PEM; both are required together. | `""` |
| `session.store.redis.tls.insecureSkipVerify` | Skip the Redis/Sentinel certificate verification (development only). | `false` |
| `store.keyPrefix` | Prefix of the Redis session keys. | `traefik-keycloak-auth:` |
| `csrf.secure` | Send the CSRF cookie only over HTTPS. | `false` |
| `csrf.headerName` | Header carrying the CSRF token. | `Hub-Csrf-Token` |
| `session.store.redis.cluster` (also `store.redis.cluster`) | **Rejected**: Redis Cluster is not supported; configuring it fails the middleware creation. | — |

The reference exposes no timeout or connection-pool option for the session store,
so the data plane applies its own defaults: **dial 5 s**, **command 3 s**, an
**idle pool as large as the connection cap**, and a connection cap of
**10 × GOMAXPROCS**. The idle pool is deliberately not smaller than the cap: a
smaller one closes connections under concurrency and re-dials them, which churns
through the ephemeral ports and ends in an open circuit breaker (measured upstream
in [`traefik-distributed-rate-limit`](https://github.com/MichNG/traefik-distributed-rate-limit)).

Every option, and every variant of it, has a runnable example under
[`example/options/`](example/options/README.md); the examples are loaded by a real
Traefik by the end-to-end stack (`make integration`).

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
* is not the only source of surprises with templates: Traefik renders the
  configuration of its *file* provider as a Go template, so `headers` values with
  a double-brace expression never reach the plugin there (they must be literal,
  or the configuration must come from a provider that does not template it, such
  as Traefik Hub or a Kubernetes CRD);
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
make integration-tls              # the same, over TLS with mutual authentication
make integration-tls-down         # tear the TLS stack down
make options                      # loads every example of example/options/ in a real Traefik
make options-down                 # tear the options stack down
make loadtest                     # load test: 401 path, Redis sessions, cookie sessions
make chaos                        # chaos test: failover, killed nodes, poisoned keys
make chaos-down                   # tear the chaos stack down
```

Test suites: the unit tests (`make test-race`), the Yaegi check
(`make yaegi-check`), the end-to-end stacks (plain, TLS), the per-option check
(`make options`, see [`example/options/`](example/options/README.md)), the load
test (`tools/loadtest`, three modes) and the chaos test (`docker/chaos.sh`, nine
scenarios). The per-option audit, the matrix option → code → test → example and
the load/chaos reports are in the project documentation (docs/21, docs/22).

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
