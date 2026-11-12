# Migration from `traefik-oidc-auth` to `traefik-keycloak-auth`

The project was renamed. The behaviour and the configuration schema are
unchanged, but four names change and two of them require an update.

## 1. Renames

| Before | After | Impact |
| :--- | :--- | :--- |
| `github.com/MichNG/traefik-oidc-auth` | `github.com/MichNG/traefik-keycloak-auth` | static configuration (`moduleName`), plugin manifest |
| plugin key `traefik-oidc-auth` | `traefik-keycloak-auth` | `experimental.plugins` / `localPlugins` and every middleware referencing it |
| Go package `src/internalconfig` (was `src/hubconfig`) | `internalconfig` | only for code importing the configuration schema |
| Go package path `.../src/...` | root package `.../` + `.../internal/...` | only for code importing the plugin |

```yaml
# Before
experimental:
  plugins:
    traefik-oidc-auth:
      moduleName: "github.com/MichNG/traefik-oidc-auth"
      version: "v0.9.0"

# After
experimental:
  plugins:
    traefik-keycloak-auth:
      moduleName: "github.com/MichNG/traefik-keycloak-auth"
      version: "v1.0.0"
```

## 2. Redis key prefix

The default prefix of the session keys changed from `traefik-oidc-auth:` to
`traefik-keycloak-auth:` (`session.DefaultKeyPrefix`). Sessions written by the
previous version are therefore **not** found after the upgrade: the users are
sent through a new login.

Two options:

* let the old sessions expire and accept one re-authentication per user;
* keep the old namespace during a transition by setting the prefix explicitly:

```yaml
session:
  store:
    redis:
      endpoints: ["sentinel-0:26379", "sentinel-1:26379", "sentinel-2:26379"]
      sentinel:
        masterSet: mymaster
store:
  keyPrefix: "traefik-oidc-auth:"   # temporary: read the sessions of the previous version
```

## 3. Behavior changes in the same release

* a session store **read** failure answers `503` (fail closed) instead of
  treating the request as unauthenticated;
* a sliding session renewal that cannot be persisted is logged and the request is
  served with the session that was just validated (a login/callback still fails
  closed with `503`);
* a Redis `READONLY`/`MASTERDOWN` reply during a Sentinel failover no longer opens
  the circuit breaker, so a failover cannot turn the read path into `503` for the
  whole breaker window;
* `forwardAccessToken` only injects `Authorization: Bearer …` for an authorized
  session.
