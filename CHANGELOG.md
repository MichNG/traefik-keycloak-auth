# Changelog

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
