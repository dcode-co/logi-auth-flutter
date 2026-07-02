## 1.0.1

* Security hardening (non-breaking):
  * **at_hash verification** (OIDC §3.1.3.6, present-only). `verifyIdToken` now
    accepts an optional `accessToken`; when the token carries an `at_hash` and an
    `accessToken` is supplied, it must match
    `base64url_nopad(SHA256(access_token)[0..15])`, rejecting token substitution.
    `signIn()` wires the token endpoint's `access_token` so a mismatch is refused
    before a session is created. Omitting `accessToken` preserves prior behaviour.
  * **JWKS `kty` filter**: key selection now requires `kty=="RSA"` alongside the
    `kid` match, so a future EC key sharing a kid won't break RS256 logins.
* Adds `IdTokenVerifyError.atHashMismatch` (code `at_hash_mismatch`). New enum
  case — patch-level source risk only for callers doing exhaustive switches over
  `IdTokenVerifyError`; runtime behaviour of existing callers is unchanged.
* README replaced with real usage documentation.

## 1.0.0

* Initial release — thin "Sign in with logi" connector for Flutter.
* OAuth 2.0 Authorization Code + PKCE (public client, no client_secret).
* Client-side id_token verification: RS256 signature (via pointycastle) +
  iss/aud/exp/iat/nonce/sub claim checks, mirroring the server and the
  iOS/Android/Web SDKs (same shared golden vectors).
* `LogiAuth.signIn()` returns a verified `LogiSession { sub, email?, ... }`.
* JWKS fetch with a 1h cache and refetch-once on key rotation (`unknown_kid`).
* Browser handoff is an injectable `LogiAuthBrowser` seam (wire to
  flutter_web_auth_2 / Custom Tabs / ASWebAuthenticationSession).
