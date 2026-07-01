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
