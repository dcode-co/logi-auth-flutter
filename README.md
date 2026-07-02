# logi_auth

Thin **"Sign in with logi"** connector for Flutter RP (Relying Party) apps.

A public OAuth 2.0 client that drives the Authorization Code + PKCE flow against
the logi (1pass) IdP and verifies the returned `id_token` on-device before it
hands you a session. It shares the same safety contract and golden vectors as
the iOS, Android, and Web SDKs.

> **Public client only.** There is no `client_secret`. Confidential RPs that run
> a backend should exchange the code and verify the `id_token` server-side
> instead of using this connector.

## Features

- OAuth 2.0 **Authorization Code + PKCE** (S256), with `state` (CSRF) and
  `nonce` (replay) generated and enforced on every sign-in.
- **Client-side `id_token` verification**: RS256 signature (via `pointycastle`,
  pure Dart) plus `iss` / `aud` / `azp` / `exp` / `iat` / `nonce` / `sub` claim
  checks. `sub` is returned only after verification passes.
- **JWKS caching** (1h) with a single refetch on key rotation (`unknown_kid`),
  and a `kty=="RSA"` key filter so a future EC key in the JWKS won't break RS256
  logins.
- **`at_hash` binding** (OIDC §3.1.3.6): when the token carries an `at_hash`, it
  is checked against the `access_token`, rejecting token-substitution before a
  session is created.
- Browser handoff is an **injectable seam** (`LogiAuthBrowser`) — wire it to
  `flutter_web_auth_2`, Custom Tabs, or `ASWebAuthenticationSession`.

## Getting started

1. Register your app as a **public client** with the logi IdP and note the
   issued `client_id` and the `redirect_uri` you registered (an HTTPS App Link /
   Universal Link, or a custom scheme such as `myapp://callback`).

2. Add the package to your `pubspec.yaml`:

   ```yaml
   dependencies:
     logi_auth: ^1.0.0
   ```

3. Implement the `LogiAuthBrowser` seam. A pure-Dart connector cannot open the
   system browser or capture the redirect itself, so the RP provides it —
   typically backed by `flutter_web_auth_2`:

   ```dart
   import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
   import 'package:logi_auth/logi_auth.dart';

   class WebAuthBrowser implements LogiAuthBrowser {
     @override
     Future<Uri> authorize(Uri authorizeUrl, {required String callbackScheme}) async {
       final result = await FlutterWebAuth2.authenticate(
         url: authorizeUrl.toString(),
         callbackUrlScheme: callbackScheme,
       );
       return Uri.parse(result);
     }
   }
   ```

## Usage

```dart
import 'package:logi_auth/logi_auth.dart';

final auth = LogiAuth(
  config: const LogiAuthConfig(
    clientId: 'your_public_client_id',
    redirectUri: 'myapp://callback',
    // issuer / tokenIssuer default to https://api.1pass.dev
    // scopes default to ['openid', 'profile:basic', 'email']
  ),
  browser: WebAuthBrowser(),
);

try {
  final LogiSession session = await auth.signIn();
  print('Signed in as ${session.sub}');   // verified subject
  print('email: ${session.email}');       // if the scope was granted
  // session.accessToken / refreshToken / expiresAt are also available.
} on LogiAuthException catch (e) {
  // e.code is a LogiAuthErrorCode (userCancelled, stateMismatch,
  // idTokenInvalid, ...); e.detail carries the verifier's reason.
  print('Sign-in failed: ${e.code.name} — ${e.message}');
}
```

`signIn()` returns a `LogiSession` only after the `id_token`'s signature and
claims (including `nonce` and, when present, `at_hash`) have been verified. Any
failure throws a typed `LogiAuthException` — an unverified subject is never
returned.

## Additional information

Part of the logi multi-platform SDK family (iOS / Android / Web / Flutter),
all sharing the same golden id_token verification vectors.

## License

Apache-2.0.
