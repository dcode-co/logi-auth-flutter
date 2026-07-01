/// Thin "Sign in with logi" connector for Flutter RP apps.
///
/// OAuth 2.0 Authorization Code + PKCE with client-side id_token (RS256)
/// verification. Public client only — confidential RPs with a backend should
/// verify server-side. Identical safety contract to the iOS/Android/Web SDKs
/// (same shared golden vectors).
library;

export 'src/id_token_verifier.dart'
    show
        Jwk,
        Jwks,
        VerifyExpected,
        VerifiedIdToken,
        IdTokenVerifyError,
        IdTokenVerificationException,
        verifyIdToken;
export 'src/logi_auth_client.dart' show LogiAuth, LogiAuthBrowser;
export 'src/models.dart';
export 'src/pkce.dart' show Pkce;
