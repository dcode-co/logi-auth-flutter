import 'package:meta/meta.dart';

/// Configuration for the logi RP connector. Create once and pass to
/// [LogiAuth].
@immutable
class LogiAuthConfig {
  const LogiAuthConfig({
    required this.clientId,
    required this.redirectUri,
    this.issuer = 'https://api.1pass.dev',
    this.tokenIssuer = 'logi',
    this.scopes = const ['openid', 'profile:basic', 'email'],
  });

  /// The client_id issued when this app was registered as a **public client**.
  final String clientId;

  /// Redirect URI registered with the logi IdP. Either an HTTPS App Link /
  /// Universal Link your app claims, or a custom scheme ("myapp://callback").
  final String redirectUri;

  /// Base URL of the logi IdP.
  final String issuer;

  /// Expected `iss` claim inside the id_token — the logi issuer STRING
  /// ("logi"), NOT the [issuer] URL (mirrors server OIDC_ISSUER).
  final String tokenIssuer;

  /// Default OAuth scopes if [LogiAuth.signIn] is called without a list.
  final List<String> scopes;
}

/// The verified outcome of a successful [LogiAuth.signIn]. [sub] is populated
/// only after this connector has verified the id_token's RS256 signature and
/// claims — the sole safety contract of v1.0. Identical shape across all 4 SDKs.
@immutable
class LogiSession {
  const LogiSession({
    required this.sub,
    required this.idToken,
    required this.accessToken,
    this.email,
    this.refreshToken,
    this.expiresAt,
    this.scope,
    this.tokenType = 'Bearer',
  });

  /// Verified subject from the id_token — pairwise per client.
  final String sub;

  /// `email` claim, if present and the scope was granted.
  final String? email;

  /// Raw id_token (already verified by this connector).
  final String idToken;

  final String accessToken;
  final String? refreshToken;
  final DateTime? expiresAt;
  final String? scope;
  final String tokenType;
}

/// Machine-readable failure codes for [LogiAuthException].
enum LogiAuthErrorCode {
  notConfigured,
  invalidAuthorizeUrl,
  userCancelled,
  stateMismatch,
  missingCode,
  authorizationServerError,
  tokenExchangeFailed,
  missingIdToken,
  idTokenInvalid,
  jwksFetchFailed,
  network,
}

/// Typed error thrown by [LogiAuth.signIn].
class LogiAuthException implements Exception {
  LogiAuthException(this.code, this.message, {this.detail});

  final LogiAuthErrorCode code;
  final String message;

  /// For [LogiAuthErrorCode.idTokenInvalid], the verifier's error code
  /// (e.g. "bad_signature", "aud_mismatch"); otherwise free-form context.
  final String? detail;

  @override
  String toString() =>
      'LogiAuthException(${code.name}): $message${detail != null ? ' [$detail]' : ''}';
}
