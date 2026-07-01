import 'dart:convert';

import 'package:http/http.dart' as http;

import 'id_token_verifier.dart';
import 'models.dart';
import 'pkce.dart';

/// Platform seam for the OAuth browser handoff. A pure-Dart connector cannot
/// launch the system browser and capture the redirect itself, so the RP (or a
/// thin companion plugin) provides this — typically backed by
/// `flutter_web_auth_2`, Custom Tabs, or ASWebAuthenticationSession.
///
/// [authorize] must open [authorizeUrl], let the user complete consent, and
/// resolve with the full redirect callback [Uri] (carrying `code`/`state`), or
/// throw if the user cancels.
abstract class LogiAuthBrowser {
  Future<Uri> authorize(Uri authorizeUrl, {required String callbackScheme});
}

/// Thin "Sign in with logi" connector: PKCE → nonce → authorize → callback →
/// token exchange → **id_token verification** → verified [LogiSession].
///
/// This is a **public client** (no client_secret). Confidential RPs with a
/// backend should exchange + verify server-side and not use this connector.
class LogiAuth {
  LogiAuth({
    required this.config,
    required LogiAuthBrowser browser,
    http.Client? httpClient,
  })  : _browser = browser,
        _http = httpClient ?? http.Client();

  final LogiAuthConfig config;
  final LogiAuthBrowser _browser;
  final http.Client _http;

  Jwks? _jwksCache;
  DateTime? _jwksFetchedAt;
  static const _jwksTtl = Duration(hours: 1);

  String get _issuer => config.issuer.replaceAll(RegExp(r'/+$'), '');

  /// Drive the flow and return a verified session. Throws [LogiAuthException].
  Future<LogiSession> signIn({List<String>? scopes}) async {
    final verifier = Pkce.generateVerifier();
    final challenge = Pkce.s256Challenge(verifier);
    final state = Pkce.randomState();
    // nonce is always generated and always verified — it binds the id_token to
    // this authorize request (replay defense).
    final nonce = Pkce.randomNonce();

    final authorizeUrl = Uri.parse('$_issuer/oauth/authorize').replace(
      queryParameters: {
        'response_type': 'code',
        'client_id': config.clientId,
        'redirect_uri': config.redirectUri,
        'scope': (scopes ?? config.scopes).join(' '),
        'state': state,
        'nonce': nonce,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
      },
    );
    final callbackScheme = Uri.parse(config.redirectUri).scheme;

    final Uri callback;
    try {
      callback = await _browser.authorize(authorizeUrl, callbackScheme: callbackScheme);
    } on LogiAuthException {
      rethrow;
    } catch (e) {
      throw LogiAuthException(
        LogiAuthErrorCode.userCancelled,
        'Browser flow was cancelled or failed',
        detail: '$e',
      );
    }

    final error = callback.queryParameters['error'];
    if (error != null) {
      throw LogiAuthException(
        LogiAuthErrorCode.authorizationServerError,
        callback.queryParameters['error_description'] ?? error,
      );
    }
    final code = callback.queryParameters['code'];
    if (code == null) {
      throw LogiAuthException(LogiAuthErrorCode.missingCode, 'Callback URL had no code');
    }
    if (callback.queryParameters['state'] != state) {
      throw LogiAuthException(LogiAuthErrorCode.stateMismatch, 'state mismatch (possible CSRF)');
    }

    final tokens = await _exchange(code, verifier);

    // Verify the id_token (public-client trust boundary) — `sub` is set only
    // after RS256 signature + claims (incl. nonce) check out.
    final idToken = tokens['id_token'];
    if (idToken is! String || idToken.isEmpty) {
      throw LogiAuthException(LogiAuthErrorCode.missingIdToken,
          'Token response had no id_token — was `openid` in the scopes?');
    }
    final verified = await _verifyWithRotationRetry(idToken, nonce);

    final email = verified.claims['email'];
    final expiresIn = tokens['expires_in'];
    return LogiSession(
      sub: verified.sub,
      email: email is String ? email : null,
      idToken: idToken,
      accessToken: tokens['access_token'] as String,
      refreshToken: tokens['refresh_token'] as String?,
      expiresAt: expiresIn is int ? DateTime.now().add(Duration(seconds: expiresIn)) : null,
      scope: tokens['scope'] as String?,
      tokenType: (tokens['token_type'] as String?) ?? 'Bearer',
    );
  }

  Future<Map<String, dynamic>> _exchange(String code, String verifier) async {
    final http.Response resp;
    try {
      resp = await _http.post(
        Uri.parse('$_issuer/oauth/token'),
        headers: const {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
        },
        body: {
          'grant_type': 'authorization_code',
          'code': code,
          'code_verifier': verifier,
          'client_id': config.clientId,
          'redirect_uri': config.redirectUri,
        },
      );
    } catch (e) {
      throw LogiAuthException(LogiAuthErrorCode.network, 'Token exchange network error', detail: '$e');
    }
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw LogiAuthException(
        LogiAuthErrorCode.tokenExchangeFailed,
        'Token exchange failed (HTTP ${resp.statusCode})',
        detail: resp.body,
      );
    }
    // A 2xx body can still be a proxy error page or otherwise malformed — a
    // raw FormatException/TypeError must not escape the LogiAuthException
    // contract. (codex P2.)
    final Object? parsed;
    try {
      parsed = jsonDecode(resp.body);
    } catch (e) {
      throw LogiAuthException(LogiAuthErrorCode.tokenExchangeFailed,
          'Token response was not valid JSON', detail: '$e');
    }
    if (parsed is! Map<String, dynamic> || parsed['access_token'] is! String) {
      throw LogiAuthException(LogiAuthErrorCode.tokenExchangeFailed,
          'Token response was missing access_token');
    }
    return parsed;
  }

  /// Fetch JWKS (1h cache) and verify. On `unknown_kid` from a stale cache —
  /// the IdP rotated signing keys within the TTL — bust the cache, refetch
  /// once, and re-verify so key rotation doesn't lock out every sign-in.
  Future<VerifiedIdToken> _verifyWithRotationRetry(String idToken, String nonce) async {
    final expected = VerifyExpected(
      issuer: config.tokenIssuer,
      clientId: config.clientId,
      nonce: nonce,
    );
    final (jwks, fromCache) = await _fetchJwks();
    try {
      return verifyIdToken(idToken, jwks, expected);
    } on IdTokenVerificationException catch (e) {
      if (e.error == IdTokenVerifyError.unknownKid && fromCache) {
        final (fresh, _) = await _fetchJwks(forceRefresh: true);
        try {
          return verifyIdToken(idToken, fresh, expected);
        } on IdTokenVerificationException catch (retry) {
          throw LogiAuthException(LogiAuthErrorCode.idTokenInvalid,
              'id_token verification failed', detail: retry.error.code);
        }
      }
      throw LogiAuthException(LogiAuthErrorCode.idTokenInvalid,
          'id_token verification failed', detail: e.error.code);
    }
  }

  Future<(Jwks, bool)> _fetchJwks({bool forceRefresh = false}) async {
    final cache = _jwksCache;
    final fetchedAt = _jwksFetchedAt;
    if (!forceRefresh &&
        cache != null &&
        fetchedAt != null &&
        DateTime.now().difference(fetchedAt) < _jwksTtl) {
      return (cache, true);
    }
    final http.Response resp;
    try {
      resp = await _http.get(
        Uri.parse('$_issuer/.well-known/jwks.json'),
        headers: const {'Accept': 'application/json'},
      );
    } catch (e) {
      throw LogiAuthException(LogiAuthErrorCode.network, 'JWKS fetch network error', detail: '$e');
    }
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throw LogiAuthException(LogiAuthErrorCode.jwksFetchFailed, 'JWKS fetch failed (HTTP ${resp.statusCode})');
    }
    // A malformed 2xx JWKS body (proxy error page, unexpected shape) must
    // surface as jwksFetchFailed, not a raw parse/type error. (codex P2.)
    final Jwks jwks;
    try {
      jwks = Jwks.fromJson(jsonDecode(resp.body) as Map<String, dynamic>);
    } catch (e) {
      throw LogiAuthException(LogiAuthErrorCode.jwksFetchFailed,
          'JWKS response was not valid JSON', detail: '$e');
    }
    _jwksCache = jwks;
    _jwksFetchedAt = DateTime.now();
    return (jwks, false);
  }
}
