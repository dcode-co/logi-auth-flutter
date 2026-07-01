import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// PKCE (RFC 7636) + OIDC nonce helpers. Always S256.
class Pkce {
  Pkce._();

  static final Random _rng = Random.secure();

  /// A PKCE verifier: 32 random bytes, base64url (no padding).
  static String generateVerifier() => _randomBase64Url(32);

  /// S256 challenge = base64url(sha256(verifier)) (no padding).
  static String s256Challenge(String verifier) {
    final digest = sha256.convert(utf8.encode(verifier)).bytes;
    return _base64Url(Uint8List.fromList(digest));
  }

  /// CSRF `state`: 16 random bytes, base64url.
  static String randomState() => _randomBase64Url(16);

  /// OIDC `nonce`: 32 random bytes, base64url. Bound to one authorize request.
  static String randomNonce() => _randomBase64Url(32);

  static String _randomBase64Url(int byteCount) {
    final bytes = Uint8List(byteCount);
    for (var i = 0; i < byteCount; i++) {
      bytes[i] = _rng.nextInt(256);
    }
    return _base64Url(bytes);
  }

  static String _base64Url(Uint8List bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');
}
