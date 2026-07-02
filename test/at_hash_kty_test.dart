import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:logi_auth/logi_auth.dart';
import 'package:pointycastle/export.dart';

/// Self-contained (no golden fixture) tests for the P2 hardening: at_hash
/// present-only verification and the JWKS kty filter. Tokens are signed inline
/// with a freshly generated RSA key so no shared fixture is touched.
void main() {
  // One RSA keypair for the whole suite.
  final pair = _generateRsaKeyPair();
  final priv = pair.privateKey as RSAPrivateKey;
  final pub = pair.publicKey as RSAPublicKey;
  const kid = 'inline-test-kid';
  final rsaJwk = Jwk(
    kty: 'RSA',
    n: _bigIntToBase64Url(pub.modulus!),
    e: _bigIntToBase64Url(pub.exponent!),
    kid: kid,
  );
  final jwks = Jwks([rsaJwk]);

  const now = 1700000000;
  const issuer = 'https://api.1pass.dev';
  const clientId = 'logi_test_client_abc';
  const nonce = 'nonce-abc123';
  const expected = VerifyExpected(issuer: issuer, clientId: clientId, nonce: nonce);
  const accessToken = 'test-access-token-xyz';

  Map<String, dynamic> basePayload({String? atHash}) => {
        'iss': issuer,
        'aud': clientId,
        'exp': now + 3600,
        'iat': now - 10,
        'nonce': nonce,
        'sub': 'user-sub-123',
        'at_hash': ?atHash,
      };

  test('at_hash present + correct access_token → verifies', () {
    final token = _signJwt(basePayload(atHash: _atHash(accessToken)), priv, kid);
    final result =
        verifyIdToken(token, jwks, expected, now: now, accessToken: accessToken);
    expect(result.sub, 'user-sub-123');
  });

  test('at_hash present + wrong access_token → atHashMismatch', () {
    final token = _signJwt(basePayload(atHash: _atHash(accessToken)), priv, kid);
    expect(
      () => verifyIdToken(token, jwks, expected,
          now: now, accessToken: 'a-different-access-token'),
      throwsA(isA<IdTokenVerificationException>().having(
          (e) => e.error, 'error', IdTokenVerifyError.atHashMismatch)),
    );
  });

  test('at_hash present but no access_token supplied → skipped (back-compat)', () {
    final token = _signJwt(basePayload(atHash: _atHash(accessToken)), priv, kid);
    final result = verifyIdToken(token, jwks, expected, now: now);
    expect(result.sub, 'user-sub-123');
  });

  test('no at_hash claim + access_token supplied → verifies (present-only)', () {
    final token = _signJwt(basePayload(), priv, kid);
    final result =
        verifyIdToken(token, jwks, expected, now: now, accessToken: accessToken);
    expect(result.sub, 'user-sub-123');
  });

  test('kty filter: EC key sharing the kid is skipped, RSA key is used', () {
    // A foreign (EC) key published under the SAME kid, ordered first. Without
    // the kty=="RSA" filter the verifier would feed it to the RSA path.
    final ecFirst = Jwks([
      Jwk(kty: 'EC', n: 'x', e: 'y', kid: kid),
      rsaJwk,
    ]);
    final token = _signJwt(basePayload(atHash: _atHash(accessToken)), priv, kid);
    final result = verifyIdToken(token, ecFirst, expected,
        now: now, accessToken: accessToken);
    expect(result.sub, 'user-sub-123');
  });

  test('kty filter: a REAL EC JWKS entry (no n/e) parses and is skipped', () {
    // Parse through Jwks.fromJson so we exercise the real wire path: a genuine
    // EC key has crv/x/y and NO n/e — it must not break JWKS parsing.
    final jwksJson = {
      'keys': [
        {
          'kty': 'EC',
          'crv': 'P-256',
          'x': 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
          'y': 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
          'kid': kid,
        },
        {'kty': 'RSA', 'n': rsaJwk.n, 'e': rsaJwk.e, 'kid': kid},
      ],
    };
    final parsed = Jwks.fromJson(jwksJson);
    final token = _signJwt(basePayload(atHash: _atHash(accessToken)), priv, kid);
    final result =
        verifyIdToken(token, parsed, expected, now: now, accessToken: accessToken);
    expect(result.sub, 'user-sub-123');
  });
}

// ── inline signing helpers ────────────────────────────────────────────────

String _atHash(String accessToken) {
  final digest = crypto.sha256.convert(utf8.encode(accessToken)).bytes;
  return _base64UrlNoPad(Uint8List.fromList(digest.sublist(0, 16)));
}

String _signJwt(Map<String, dynamic> payload, RSAPrivateKey priv, String kid) {
  final header = {'alg': 'RS256', 'typ': 'JWT', 'kid': kid};
  final h = _base64UrlNoPad(utf8.encode(jsonEncode(header)));
  final p = _base64UrlNoPad(utf8.encode(jsonEncode(payload)));
  final signingInput = '$h.$p';
  final signer = RSASigner(SHA256Digest(), '0609608648016503040201')
    ..init(true, PrivateKeyParameter<RSAPrivateKey>(priv));
  final sig = signer.generateSignature(
      Uint8List.fromList(utf8.encode(signingInput)));
  return '$signingInput.${_base64UrlNoPad(sig.bytes)}';
}

String _base64UrlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

String _bigIntToBase64Url(BigInt v) {
  var hex = v.toRadixString(16);
  if (hex.length % 2 != 0) hex = '0$hex';
  final bytes = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return _base64UrlNoPad(bytes);
}

AsymmetricKeyPair<PublicKey, PrivateKey> _generateRsaKeyPair() {
  final rng = FortunaRandom();
  final seed = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) % 256));
  rng.seed(KeyParameter(seed));
  final gen = RSAKeyGenerator()
    ..init(ParametersWithRandom(
      RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64),
      rng,
    ));
  return gen.generateKeyPair();
}
