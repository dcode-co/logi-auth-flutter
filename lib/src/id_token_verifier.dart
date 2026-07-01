import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

// RS256 id_token 검증 — pointycastle(pure Dart) RSA primitive만 사용.
// 서버 검증 규칙 mirror: logi server/app/lib/oauth/jwt_verifier.rb
//   kid 필수 → JWKS 조회 → RS256 서명검증 → iss · aud · exp · iat · nonce · sub.
// 4플랫폼 공통 골든 벡터(../../test-vectors/id-token-vectors.json)를 동일 통과.
//
// 왜 pointycastle: Dart 에는 다른 SDK 의 시스템 crypto(WebCrypto/Security/
// java.security) 같은 순수-Dart RSA primitive 가 없다. JWS 파싱 + 클레임 검사는
// 여기서 직접 구현(verify.ts mirror)하고, RSA-PKCS1v15 SHA-256 검증만 위임한다.

/// Failure reasons; [code] mirrors the Web verifier and golden-vector strings.
enum IdTokenVerifyError {
  malformed('malformed'),
  missingKid('missing_kid'),
  unknownKid('unknown_kid'),
  badSignature('bad_signature'),
  issMismatch('iss_mismatch'),
  audMismatch('aud_mismatch'),
  expired('expired'),
  nonceMismatch('nonce_mismatch'),
  missingClaim('missing_claim');

  const IdTokenVerifyError(this.code);
  final String code;
}

/// Thrown by [verifyIdToken]; carries the machine [error] (and `.error.code`).
class IdTokenVerificationException implements Exception {
  IdTokenVerificationException(this.error);
  final IdTokenVerifyError error;
  @override
  String toString() => 'IdTokenVerificationException(${error.code})';
}

/// A JSON Web Key (RSA).
class Jwk {
  Jwk({required this.kty, required this.n, required this.e, required this.kid});
  factory Jwk.fromJson(Map<String, dynamic> j) => Jwk(
        kty: j['kty'] as String,
        n: j['n'] as String,
        e: j['e'] as String,
        kid: j['kid'] as String,
      );
  final String kty;
  final String n;
  final String e;
  final String kid;
}

/// A JWKS document.
class Jwks {
  Jwks(this.keys);
  factory Jwks.fromJson(Map<String, dynamic> j) => Jwks(
        (j['keys'] as List<dynamic>)
            .map((k) => Jwk.fromJson(k as Map<String, dynamic>))
            .toList(),
      );
  final List<Jwk> keys;
}

/// Expected claim values for verification.
class VerifyExpected {
  const VerifyExpected({required this.issuer, required this.clientId, this.nonce});

  /// id_token.iss must equal this (logi issuer STRING "logi", NOT a URL).
  final String issuer;

  /// id_token.aud must contain this (the RP's client_id).
  final String clientId;

  /// If non-null, id_token.nonce must equal this (the authorize value).
  final String? nonce;
}

/// A verified id_token's subject + full claim set.
class VerifiedIdToken {
  VerifiedIdToken(this.sub, this.claims);
  final String sub;
  final Map<String, dynamic> claims;
}

/// Verify a logi-issued id_token and return its verified subject. Throws
/// [IdTokenVerificationException] on any failure — never returns an unverified
/// subject. Claim order matches server + Web/iOS/Android:
/// signature → iss → aud → exp → iat → nonce → sub.
///
/// [now] is Unix seconds; defaults to now. Injectable for deterministic tests.
VerifiedIdToken verifyIdToken(
  String idToken,
  Jwks jwks,
  VerifyExpected expected, {
  int? now,
  int clockSkewSec = 60,
}) {
  final nowSec = now ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;

  final parts = idToken.split('.');
  if (parts.length != 3 ||
      parts[0].isEmpty ||
      parts[1].isEmpty ||
      parts[2].isEmpty) {
    throw IdTokenVerificationException(IdTokenVerifyError.malformed);
  }

  final header = _decodeJsonSegment(parts[0]);
  final payload = _decodeJsonSegment(parts[1]);
  if (header == null || payload == null) {
    throw IdTokenVerificationException(IdTokenVerifyError.malformed);
  }

  // kid → JWKS key.
  final kid = header['kid'];
  if (kid is! String || kid.isEmpty) {
    throw IdTokenVerificationException(IdTokenVerifyError.missingKid);
  }
  Jwk? jwk;
  for (final k in jwks.keys) {
    if (k.kid == kid) {
      jwk = k;
      break;
    }
  }
  if (jwk == null) {
    throw IdTokenVerificationException(IdTokenVerifyError.unknownKid);
  }

  // RS256 signature verification via pointycastle.
  final signature = _base64UrlDecode(parts[2]);
  if (signature == null ||
      !_verifyRs256('${parts[0]}.${parts[1]}', signature, jwk)) {
    throw IdTokenVerificationException(IdTokenVerifyError.badSignature);
  }

  // Claim checks (order: iss → aud → exp → iat → nonce → sub).
  if (payload['iss'] != expected.issuer) {
    throw IdTokenVerificationException(IdTokenVerifyError.issMismatch);
  }

  if (!_audienceMatches(payload['aud'], expected.clientId)) {
    throw IdTokenVerificationException(IdTokenVerifyError.audMismatch);
  }

  final exp = _numericClaim(payload['exp']);
  if (exp == null || exp <= nowSec - clockSkewSec) {
    throw IdTokenVerificationException(IdTokenVerifyError.expired);
  }

  final iat = _numericClaim(payload['iat']);
  if (iat == null || iat > nowSec + clockSkewSec) {
    // iat missing or in the future → malformed (mirrors the other verifiers).
    throw IdTokenVerificationException(IdTokenVerifyError.malformed);
  }

  if (expected.nonce != null && payload['nonce'] != expected.nonce) {
    throw IdTokenVerificationException(IdTokenVerifyError.nonceMismatch);
  }

  final sub = payload['sub'];
  if (sub is! String || sub.isEmpty) {
    throw IdTokenVerificationException(IdTokenVerifyError.missingClaim);
  }

  return VerifiedIdToken(sub, payload);
}

// ── Helpers ──────────────────────────────────────────────────────────────

bool _verifyRs256(String signingInput, Uint8List signature, Jwk jwk) {
  final modulusBytes = _base64UrlDecode(jwk.n);
  final exponentBytes = _base64UrlDecode(jwk.e);
  if (modulusBytes == null || exponentBytes == null) return false;
  try {
    final pub = RSAPublicKey(_bytesToBigInt(modulusBytes), _bytesToBigInt(exponentBytes));
    // '0609608648016503040201' = DER OID for SHA-256, per PKCS#1 v1.5.
    final signer = RSASigner(SHA256Digest(), '0609608648016503040201')
      ..init(false, PublicKeyParameter<RSAPublicKey>(pub));
    return signer.verifySignature(
      Uint8List.fromList(utf8.encode(signingInput)),
      RSASignature(signature),
    );
  } catch (_) {
    return false;
  }
}

Map<String, dynamic>? _decodeJsonSegment(String segment) {
  final bytes = _base64UrlDecode(segment);
  if (bytes == null) return null;
  try {
    final decoded = jsonDecode(utf8.decode(bytes));
    return decoded is Map<String, dynamic> ? decoded : null;
  } catch (_) {
    return null;
  }
}

bool _audienceMatches(dynamic aud, String clientId) {
  if (aud is String) return aud == clientId;
  if (aud is List) return aud.contains(clientId);
  return false;
}

int? _numericClaim(dynamic value) {
  if (value is int) return value;
  if (value is double) return value.toInt();
  return null;
}

Uint8List? _base64UrlDecode(String segment) {
  try {
    return base64Url.decode(base64Url.normalize(segment));
  } catch (_) {
    return null;
  }
}

BigInt _bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}
