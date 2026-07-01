import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:logi_auth/logi_auth.dart';

/// Golden-vector parity test. `test/fixtures/id-token-vectors.json` is a copy of
/// the 4-SDK shared set (`test-vectors/id-token-vectors.json`, SoT =
/// generate.mjs). Flutter MUST produce identical verify/reject results to
/// Web/iOS/Android. JWKS is a fixed snapshot so this runs offline.
void main() {
  final vectors = jsonDecode(
    File('test/fixtures/id-token-vectors.json').readAsStringSync(),
  ) as Map<String, dynamic>;

  final now = vectors['now'] as int;
  final expectedJson = vectors['expected'] as Map<String, dynamic>;
  final expected = VerifyExpected(
    issuer: expectedJson['issuer'] as String,
    clientId: expectedJson['clientId'] as String,
    nonce: expectedJson['nonce'] as String?,
  );
  final jwks = Jwks.fromJson(vectors['jwks'] as Map<String, dynamic>);
  final cases = (vectors['cases'] as List<dynamic>).cast<Map<String, dynamic>>();

  test('golden vectors verify/reject identically across the 4 SDKs', () {
    for (final c in cases) {
      final name = c['name'] as String;
      final token = c['token'] as String;
      final expect_ = c['expect'] as Map<String, dynamic>;
      final wantValid = expect_['valid'] as bool;

      try {
        final result = verifyIdToken(token, jwks, expected, now: now);
        expect(wantValid, isTrue, reason: "case '$name' expected invalid but verified");
        final wantSub = expect_['sub'];
        if (wantSub is String) {
          expect(result.sub, wantSub, reason: "case '$name' sub mismatch");
        }
      } on IdTokenVerificationException catch (e) {
        expect(wantValid, isFalse, reason: "case '$name' expected valid but threw ${e.error.code}");
        final wantError = expect_['error'];
        if (wantError is String) {
          expect(e.error.code, wantError, reason: "case '$name' error code mismatch");
        }
      }
    }
  });

  test('golden-vector set is complete (>= 9 cases incl. valid)', () {
    expect(cases.length, greaterThanOrEqualTo(9));
    expect(cases.any((c) => c['name'] == 'valid'), isTrue);
  });
}
