import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;

import 'errors.dart';

final Random _rng = Random.secure();

String b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List b64urlDecode(String s) {
  if (!RegExp(r'^[A-Za-z0-9_-]*$').hasMatch(s)) {
    throw const FormatException('not base64url');
  }
  return base64Url.decode(base64Url.normalize(s));
}

/// Cryptographically random base64url string.
String randomToken([int bytes = 32]) =>
    b64url(List<int>.generate(bytes, (_) => _rng.nextInt(256)));

/// RFC 7636 §4.2 (S256 only; Identvia rejects `plain`).
String codeChallengeS256(String verifier) {
  if (!RegExp(r'^[A-Za-z0-9\-._~]{43,128}$').hasMatch(verifier)) {
    throw ConfigurationException(
        'PKCE code_verifier must be 43–128 unreserved characters.');
  }
  return b64url(sha256.convert(ascii.encode(verifier)).bytes);
}

class Pkce {
  Pkce._(this.verifier, this.challenge);
  factory Pkce.generate() {
    final v = randomToken(48); // 64 chars
    return Pkce._(v, codeChallengeS256(v));
  }
  final String verifier;
  final String challenge;
  String get method => 'S256';
}

/// Constant-time comparison.
bool safeEquals(String a, String b) {
  final x = utf8.encode(a), y = utf8.encode(b);
  var d = x.length ^ y.length;
  for (var i = 0; i < max(x.length, y.length); i++) {
    d |= (i < x.length ? x[i] : 0) ^ (i < y.length ? y[i] : 0);
  }
  return d == 0;
}
