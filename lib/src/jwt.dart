import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:pointycastle/export.dart';

import 'errors.dart';
import 'pkce.dart';

/// Identvia signs ID tokens with RS256; ES256 is accepted for future keys. Never HS* or `none`.
const List<String> kAllowedAlgs = ['RS256', 'ES256'];

class Jwk {
  Jwk(this.json);
  final Map<String, dynamic> json;
  String? get kid => json['kid'] as String?;
  String? get kty => json['kty'] as String?;
  String? get alg => json['alg'] as String?;
  String? get use => json['use'] as String?;
}

class IdTokenClaims {
  IdTokenClaims(this.raw);
  final Map<String, dynamic> raw;
  String get sub => raw['sub'] as String;
  String get iss => raw['iss'] as String;
  String? get email => raw['email'] as String?;
  bool? get emailVerified => raw['email_verified'] as bool?;
  String? get name => raw['name'] as String?;
  String? get givenName => raw['given_name'] as String?;
  String? get familyName => raw['family_name'] as String?;
  String? get picture => raw['picture'] as String?;
  int? get authTime => raw['auth_time'] as int?;
  List<String> get amr => (raw['amr'] as List?)?.cast<String>() ?? const [];
  Map<String, dynamic> toJson() => raw;
}

BigInt _bigInt(Uint8List b) {
  var r = BigInt.zero;
  for (final x in b) {
    r = (r << 8) | BigInt.from(x);
  }
  return r;
}

/// Verifies an RS256 (RSASSA-PKCS1-v1_5 / SHA-256) or ES256 (P-256, raw r||s) JWS signature.
bool verifyJws(String alg, Jwk key, String signingInput, Uint8List signature) {
  final data = Uint8List.fromList(ascii.encode(signingInput));
  try {
    if (alg == 'RS256') {
      if (key.kty != 'RSA') return false;
      final pub = RSAPublicKey(_bigInt(b64urlDecode(key.json['n'] as String)),
          _bigInt(b64urlDecode(key.json['e'] as String)));
      final signer = RSASigner(SHA256Digest(), '0609608648016503040201')
        ..init(false, PublicKeyParameter<RSAPublicKey>(pub));
      return signer.verifySignature(data, RSASignature(signature));
    }
    if (alg == 'ES256') {
      if (key.kty != 'EC' ||
          key.json['crv'] != 'P-256' ||
          signature.length != 64) {
        return false;
      }
      final curve = ECCurve_secp256r1();
      final q = curve.curve.createPoint(
          _bigInt(b64urlDecode(key.json['x'] as String)),
          _bigInt(b64urlDecode(key.json['y'] as String)));
      final signer = ECDSASigner(SHA256Digest())
        ..init(false, PublicKeyParameter<ECPublicKey>(ECPublicKey(q, curve)));
      return signer.verifySignature(
          data,
          ECSignature(_bigInt(signature.sublist(0, 32)),
              _bigInt(signature.sublist(32))));
    }
  } catch (_) {
    return false;
  }
  return false;
}

/// OIDC Core §3.1.3.7 ID token validation.
class IdTokenValidator {
  IdTokenValidator(
      {required this.issuer,
      required this.clientId,
      required this.getKey,
      this.leeway = const Duration(seconds: 60),
      DateTime Function()? clock})
      : _clock = clock ?? DateTime.now;
  final String issuer;
  final String clientId;
  final Future<Jwk?> Function(String kid) getKey;
  final Duration leeway;
  final DateTime Function() _clock;

  Future<IdTokenClaims> validate(String jwt,
      {String? nonce,
      bool requireNonce = false,
      int? maxAge,
      String? accessToken}) async {
    final parts = jwt.split('.');
    if (parts.length != 3) {
      throw ValidationException('ID token is not a signed JWT.');
    }
    Map<String, dynamic> header, c;
    Uint8List sig;
    try {
      header = jsonDecode(utf8.decode(b64urlDecode(parts[0])))
          as Map<String, dynamic>;
      c = jsonDecode(utf8.decode(b64urlDecode(parts[1])))
          as Map<String, dynamic>;
      sig = b64urlDecode(parts[2]);
    } catch (_) {
      throw ValidationException('ID token is malformed.');
    }
    final alg = header['alg'];
    if (alg is! String || !kAllowedAlgs.contains(alg)) {
      throw ValidationException('ID token algorithm $alg is not allowed.');
    }
    final kid = header['kid'];
    if (kid is! String) {
      throw ValidationException('ID token has no key ID (kid).');
    }
    final key = await getKey(kid);
    if (key == null) {
      throw ValidationException('ID token was signed with an unknown key.');
    }
    if (key.alg != null && key.alg != alg) {
      throw ValidationException('ID token algorithm does not match its key.');
    }
    if (!verifyJws(alg, key, '${parts[0]}.${parts[1]}', sig)) {
      throw ValidationException('ID token signature is invalid.');
    }

    final now = _clock().millisecondsSinceEpoch ~/ 1000;
    final tol = leeway.inSeconds;
    if (c['iss'] != issuer) {
      throw ValidationException('ID token issuer mismatch.');
    }
    final aud = c['aud'];
    final auds = aud is List ? aud.cast<String>() : [aud];
    if (!auds.contains(clientId)) {
      throw ValidationException('ID token was not issued for this app (aud).');
    }
    if (auds.length > 1 && c['azp'] != clientId) {
      throw ValidationException('ID token azp mismatch.');
    }
    if (c.containsKey('azp') && c['azp'] != clientId) {
      throw ValidationException('ID token azp mismatch.');
    }
    final sub = c['sub'];
    if (sub is! String || sub.isEmpty || sub.length > 255) {
      throw ValidationException('ID token has no subject.');
    }
    final exp = c['exp'], iat = c['iat'];
    if (exp is! int || iat is! int) {
      throw ValidationException('ID token is missing exp/iat.');
    }
    if (exp + tol < now) throw ValidationException('ID token has expired.');
    if (iat > now + tol) {
      throw ValidationException('ID token was issued in the future.');
    }
    if (nonce != null || requireNonce) {
      final n = c['nonce'];
      if (n is! String || nonce == null || !safeEquals(n, nonce)) {
        throw ValidationException('ID token nonce mismatch (possible replay).');
      }
    }
    if (maxAge != null) {
      final at = c['auth_time'];
      if (at is! int) {
        throw ValidationException(
            'ID token has no auth_time but max_age was requested.');
      }
      if (at + maxAge + tol < now) {
        throw ValidationException(
            'The user signed in too long ago for the requested max_age.');
      }
    }
    if (c['at_hash'] != null && accessToken != null) {
      final h = b64url(
          sha256.convert(ascii.encode(accessToken)).bytes.sublist(0, 16));
      if (!safeEquals(h, c['at_hash'].toString())) {
        throw ValidationException(
            'ID token at_hash does not match the access token.');
      }
    }
    return IdTokenClaims(c);
  }
}
