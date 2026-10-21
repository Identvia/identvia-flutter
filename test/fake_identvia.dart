// In-memory Identvia mirroring the real server's rules (PKCE S256, nonce, iss, rotation with reuse detection).
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:identvia/src/pkce.dart';
import 'package:pointycastle/export.dart';

const issuer = 'https://id.identvia.test';
const clientId = 'oid_flutter_test';

Uint8List _bytes(BigInt n) {
  final hex = n.toRadixString(16);
  final s = hex.length.isOdd ? '0$hex' : hex;
  return Uint8List.fromList([
    for (var i = 0; i < s.length; i += 2)
      int.parse(s.substring(i, i + 2), radix: 16)
  ]);
}

AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> rsaKeyPair() {
  final rnd = FortunaRandom()
    ..seed(KeyParameter(Uint8List.fromList(
        List.generate(32, (_) => Random.secure().nextInt(256)))));
  final gen = RSAKeyGenerator()
    ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64), rnd));
  final p = gen.generateKeyPair();
  return AsymmetricKeyPair(
      p.publicKey as RSAPublicKey, p.privateKey as RSAPrivateKey);
}

String signRs256(Map<String, dynamic> header, Map<String, dynamic> claims,
    RSAPrivateKey key) {
  final input =
      '${b64url(utf8.encode(jsonEncode(header)))}.${b64url(utf8.encode(jsonEncode(claims)))}';
  final signer = RSASigner(SHA256Digest(), '0609608648016503040201')
    ..init(true, PrivateKeyParameter<RSAPrivateKey>(key));
  return '$input.${b64url(signer.generateSignature(Uint8List.fromList(ascii.encode(input))).bytes)}';
}

class FakeIdentvia {
  FakeIdentvia(
      {this.redirectUris = const ['com.example.notes:/oauth/identvia'],
      this.stage5 = false})
      : keys = rsaKeyPair();
  final List<String> redirectUris;
  final bool stage5;
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keys;
  String kid = 'k1';
  final userSub = 'pw_${randomToken(9)}';
  String? forceNonce;
  bool wrongIss = false, omitIss = false;
  String Function(Map<String, dynamic> claims)? idTokenOverride;
  final codes = <String, Map<String, dynamic>>{};
  final refresh = <String, Map<String, dynamic>>{};
  final revokedFamilies = <String>{};
  final access = <String, Map<String, dynamic>>{};
  final requests = <http.Request>[];
  int jwksFetches = 0;

  Map<String, dynamic> get discovery => {
        'issuer': issuer,
        'authorization_endpoint': '$issuer/oauth/authorize',
        'token_endpoint': '$issuer/oauth/token',
        'userinfo_endpoint': '$issuer/oauth/userinfo',
        'jwks_uri': '$issuer/oauth/jwks.json',
        'revocation_endpoint': '$issuer/oauth/revoke',
        'end_session_endpoint': '$issuer/oauth/logout',
        'code_challenge_methods_supported': ['S256'],
        'authorization_response_iss_parameter_supported': true,
        if (stage5) 'authorization_details_types_supported': ['agent_task'],
      };

  Map<String, dynamic> get jwk => {
        'kty': 'RSA',
        'kid': kid,
        'use': 'sig',
        'alg': 'RS256',
        'n': b64url(_bytes(keys.publicKey.modulus!)),
        'e': b64url(_bytes(keys.publicKey.publicExponent!))
      };

  String idToken(String sub, String? nonce, String at) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final c = <String, dynamic>{
      'iss': issuer,
      'sub': sub,
      'aud': clientId,
      'azp': clientId,
      'iat': now,
      'exp': now + 600,
      'auth_time': now,
      'email': 'ada@example.com',
      'email_verified': true,
      'name': 'Ada',
      'at_hash': b64url(sha256.convert(ascii.encode(at)).bytes.sublist(0, 16)),
      if (nonce != null) 'nonce': nonce
    };
    if (idTokenOverride != null) return idTokenOverride!(c);
    return signRs256(
        {'alg': 'RS256', 'kid': kid, 'typ': 'JWT'}, c, keys.privateKey);
  }

  Map<String, dynamic> _issue(String sub, String scope, String? nonce,
      [String? family]) {
    final at = 'at_${randomToken(18)}';
    access[at] = {'sub': sub, 'family': family};
    final out = <String, dynamic>{
      'token_type': 'Bearer',
      'access_token': at,
      'expires_in': 600,
      'scope': scope
    };
    if (scope.split(' ').contains('openid')) {
      out['id_token'] = idToken(sub, nonce, at);
    }
    if (scope.split(' ').contains('offline_access')) {
      final fam = family ?? randomToken(6);
      final rt = 'rt_${randomToken(18)}';
      refresh[rt] = {'family': fam, 'used': false, 'sub': sub, 'scope': scope};
      access[at]!['family'] = fam;
      out['refresh_token'] = rt;
    }
    return out;
  }

  http.Response _j(int s, Object body) => http.Response(jsonEncode(body), s,
      headers: {'content-type': 'application/json'});

  late final http.Client client = MockClient((req) async {
    requests.add(req);
    final f = req.method == 'POST'
        ? Uri.splitQueryString(req.body)
        : <String, String>{};
    switch (req.url.path) {
      case '/.well-known/openid-configuration':
        return _j(200, discovery);
      case '/oauth/jwks.json':
        jwksFetches++;
        return _j(200, {
          'keys': [jwk]
        });
      case '/oauth/token':
        if (f['client_id'] != clientId || f.containsKey('client_secret')) {
          return _j(401, {'error': 'invalid_client'});
        }
        if (f['grant_type'] == 'authorization_code') {
          final c = codes[f['code']];
          if (c == null || c['used'] == true) {
            return _j(400, {'error': 'invalid_grant'});
          }
          c['used'] = true;
          if (c['redirect_uri'] != f['redirect_uri']) {
            return _j(400, {'error': 'invalid_grant'});
          }
          if (b64url(sha256
                  .convert(ascii.encode(f['code_verifier'] ?? ''))
                  .bytes) !=
              c['challenge']) {
            return _j(
                400, {'error': 'invalid_grant', 'error_description': 'PKCE'});
          }
          final out = _issue(
              c['sub'] as String, c['scope'] as String, c['nonce'] as String?);
          if (c['details'] != null) out['authorization_details'] = c['details'];
          return _j(200, out);
        }
        if (f['grant_type'] == 'refresh_token') {
          final r = refresh[f['refresh_token']];
          if (r == null || revokedFamilies.contains(r['family'])) {
            return _j(400, {'error': 'invalid_grant'});
          }
          if (r['used'] == true) {
            revokedFamilies.add(r['family'] as String);
            return _j(
                400, {'error': 'invalid_grant', 'error_description': 'reuse'});
          }
          r['used'] = true;
          return _j(
              200,
              _issue(r['sub'] as String, r['scope'] as String, null,
                  r['family'] as String));
        }
        return _j(400, {'error': 'unsupported_grant_type'});
      case '/oauth/userinfo':
        final a = access[
            (req.headers['Authorization'] ?? '').replaceFirst('Bearer ', '')];
        if (a == null || revokedFamilies.contains(a['family'])) {
          return _j(401, {'error': 'invalid_token'});
        }
        return _j(200, {'sub': a['sub'], 'email': 'ada@example.com'});
      case '/oauth/revoke':
        final r = refresh[f['token']];
        if (r != null) revokedFamilies.add(r['family'] as String);
        return http.Response('', 200);
    }
    return _j(404, {'error': 'not_found'});
  });

  /// The user signs in and consents; returns the redirect Identvia would send.
  String authorize(String url, {bool deny = false}) {
    final q = Uri.parse(url).queryParameters;
    final ru = q['redirect_uri']!;
    if (!redirectUris.contains(ru)) throw StateError('Invalid redirect');
    if (q['code_challenge_method'] != 'S256' ||
        q['nonce'] == null ||
        q['state'] == null) {
      throw StateError('bad request');
    }
    final params = <String, String>{'state': q['state']!};
    if (!omitIss) params['iss'] = wrongIss ? 'https://evil.example' : issuer;
    if (deny) {
      params['error'] = 'access_denied';
    } else {
      final code = 'c_${randomToken(18)}';
      codes[code] = {
        'challenge': q['code_challenge'],
        'redirect_uri': ru,
        'nonce': forceNonce ?? q['nonce'],
        'scope': q['scope'],
        'sub': userSub,
        'details': q['authorization_details'] != null
            ? jsonDecode(q['authorization_details']!)
            : null
      };
      params['code'] = code;
    }
    return Uri.parse(ru).replace(queryParameters: params).toString();
  }
}
