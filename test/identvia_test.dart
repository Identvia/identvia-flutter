import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:identvia/identvia.dart';
import 'package:identvia/src/pkce.dart' show b64url;

import 'fake_identvia.dart';

const redirect = 'com.example.notes:/oauth/identvia';

class FakeBrowser implements AuthBrowser {
  FakeBrowser(this.idp, {this.deny = false, this.tamper, this.cancel = false});
  final FakeIdentvia idp;
  final bool deny, cancel;
  final String Function(String)? tamper;
  final opened = <String>[];
  @override
  Future<String> authenticate(String url, Uri redirectUri,
      {required bool ephemeral}) async {
    opened.add(url);
    if (cancel) throw CancelledException();
    if (url.contains('/oauth/logout')) return redirectUri.toString();
    final cb = idp.authorize(url, deny: deny);
    return tamper != null ? tamper!(cb) : cb;
  }
}

(IdentviaClient, FakeIdentvia, FakeBrowser, MemoryTokenStore) make(
    {FakeIdentvia? idp,
    bool deny = false,
    bool cancel = false,
    String Function(String)? tamper,
    Duration leeway = const Duration(seconds: 60)}) {
  final f = idp ?? FakeIdentvia();
  final b = FakeBrowser(f, deny: deny, tamper: tamper, cancel: cancel);
  final store = MemoryTokenStore();
  final c = IdentviaClient(
      issuer: issuer,
      clientId: clientId,
      redirectUri: redirect,
      browser: b,
      store: store,
      httpClient: f.client,
      refreshLeeway: leeway);
  return (c, f, b, store);
}

void main() {
  group('PKCE', () {
    test('RFC 7636 Appendix B vector', () {
      expect(codeChallengeS256('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
          'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    });
    test('verifiers are 64 chars and unique', () {
      final a = Pkce.generate(), b = Pkce.generate();
      expect(a.verifier.length, 64);
      expect(a.verifier, isNot(b.verifier));
      expect(a.challenge, codeChallengeS256(a.verifier));
      expect(() => codeChallengeS256('short'),
          throwsA(isA<ConfigurationException>()));
    });
  });

  group('configuration', () {
    test('redirect URI rules (RFC 8252)', () {
      expect(assertNativeRedirect('com.example.app:/cb').scheme,
          'com.example.app');
      expect(assertNativeRedirect('https://app.example.com/cb').host,
          'app.example.com');
      expect(assertNativeRedirect('http://127.0.0.1:8123/cb').port, 8123);
      for (final bad in [
        'myapp://cb',
        'http://app.example.com/cb',
        'com.example.app:/cb#x',
        'javascript:alert(1)'
      ]) {
        expect(() => assertNativeRedirect(bad),
            throwsA(isA<ConfigurationException>()),
            reason: bad);
      }
    });
    test('issuer must be https', () {
      expect(
          () => IdentviaClient(
              issuer: 'http://id.identvia.com',
              clientId: 'x',
              redirectUri: redirect,
              store: MemoryTokenStore()),
          throwsA(isA<ConfigurationException>()));
    });
  });

  group('sign-in', () {
    test(
        'full flow: PKCE, state, nonce, iss, signature; tokens stored with the refresh token separate',
        () async {
      final (c, f, b, store) = make();
      final s = await c.signIn(prompt: 'login');
      expect(s.user.email, 'ada@example.com');
      expect(s.user.sub, f.userSub);
      final q = Uri.parse(b.opened.single).queryParameters;
      expect(q['code_challenge_method'], 'S256');
      expect(q['scope'], 'openid email profile offline_access');
      expect(store.values.keys.toSet(),
          {'identvia.$clientId.session', 'identvia.$clientId.rt'});
      expect(
          store.values['identvia.$clientId.session'], isNot(contains('rt_')));
      final tokenReq =
          f.requests.firstWhere((r) => r.url.path == '/oauth/token');
      expect(Uri.splitQueryString(tokenReq.body).containsKey('client_secret'),
          isFalse);
    });
    test('cancel', () async {
      final (c, _, _, store) = make(cancel: true);
      await expectLater(c.signIn(), throwsA(isA<CancelledException>()));
      expect(store.values, isEmpty);
    });
    test('access_denied', () async {
      final (c, _, _, _) = make(deny: true);
      await expectLater(
          c.signIn(),
          throwsA(isA<AuthorizationException>()
              .having((e) => e.error, 'error', 'access_denied')));
    });
    for (final (name, tamper) in [
      (
        'forged state',
        (String u) => u.replaceFirst(RegExp(r'state=[^&]+'), 'state=forged')
      ),
      (
        'another app\'s redirect',
        (String u) => u.replaceFirst('com.example.notes:', 'com.evil.app:')
      ),
    ]) {
      test('rejects $name', () async {
        final (c, _, _, _) = make(tamper: tamper);
        await expectLater(c.signIn(), throwsA(isA<InvalidStateException>()));
      });
    }
    test('rejects wrong and missing iss', () async {
      final f = FakeIdentvia()..wrongIss = true;
      await expectLater(
          make(idp: f).$1.signIn(), throwsA(isA<InvalidStateException>()));
      final g = FakeIdentvia()..omitIss = true;
      await expectLater(
          make(idp: g).$1.signIn(), throwsA(isA<InvalidStateException>()));
    });
    test('rejects nonce replay', () async {
      final f = FakeIdentvia()..forceNonce = 'attacker';
      await expectLater(
          make(idp: f).$1.signIn(),
          throwsA(isA<ValidationException>()
              .having((e) => e.message, 'm', contains('nonce'))));
    });
  });

  group('ID token validation', () {
    Future<void> expectReject(
        Map<String, dynamic> Function(Map<String, dynamic>) patch,
        String contains_,
        {Map<String, dynamic>? header,
        bool otherKey = false}) async {
      final f = FakeIdentvia();
      final other = otherKey ? rsaKeyPair() : null;
      f.idTokenOverride = (c) => signRs256(
          header ?? {'alg': 'RS256', 'kid': 'k1'},
          patch(c),
          other?.privateKey ?? f.keys.privateKey);
      await expectLater(
          make(idp: f).$1.signIn(),
          throwsA(isA<ValidationException>()
              .having((e) => e.message, 'message', contains(contains_))));
    }

    test(
        'wrong issuer',
        () => expectReject(
            (c) => {...c, 'iss': 'https://evil.example'}, 'issuer'));
    test(
        'wrong audience',
        () =>
            expectReject((c) => {...c, 'aud': 'other', 'azp': 'other'}, 'aud'));
    test('expired',
        () => expectReject((c) => {...c, 'exp': 1000, 'iat': 900}, 'expired'));
    test(
        'issued in the future',
        () => expectReject(
            (c) => {
                  ...c,
                  'iat': (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600
                },
            'future'));
    test('signed by another key',
        () => expectReject((c) => c, 'signature', otherKey: true));
    test(
        'unknown kid',
        () => expectReject((c) => c, 'unknown key',
            header: {'alg': 'RS256', 'kid': 'nope'}));
    test(
        'at_hash mismatch',
        () => expectReject(
            (c) => {...c, 'at_hash': 'AAAAAAAAAAAAAAAAAAAAAA'}, 'at_hash'));
    test('alg none', () async {
      final f = FakeIdentvia();
      f.idTokenOverride = (c) =>
          '${b64url(utf8.encode('{"alg":"none","kid":"k1"}'))}.${b64url(utf8.encode(jsonEncode(c)))}.';
      await expectLater(
          make(idp: f).$1.signIn(),
          throwsA(isA<ValidationException>()
              .having((e) => e.message, 'm', contains('none'))));
    });
    test('HS256 alg confusion', () async {
      final f = FakeIdentvia();
      f.idTokenOverride = (c) =>
          '${b64url(utf8.encode('{"alg":"HS256","kid":"k1"}'))}.${b64url(utf8.encode(jsonEncode(c)))}.AAAA';
      await expectLater(
          make(idp: f).$1.signIn(),
          throwsA(isA<ValidationException>()
              .having((e) => e.message, 'm', contains('HS256'))));
    });
  });

  group('tokens', () {
    test('refresh rotation, single-flight', () async {
      final (c, f, _, store) = make(leeway: const Duration(hours: 1));
      await c.signIn();
      final rt1 = store.values['identvia.$clientId.rt'];
      final r = await Future.wait(
          [c.getAccessToken(), c.getAccessToken(), c.getAccessToken()]);
      expect(r.toSet().length, 1);
      expect(
          f.requests
              .where((x) =>
                  x.url.path == '/oauth/token' &&
                  x.body.contains('grant_type=refresh_token'))
              .length,
          1);
      expect(store.values['identvia.$clientId.rt'], isNot(rt1));
    });
    test('reuse detection signs the user out', () async {
      final (c, f, _, store) = make(leeway: const Duration(hours: 1));
      await c.signIn();
      final old = store.values['identvia.$clientId.rt']!;
      await c.getAccessToken();
      await f.client.post(Uri.parse('$issuer/oauth/token'), body: {
        'grant_type': 'refresh_token',
        'refresh_token': old,
        'client_id': clientId
      });
      await expectLater(
          c.getAccessToken(),
          throwsA(isA<TokenException>()
              .having((e) => e.error, 'error', 'login_required')));
      expect(store.values, isEmpty);
    });
    test('session survives restart; userinfo checks sub', () async {
      final (c, f, b, store) = make();
      await c.signIn();
      final again = IdentviaClient(
          issuer: issuer,
          clientId: clientId,
          redirectUri: redirect,
          browser: b,
          store: store,
          httpClient: f.client);
      expect((await again.currentSession())!.user.sub, f.userSub);
      expect((await again.userinfo())['sub'], f.userSub);
    });
    test('signOut revokes, clears and can end the Identvia session', () async {
      final (c, f, b, store) = make();
      await c.signIn();
      await c.signOut(federated: true);
      expect(f.revokedFamilies.length, 1);
      expect(store.values, isEmpty);
      final q = Uri.parse(b.opened.last).queryParameters;
      expect(q['id_token_hint'], isNotNull);
      expect(q['post_logout_redirect_uri'], redirect);
    });
    test('authorization_details (RAR) requires server 2026-10-21_5+', () async {
      await expectLater(
          make().$1.signIn(
              authorizationDetails: [AuthorizationDetail.agentTask('x')]),
          throwsA(isA<UnsupportedException>()));
      final s = await make(idp: FakeIdentvia(stage5: true)).$1.signIn(
          authorizationDetails: [
            AuthorizationDetail.agentTask('Order groceries')
          ]);
      expect(s.tokens.authorizationDetails!.first['type'], 'agent_task');
    });
  });
}
