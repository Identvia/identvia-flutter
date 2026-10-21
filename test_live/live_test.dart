// Against a REAL Identvia server (stage 4+). Run:
//   IDENTVIA_LIVE_STATE=/tmp/live-state.json flutter test test_live
// (state file produced by tools/live/helper.php setup in the identvia-sdks monorepo checkout)
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:identvia/identvia.dart';

class HelperBrowser implements AuthBrowser {
  HelperBrowser(this.statePath);
  final String statePath;
  @override
  Future<String> authenticate(String url, Uri redirectUri,
      {required bool ephemeral}) async {
    if (url.contains('/oauth/logout')) return redirectUri.toString();
    final r = await Process.run(
        'php', ['../tools/live/helper.php', 'browse', statePath, url]);
    if (r.exitCode != 0) throw StateError('helper failed: ${r.stderr}');
    return (r.stdout as String).trim();
  }
}

void main() {
  final path = Platform.environment['IDENTVIA_LIVE_STATE'];
  final s = path == null
      ? null
      : jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
  test('sign-in, refresh rotation, userinfo, sign-out against a real server',
      () async {
    final store = MemoryTokenStore();
    final c = IdentviaClient(
        issuer: s!['base'] as String,
        clientId: s['publicClientId'] as String,
        redirectUri: s['publicRedirect'] as String,
        browser: HelperBrowser(path!),
        store: store,
        refreshLeeway: const Duration(hours: 1));
    final session = await c.signIn();
    expect(session.user.email, s['userEmail']);
    final rt1 =
        store.values.entries.firstWhere((e) => e.key.endsWith('.rt')).value;
    await c.getAccessToken();
    final rt2 =
        store.values.entries.firstWhere((e) => e.key.endsWith('.rt')).value;
    expect(rt2, isNot(rt1));
    expect((await c.userinfo())['sub'], session.user.sub);
    await c.signOut();
    expect(store.values, isEmpty);
  }, skip: s == null ? 'set IDENTVIA_LIVE_STATE' : false);
}
