import 'package:flutter/material.dart';
import 'package:identvia/identvia.dart';

// Register a *public* (no secret) client at https://identvia.com/developers with this redirect URI.
// Never put a client secret in a mobile app.
final identvia = IdentviaClient(
  clientId: const String.fromEnvironment('IDENTVIA_CLIENT_ID',
      defaultValue: 'oid_your_client_id'),
  redirectUri: 'com.example.identvia.example:/oauth/identvia',
);

void main() => runApp(const MaterialApp(home: HomePage()));

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  IdentviaSession? _session;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    identvia.currentSession().then((s) => setState(() => _session = s));
  }

  Future<void> _run(Future<void> Function() f) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await f();
    } on CancelledException {
      // user closed the browser
    } on IdentviaException catch (e) {
      _error = e.toString();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = _session;
    return Scaffold(
      appBar: AppBar(title: const Text('Identvia example')),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            if (s == null)
              SignInWithIdentviaButton(
                loading: _busy,
                onPressed: () => _run(() async {
                  final r = await identvia.signIn();
                  setState(() => _session = r);
                }),
              )
            else ...[
              Text('Signed in as ${s.user.name ?? s.user.email ?? s.user.sub}'),
              const SizedBox(height: 8),
              Text('Pairwise sub: ${s.user.sub}',
                  style: Theme.of(context).textTheme.bodySmall),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: _busy
                    ? null
                    : () => _run(() async {
                          final info = await identvia.userinfo();
                          if (context.mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text('userinfo: $info')));
                          }
                        }),
                child: const Text('Call userinfo'),
              ),
              TextButton(
                onPressed: _busy
                    ? null
                    : () => _run(() async {
                          await identvia.signOut();
                          setState(() => _session = null);
                        }),
                child: const Text('Sign out'),
              ),
            ],
            if (_error != null)
              Padding(
                  padding: const EdgeInsets.only(top: 16),
                  child:
                      Text(_error!, style: const TextStyle(color: Colors.red))),
          ]),
        ),
      ),
    );
  }
}
