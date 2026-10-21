import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:identvia/identvia.dart';

void main() {
  testWidgets('button renders label, mark, and calls onPressed', (t) async {
    var taps = 0;
    await t.pumpWidget(MaterialApp(
        home: Scaffold(
            body: Center(
                child: SignInWithIdentviaButton(
                    onPressed: () => taps++,
                    theme: IdentviaButtonTheme.dark,
                    text: IdentviaButtonText.continueWith)))));
    expect(find.text('Continue with Identvia'), findsOneWidget);
    expect(find.byType(IdentviaMark), findsOneWidget);
    await t.tap(find.byType(SignInWithIdentviaButton));
    expect(taps, 1);
    expect(t.getSize(find.byType(SignInWithIdentviaButton)).height, 40);
    final h = t.ensureSemantics();
    expect(
        t.getSemantics(find.bySemanticsLabel('Continue with Identvia')),
        matchesSemantics(
            label: 'Continue with Identvia',
            isButton: true,
            hasTapAction: true,
            isEnabled: true,
            hasEnabledState: true,
            isFocusable: true,
            hasFocusAction: true));
    h.dispose();
  });
  testWidgets('loading disables the button', (t) async {
    var taps = 0;
    await t.pumpWidget(MaterialApp(
        home: Scaffold(
            body: SignInWithIdentviaButton(
                onPressed: () => taps++,
                loading: true,
                size: IdentviaButtonSize.large))));
    await t.tap(find.byType(SignInWithIdentviaButton), warnIfMissed: false);
    expect(taps, 0);
    expect(t.getSize(find.byType(SignInWithIdentviaButton)).height, 48);
  });
}
