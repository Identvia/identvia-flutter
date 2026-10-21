import 'package:flutter/material.dart';

enum IdentviaButtonTheme { light, dark, brand }

enum IdentviaButtonSize { small, medium, large }

enum IdentviaButtonShape { rect, rounded, pill }

enum IdentviaButtonText { signIn, continueWith, signUp }

/// The official "Sign in with Identvia" button (same colours, sizes and shapes as button.js).
class SignInWithIdentviaButton extends StatelessWidget {
  const SignInWithIdentviaButton({
    super.key,
    required this.onPressed,
    this.theme = IdentviaButtonTheme.light,
    this.size = IdentviaButtonSize.medium,
    this.shape = IdentviaButtonShape.rounded,
    this.text = IdentviaButtonText.signIn,
    this.fullWidth = false,
    this.loading = false,
  });

  final VoidCallback? onPressed;
  final IdentviaButtonTheme theme;
  final IdentviaButtonSize size;
  final IdentviaButtonShape shape;
  final IdentviaButtonText text;
  final bool fullWidth;
  final bool loading;

  static const _brand = Color(0xFF4B4ACF);

  String get label => switch (text) {
        IdentviaButtonText.signIn => 'Sign in with Identvia',
        IdentviaButtonText.continueWith => 'Continue with Identvia',
        IdentviaButtonText.signUp => 'Sign up with Identvia',
      };

  @override
  Widget build(BuildContext context) {
    final (h, px, fs, icon, r) = switch (size) {
      IdentviaButtonSize.small => (32.0, 12.0, 13.0, 16.0, 6.0),
      IdentviaButtonSize.medium => (40.0, 16.0, 14.0, 20.0, 8.0),
      IdentviaButtonSize.large => (48.0, 20.0, 16.0, 22.0, 10.0),
    };
    final (bg, border, fg) = switch (theme) {
      IdentviaButtonTheme.light => (
          Colors.white,
          const Color(0xFFD4D4D8),
          const Color(0xFF18181B)
        ),
      IdentviaButtonTheme.dark => (
          const Color(0xFF18181B),
          const Color(0xFF3F3F46),
          Colors.white
        ),
      IdentviaButtonTheme.brand => (_brand, _brand, Colors.white),
    };
    final radius = switch (shape) {
      IdentviaButtonShape.rect => 4.0,
      IdentviaButtonShape.rounded => r,
      IdentviaButtonShape.pill => h / 2
    };
    final child = Row(
      mainAxisSize: fullWidth ? MainAxisSize.max : MainAxisSize.min,
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        loading
            ? SizedBox.square(
                dimension: icon,
                child: CircularProgressIndicator(strokeWidth: 2, color: fg))
            : IdentviaMark(size: icon),
        SizedBox(
            width: size == IdentviaButtonSize.small
                ? 8
                : size == IdentviaButtonSize.large
                    ? 12
                    : 10),
        Flexible(
            child: Text(label,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                    fontSize: fs,
                    fontWeight: FontWeight.w600,
                    color: fg,
                    letterSpacing: -0.1))),
      ],
    );
    // The OutlinedButton supplies the button role and the tap/focus actions; the inner
    // Semantics gives one clean label (the mark/spinner are decorative).
    return SizedBox(
      height: h,
      width: fullWidth ? double.infinity : null,
      child: OutlinedButton(
        onPressed: loading ? null : onPressed,
        style: OutlinedButton.styleFrom(
          backgroundColor: bg,
          foregroundColor: fg,
          disabledBackgroundColor: bg.withValues(alpha: 0.5),
          side: BorderSide(color: border),
          padding: EdgeInsets.symmetric(horizontal: px),
          shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(radius)),
        ),
        child: Semantics(label: label, excludeSemantics: true, child: child),
      ),
    );
  }
}

/// The Identvia mark (brand square with dot and check), drawn from the same geometry as the SVG logo.
class IdentviaMark extends StatelessWidget {
  const IdentviaMark({super.key, this.size = 20});
  final double size;
  @override
  Widget build(BuildContext context) =>
      CustomPaint(size: Size.square(size), painter: _MarkPainter());
}

class _MarkPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final s = size.width / 28;
    canvas.drawRRect(
        RRect.fromRectAndRadius(Offset.zero & size, Radius.circular(8 * s)),
        Paint()..color = const Color(0xFF4B4ACF));
    canvas.drawCircle(
        Offset(9.25 * s, 8.25 * s), 2.1 * s, Paint()..color = Colors.white);
    final p = Path()
      ..moveTo(8.6 * s, 13.4 * s)
      ..lineTo(12.5 * s, 19.5 * s)
      ..lineTo(20.4 * s, 8 * s);
    canvas.drawPath(
        p,
        Paint()
          ..color = Colors.white
          ..style = PaintingStyle.stroke
          ..strokeWidth = 2.6 * s
          ..strokeCap = StrokeCap.round
          ..strokeJoin = StrokeJoin.round);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
