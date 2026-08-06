import 'package:buzz/app.dart';
import 'package:buzz/shared/security/sensitive_action_authorizer.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';

void main() {
  testWidgets('protected cold launch authenticates before showing content', (
    tester,
  ) async {
    final authorizer = _FakeAuthorizer();
    await tester.pumpWidget(_testApp(authorizer: authorizer));
    await tester.pump();

    expect(authorizer.calls, 1);
    expect(find.text('Private content'), findsOneWidget);
    expect(find.byKey(const Key('app-lock-screen')), findsNothing);
  });

  testWidgets('cancelled cold launch stays on privacy-safe lock screen', (
    tester,
  ) async {
    final authorizer = _FakeAuthorizer(result: DeviceAuthResult.cancelled);
    await tester.pumpWidget(_testApp(authorizer: authorizer));
    await tester.pump();

    expect(find.byKey(const Key('app-lock-screen')), findsOneWidget);
    expect(find.text('Private content'), findsNothing);
    expect(find.text('Unlock with Face ID'), findsOneWidget);
  });

  testWidgets('resume inside five minutes remains unlocked', (tester) async {
    var now = DateTime.utc(2026, 8, 6);
    final authorizer = _FakeAuthorizer();
    await tester.pumpWidget(_testApp(authorizer: authorizer, now: () => now));
    await tester.pump();

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);

    now = now.add(const Duration(minutes: 4));
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();

    expect(authorizer.calls, 1);
    expect(find.text('Private content'), findsOneWidget);
  });

  testWidgets('resume after five minutes requires fresh authentication', (
    tester,
  ) async {
    var now = DateTime.utc(2026, 8, 6);
    final authorizer = _FakeAuthorizer();
    await tester.pumpWidget(_testApp(authorizer: authorizer, now: () => now));
    await tester.pump();

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    now = now.add(const Duration(minutes: 5));
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();

    expect(authorizer.calls, 2);
    expect(find.text('Private content'), findsOneWidget);
  });

  testWidgets('disabled protection never authenticates', (tester) async {
    final authorizer = _FakeAuthorizer();
    await tester.pumpWidget(_testApp(authorizer: authorizer, enabled: false));
    await tester.pump();

    expect(authorizer.calls, 0);
    expect(find.text('Private content'), findsOneWidget);
  });
}

Widget _testApp({
  required _FakeAuthorizer authorizer,
  DateTime Function()? now,
  bool enabled = true,
}) {
  return ProviderScope(
    overrides: [
      sensitiveActionAuthorizerProvider.overrideWithValue(authorizer),
      if (now != null) appLockClockProvider.overrideWithValue(now),
    ],
    child: MaterialApp(
      theme: ThemeData(platform: TargetPlatform.iOS),
      home: AppLockGate(
        enabled: enabled,
        child: const Scaffold(body: Text('Private content')),
      ),
    ),
  );
}

class _FakeAuthorizer implements SensitiveActionAuthorizer {
  _FakeAuthorizer({this.result = DeviceAuthResult.success});

  DeviceAuthResult result;
  int calls = 0;

  @override
  Future<DeviceAuthResult> authorizeIdentityAction() async {
    calls++;
    return result;
  }

  @override
  Future<bool> isSupported() async => true;
}
