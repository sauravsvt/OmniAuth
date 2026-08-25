# Mobile Runtime Validation

Last checked: 2026-08-25.

## Passing Checks

From `oss/client-mobile`:

```bash
npm test -- --runInBand
npm run typecheck -- --noEmit
npm audit
env EXPO_NO_TELEMETRY=1 HOME=/tmp/omniauth-expo-home npx --yes expo-doctor
env EXPO_NO_TELEMETRY=1 HOME=/tmp/omniauth-expo-home npx expo config --type public
env EXPO_NO_TELEMETRY=1 HOME=/tmp/omniauth-expo-home npx expo start --offline --port 19001
curl -sS --max-time 5 http://127.0.0.1:19001/status
curl -sS --max-time 30 "http://127.0.0.1:19001/index.bundle?platform=android&dev=true&minify=false"
```

Results:

- Expo doctor passed all 21 checks.
- Expo public config resolves for SDK 57.
- Metro starts and reports `packager-status:running`.
- Android JS bundle compiles and includes `requireNativeModule('OmniAuth')`.
- Android emulator `Pixel_8_API_35` boots and is visible through ADB as `emulator-5554`.

## Native Runtime Blocker

`npx expo run:android --no-bundler --device emulator-5554` cannot validate the native challenge/vault/signing flow from the current checkout. Expo treats `oss/client-mobile/android/` as a malformed Android project, clears it, and regenerates a standard native app project.

The checked-in Android folder currently contains only:

```text
android/src/main/java/expo/modules/omniauth/OmniAuthModule.kt
```

That source file is not enough for a buildable Expo dev client. The native module needs proper Expo local-module or generated native-project integration before the runtime vault, signing, and backend challenge flow can be verified on device.

This remains prototype-level validation only. It is not a production security claim.
