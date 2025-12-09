# OmniAuth Testing Guide

Current System Status:
- **Node.js/NPM**: ✅ Installed (v10.9.2)
- **Rust**: ❌ Not Detected
- **Go**: ❌ Not Detected

To test the system fully, you must install the missing build tools.

## 1. Prerequisites (Install These First)

### A. Rust (The Core)
Required to build the `crypto-core` and generate UniFFI bindings.
1. Download **Rustup**: [https://rustup.rs/](https://rustup.rs/)
2. Run the installer and select the default stable toolchain.
3. **Verify**: Open a new terminal and run `cargo --version`.

### B. Go (The Backend)
Required to run the Verifier and Rotation Engine.
1. Download **Go 1.21+**: [https://go.dev/dl/](https://go.dev/dl/)
2. Install and ensure `go` is in your PATH.
3. **Verify**: Run `go version`.

### C. Mobile Tools (React Native + Expo)
1. **Expo CLI**: `npm install -g expo-cli`
2. **Android**: Install [Android Studio](https://developer.android.com/studio).
3. **iOS** (Mac only): Install Xcode.

---

## 2. Running the Tests

Once the tools are installed, follow this sequence:

### Step 1: Test the Quantum Core (Rust)
This verifies that Kyber and Dilithium are working correctly.

```bash
cd oss/crypto-core
cargo test
```

*Expected Output:* `test result: ok. X passed; 0 failed.`

### Step 2: Test the Backend (Go)
This verifies the PQC signature verification logic.

```bash
cd proprietary/backend
go mod tidy
go test ./...
```

*Expected Output:* `PASS`

### Step 3: Run the Mobile App
Since you have NPM, you can install the JavaScript dependencies now:

```bash
cd oss/client-mobile
npm install
```

**To run the app on a physical device or emulator:**
```bash
npx expo run:android
# OR
npx expo run:ios
```
*Note: This will compile the Rust core into the app, taking a few minutes the first time.*

---

## 3. End-to-End Manual Test

1. **Start the Backend**:
   ```bash
   cd proprietary/backend
   go run cmd/worker/main.go
   ```
2. **Start the Mobile App**:
   ```bash
   cd oss/client-mobile
   npm start
   ```
3. **On the App**:
   - Enter a password (e.g., "secure_password").
   - Tap **Generate Identity**.
   - Wait for "Vault Created & Unlocked".
   - Tap **Test Signing**.
4. **Verification**:
   - The app should show a success alert with the signature length.
   - If connected to the backend (in a real scenario), the backend verify logs would show `AUTH SUCCESS`.
