package expo.modules.omniauth

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
// Import the UniFFI generated bindings
import com.omniauth.core.Vault
import com.omniauth.core.Identity
import com.omniauth.core.AuthError

class OmniAuthModule : Module() {
  // Keep the Vault identity in memory (Native Side)
  // We do NOT send the Identity object to JS. We only send results.
  private var activeIdentity: Identity? = null

  override fun definition() = ModuleDefinition {
    Name("OmniAuth")

    // 1. Initialize / Create Vault
    // AsyncFunction prevents UI thread blocking during PQC key generation
    AsyncFunction("createVault") { password: String ->
      try {
        // Call Rust Constructor
        val vault = Vault(password)
        // Immediately unlock and store in memory (for this demo)
        activeIdentity = vault.unlock()
        return@AsyncFunction "SUCCESS"
      } catch (e: Exception) {
        throw Exception("Vault Creation Failed: ${e.message}")
      }
    }

    // 2. Get Public Keys (Safe to return to JS - lightweight, can stay sync)
    Function("getPublicKey") {
      activeIdentity?.let {
        return@Function it.getPublicSigningKey() // Returns Base64 String
      } ?: throw Exception("Vault Locked")
    }

    // 3. Sign a Challenge (The Core Auth Action)
    // AsyncFunction prevents main thread stutter on older devices
    AsyncFunction("signChallenge") { message: String ->
      activeIdentity?.let {
        // Rust performs Dilithium signing
        return@AsyncFunction it.signPayload(message) // Returns Base64 Signature
      } ?: throw Exception("Vault Locked")
    }

    // 4. Lock (Zeroize from memory side - sort of)
    Function("lock") {
      activeIdentity = null // Let GC handle it (Rust Drop trait will zeroize)
    }
  }
}
