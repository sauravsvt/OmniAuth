package expo.modules.omniauth

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import com.omniauth.core.Vault

class OmniAuthModule : Module() {
  private var activeVault: Vault? = null

  override fun definition() = ModuleDefinition {
    Name("OmniAuth")

    AsyncFunction("createVault") { password: String ->
      try {
        val vault = Vault(password)
        activeVault = vault
        return@AsyncFunction "SUCCESS"
      } catch (e: Exception) {
        throw Exception("Vault Creation Failed: ${e.message}")
      }
    }

    AsyncFunction("getPublicKey") { password: String ->
      val vault = activeVault ?: throw Exception("No active vault")
      try {
        return@AsyncFunction vault.getPublicSigningKey(password)
      } catch (e: Exception) {
        throw Exception("Failed to get public key: ${e.message}")
      }
    }

    AsyncFunction("signChallenge") { password: String, message: String ->
      val vault = activeVault ?: throw Exception("No active vault")
      try {
        return@AsyncFunction vault.sign(password, message)
      } catch (e: Exception) {
        throw Exception("Signing failed: ${e.message}")
      }
    }

    Function("exportBlob") {
      val vault = activeVault ?: throw Exception("No active vault")
      return@Function vault.exportEncryptedBlob()
    }

    AsyncFunction("restoreVault") { encryptedBlob: String ->
      try {
        activeVault = Vault.newWithBlob(encryptedBlob)
        return@AsyncFunction "SUCCESS"
      } catch (e: Exception) {
        throw Exception("Vault Restore Failed: ${e.message}")
      }
    }

    Function("lock") {
      activeVault = null
    }
  }
}
