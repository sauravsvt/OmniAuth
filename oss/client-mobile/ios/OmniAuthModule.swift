import ExpoModulesCore
import omniauth_core

public class OmniAuthModule: Module {
  private var activeVault: Vault? = nil
  private var activePassword: String? = nil

  public func definition() -> ModuleDefinition {
    Name("OmniAuth")

    AsyncFunction("createVault") { (password: String) -> String in
      do {
        let vault = try Vault(masterPassword: password)
        self.activeVault = vault
        self.activePassword = password
        return "SUCCESS"
      } catch {
        throw Exception(name: "VaultCreationError", description: error.localizedDescription)
      }
    }

    AsyncFunction("getPublicKey") { (password: String) -> String in
      guard let vault = self.activeVault else {
        throw Exception(name: "NoVault", description: "No active vault")
      }
      do {
        return try vault.getPublicSigningKey(password: password)
      } catch {
        throw Exception(name: "GetKeyError", description: error.localizedDescription)
      }
    }

    AsyncFunction("signChallenge") { (password: String, message: String) -> String in
      guard let vault = self.activeVault else {
        throw Exception(name: "NoVault", description: "No active vault")
      }
      do {
        return try vault.sign(password: password, message: message)
      } catch {
        throw Exception(name: "SignError", description: error.localizedDescription)
      }
    }

    Function("exportBlob") { () -> String in
      guard let vault = self.activeVault else {
        throw Exception(name: "NoVault", description: "No active vault")
      }
      do {
        return try vault.exportEncryptedBlob()
      } catch {
        throw Exception(name: "ExportError", description: error.localizedDescription)
      }
    }

    AsyncFunction("restoreVault") { (encryptedBlob: String) -> String in
      do {
        self.activeVault = try Vault.newWithBlob(encryptedBlobStr: encryptedBlob)
        return "SUCCESS"
      } catch {
        throw Exception(name: "RestoreError", description: error.localizedDescription)
      }
    }

    Function("lock") {
      self.activeVault = nil
      self.activePassword = nil
    }
  }
}
