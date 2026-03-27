import { requireNativeModule } from 'expo-modules-core';

const OmniAuthNative = requireNativeModule('OmniAuth');

export class CryptoService {
    /**
     * Creates a new Quantum-Safe Vault with PQC key material.
     * The vault encrypts identity keys using the master password (Argon2id + XChaCha20-Poly1305).
     */
    static async createVault(password: string): Promise<boolean> {
        try {
            const result = await OmniAuthNative.createVault(password);
            return result === 'SUCCESS';
        } catch (e) {
            console.error('Failed to create vault', e);
            return false;
        }
    }

    /**
     * Returns the Dilithium3 Public Key (Base64).
     * Requires password to verify vault integrity before extracting.
     */
    static async getPublicKey(password: string): Promise<string> {
        try {
            return await OmniAuthNative.getPublicKey(password);
        } catch (e) {
            console.error('Failed to get public key', e);
            return '';
        }
    }

    /**
     * Signs a server challenge using the Dilithium Private Key.
     * The private key is decrypted transiently -- it never persists in memory.
     * @param password The master password to decrypt the vault
     * @param message The challenge/nonce from the server
     */
    static async signChallenge(password: string, message: string): Promise<string> {
        try {
            return await OmniAuthNative.signChallenge(password, message);
        } catch (e) {
            console.error('Signing failed', e);
            throw e;
        }
    }

    /**
     * Exports the encrypted vault blob for persistence (e.g., to MMKV or SecureStore).
     */
    static exportBlob(): string {
        return OmniAuthNative.exportBlob();
    }

    /**
     * Restores a vault from a previously exported encrypted blob.
     */
    static async restoreVault(encryptedBlob: string): Promise<boolean> {
        try {
            const result = await OmniAuthNative.restoreVault(encryptedBlob);
            return result === 'SUCCESS';
        } catch (e) {
            console.error('Failed to restore vault', e);
            return false;
        }
    }

    /**
     * Locks the vault by clearing it from memory.
     */
    static lock(): void {
        OmniAuthNative.lock();
    }
}
