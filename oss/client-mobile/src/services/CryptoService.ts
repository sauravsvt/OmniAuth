import { requireNativeModule } from 'expo-modules-core';

// Connect to the Kotlin/Swift Module defined above
const OmniAuthNative = requireNativeModule('OmniAuth');

export class CryptoService {
    /**
     * Generates a fresh Quantum-Safe Identity.
     * In a real app, this would also persist the Encrypted Blob to MMKV.
     */
    static async createVault(password: string): Promise<boolean> {
        try {
            const result = OmniAuthNative.createVault(password);
            return result === 'SUCCESS';
        } catch (e) {
            console.error('Failed to create vault', e);
            return false;
        }
    }

    /**
     * Returns the Dilithium3 Public Key (Base64).
     * Used during User Registration.
     */
    static getPublicKey(): string {
        try {
            return OmniAuthNative.getPublicKey();
        } catch (e) {
            return '';
        }
    }

    /**
     * Signs a server nonce using the Dilithium Private Key.
     * @param nonce The random string from the server
     */
    static signChallenge(nonce: string): string {
        try {
            return OmniAuthNative.signChallenge(nonce);
        } catch (e) {
            console.error('Signing failed', e);
            throw e;
        }
    }

    static lock(): void {
        OmniAuthNative.lock();
    }
}
