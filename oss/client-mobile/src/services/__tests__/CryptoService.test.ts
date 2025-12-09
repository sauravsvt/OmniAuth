import { CryptoService } from '../CryptoService';
import { requireNativeModule } from 'expo-modules-core';

// Mock the Expo Native Module
jest.mock('expo-modules-core', () => ({
    requireNativeModule: jest.fn(() => ({
        createVault: jest.fn((pwd) => 'SUCCESS'),
        getPublicKey: jest.fn(() => 'mock_dilithium_pk_base64'),
        signChallenge: jest.fn((msg) => `signed_${msg}`),
        lock: jest.fn(),
    })),
}));

describe('CryptoService', () => {
    it('should return true when vault creation succeeds', async () => {
        const result = await CryptoService.createVault('strong_password');
        expect(result).toBe(true);
    });

    it('should return the public key', () => {
        const pk = CryptoService.getPublicKey();
        expect(pk).toBe('mock_dilithium_pk_base64');
    });

    it('should sign the challenge correctly', () => {
        const signature = CryptoService.signChallenge('nonce_123');
        expect(signature).toBe('signed_nonce_123');
    });
});
