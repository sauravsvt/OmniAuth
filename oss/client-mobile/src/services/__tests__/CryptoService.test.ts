import { CryptoService } from '../CryptoService';

jest.mock('expo-modules-core', () => ({
    requireNativeModule: jest.fn(() => ({
        createVault: jest.fn((_pwd: string) => Promise.resolve('SUCCESS')),
        getPublicKey: jest.fn((_pwd: string) => Promise.resolve('mock_dilithium_pk_base64')),
        signChallenge: jest.fn((_pwd: string, msg: string) => Promise.resolve(`signed_${msg}`)),
        exportBlob: jest.fn(() => '{"version":1,"salt":"...","nonce":"...","ciphertext":"..."}'),
        restoreVault: jest.fn((_blob: string) => Promise.resolve('SUCCESS')),
        lock: jest.fn(),
    })),
}));

describe('CryptoService', () => {
    it('should return true when vault creation succeeds', async () => {
        const result = await CryptoService.createVault('strong_password');
        expect(result).toBe(true);
    });

    it('should return the public key given a password', async () => {
        const pk = await CryptoService.getPublicKey('strong_password');
        expect(pk).toBe('mock_dilithium_pk_base64');
    });

    it('should sign the challenge with password and message', async () => {
        const signature = await CryptoService.signChallenge('strong_password', 'nonce_123');
        expect(signature).toBe('signed_nonce_123');
    });

    it('should export the encrypted vault blob', () => {
        const blob = CryptoService.exportBlob();
        expect(blob).toContain('version');
    });

    it('should restore a vault from an encrypted blob', async () => {
        const result = await CryptoService.restoreVault('{"version":1}');
        expect(result).toBe(true);
    });
});
