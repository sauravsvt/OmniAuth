import React, { useState } from 'react';
import { View, Text, TextInput, Button, ActivityIndicator, Alert, StyleSheet, Platform } from 'react-native';
import { CryptoService } from '../services/CryptoService';

export default function RegistrationScreen() {
    const [password, setPassword] = useState('');
    const [status, setStatus] = useState('Idle');
    const [debugKey, setDebugKey] = useState('');

    const handleCreateIdentity = async () => {
        if (password.length < 8) {
            Alert.alert('Security Alert', 'Password must be at least 8 characters.');
            return;
        }

        setStatus('Generating Quantum Keys...');

        // 1. Offload to Rust (Heavy CPU task)
        // We use setTimeout to allow UI to render the loading state before freezing slightly
        setTimeout(async () => {
            const success = await CryptoService.createVault(password);

            if (success) {
                // 2. Fetch the Public Key to show user (or send to API)
                const pubKey = CryptoService.getPublicKey();
                setDebugKey(pubKey);
                setStatus('Vault Created & Unlocked');
                Alert.alert('Success', 'Your identity is now Quantum-Proof.');
            } else {
                setStatus('Failed');
            }
        }, 100);
    };

    const handleTestSign = async () => {
        try {
            const nonce = "server_challenge_12345";
            const sig = CryptoService.signChallenge(nonce);

            // Real Backend Verification
            Alert.alert('Sending to Quantum Backend...', 'Verifying Dilithium Signature...');

            // Android Emulator needs 10.0.2.2, iOS Simulator uses localhost
            const baseUrl = Platform.OS === 'android' ? 'http://10.0.2.2:8080' : 'http://localhost:8080';

            const response = await fetch(`${baseUrl}/api/v1/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    public_key: debugKey,
                    message: nonce,
                    signature: sig
                })
            });

            const json = await response.json();

            if (json.success) {
                Alert.alert('✅ QUANTUM VERIFIED', 'The backend confirmed your Identity using Dilithium-3.');
            } else {
                Alert.alert('❌ REJECTED', `Backend Error: ${json.error}`);
            }

        } catch (e) {
            Alert.alert('Error', `Handshake failed: ${e}`);
        }
    };

    return (
        <View style={styles.container}>
            <Text style={styles.title}>OmniAuth</Text>
            <Text style={styles.subtitle}>Quantum-Safe Identity</Text>

            <TextInput
                style={styles.input}
                placeholder="Set Master Password"
                secureTextEntry
                value={password}
                onChangeText={setPassword}
            />

            <Button title="Generate Identity" onPress={handleCreateIdentity} />

            {status !== 'Idle' && <Text style={styles.status}>{status}</Text>}

            {debugKey ? (
                <View style={styles.debugArea}>
                    <Text style={styles.label}>Dilithium Public Key (Truncated):</Text>
                    <Text style={styles.code}>{debugKey.substring(0, 30)}...</Text>
                    <Button title="Test Signing (Mock Handshake)" onPress={handleTestSign} />
                </View>
            ) : null}
        </View>
    );
}

const styles = StyleSheet.create({
    container: { flex: 1, justifyContent: 'center', padding: 20, backgroundColor: '#f5f5f5' },
    title: { fontSize: 28, fontWeight: 'bold', textAlign: 'center', marginBottom: 5 },
    subtitle: { fontSize: 16, color: '#666', textAlign: 'center', marginBottom: 30 },
    input: { backgroundColor: 'white', padding: 15, borderRadius: 8, marginBottom: 15, borderWidth: 1, borderColor: '#ddd' },
    status: { marginTop: 20, textAlign: 'center', color: '#007AFF' },
    debugArea: { marginTop: 30, padding: 15, backgroundColor: '#e0e0e0', borderRadius: 8 },
    label: { fontSize: 12, fontWeight: 'bold', marginBottom: 5 },
    code: { fontFamily: 'monospace', fontSize: 10, marginBottom: 15, color: '#333' }
});
