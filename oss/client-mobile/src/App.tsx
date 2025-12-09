import React from 'react';
import { SafeAreaView, StatusBar } from 'react-native';
import RegistrationScreen from './screens/RegistrationScreen';

export default function App() {
    return (
        <SafeAreaView style={{ flex: 1 }}>
            <StatusBar barStyle="dark-content" />
            <RegistrationScreen />
        </SafeAreaView>
    );
}
