import {NavigationContainer} from '@react-navigation/native';
import {createNativeStackNavigator} from '@react-navigation/native-stack';
import React from 'react';
import {SafeAreaView, StyleSheet, Text, View} from 'react-native';
import Login from './screens/Login/Login'
import Register from './screens/Register/Register';
import GlobalStyles from './screens/styles/globalStyles';

const {Navigator, Screen} = createNativeStackNavigator();

function App() {
    return (
        <NavigationContainer>
            <SafeAreaView style={GlobalStyles.droidSafeArea}>
                <Navigator screenOptions={{headerShown: false}} initialRouteName="Register">
                    <Screen name="Login" component={Login}></Screen>
                    <Screen name="Register" component={Register}></Screen>

                </Navigator>
            </SafeAreaView>
        </NavigationContainer>
    );
}

export default App