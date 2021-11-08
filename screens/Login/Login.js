import { ImageBackground, StyleSheet, SafeAreaView } from 'react-native'
import React from 'react'
import image from '../../assets/pexels-anna-shvets-3727464.jpg'
import Form from './Form'
const Login = () => {
    return (
        <SafeAreaView style={styles.container}>
        <ImageBackground source={image} resizeMode='cover' style={styles.image}>
            <Form/>
        </ImageBackground>
    </SafeAreaView>
    )
}

export default Login

const styles=StyleSheet.create({
    container: {
      flex: 1,
      position:'relative'

    },
    image: {
      flex: 1,
      justifyContent: "center"
    },
    
  });

