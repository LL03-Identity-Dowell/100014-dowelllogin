import { StyleSheet, Text, TextInput, TouchableOpacity, View } from 'react-native'
import React,{useState} from 'react';
import DropDownPicker from 'react-native-dropdown-picker';
import { CommonActions, useNavigation } from '@react-navigation/native' 
const Register = () => {
    return (
        <View>
            <Text style={styles.title}>Join with uxlivinglab</Text>
            <Text style={{textAlign:'center'}}>Select your role</Text>

            <Form/>
        </View>
    )
}

export default Register
const Form=()=>{
    const [open, setOpen] = useState(false);
    const [value, setValue] = useState(null);
    const [items, setItems] = useState([
      {label: 'Admin', value: 'Admin'},
      {label: 'Guest', value: 'Guest'},
    ]);
    return(
        <View >
             <DropDownPicker
             style={styles.picker}
      open={open}
      value={value}
      items={items}
      setOpen={setOpen}
      setValue={setValue}
      setItems={setItems}
      placeholder="Roles"
    />
    <NamesForm/>
    <TextInput
                style={styles.email}
                placeholder="User Email"
      />
      <CountryPhone/>
      <UserPass/>
      <Buttons/>
        </View>
    )
}
const Buttons=()=>{
    const navigation = useNavigation() 

    return(
        <View style={{flexDirection:'row',marginTop:20,paddingHorizontal:70}}>
            <TouchableOpacity
            style={styles.btn,styles.btn_cancel}
            onPress={() => navigation.navigate('Login')}>
<Text>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
            style={styles.btn,styles.btn_success}
           
            >
<Text>Sign Up</Text>
            </TouchableOpacity>
        </View>
    )
}
const UserPass=()=>{
    return(
        <View style={{flexDirection:'row',marginBottom:20}}>
            <TextInput
                style={styles.input}
                placeholder="User Name"
      />
       <TextInput
                style={styles.input}
                placeholder="Password"
      />
        </View>
    )
}
const NamesForm=()=>{
    return(
        <View style={{flexDirection:'row',marginBottom:20}}>
            <TextInput
                style={styles.input}
                placeholder="First Name"
      />
       <TextInput
                style={styles.input}
                placeholder="Last Name"
      />
        </View>
    )
}

const CountryPhone=()=>{
    return(
        <View style={{flexDirection:'row',marginBottom:20}}>
            <TextInput
                style={styles.input}
                placeholder="Country code"
      />
       <TextInput
                style={styles.input}
                placeholder="Phone Number"
      />
        </View>
    )
}

const styles = StyleSheet.create({
    title:{
        fontSize:30,
        textAlign:'center',
        margin:45,
        fontWeight:'bold'
    },
    input:{
        color:"white",
        backgroundColor:"#59701e",
        fontSize:14,
        width:160,
        height:40,
        borderRadius:6,
        paddingLeft:15,
        margin:10
    },
    email:{
        color:"white",
        backgroundColor:"#59701e",
        fontSize:14,
        height:40,
        borderRadius:6,
        paddingLeft:15,
        margin:10
    },
    picker:{
        color:"white",
        backgroundColor:"#a9bd8e",
        fontSize:14,
        width:340,
        height:40,
        borderRadius:6,
        paddingLeft:15,
        margin:10
    },
    btn_success:{
        color:"white",
        backgroundColor:"#34c759",
        fontSize:14,
        borderRadius:6,
        paddingLeft:10,
        marginTop:10,
        marginRight:10,
        marginBottom:10,

        width:100,
        height:30,
    },
    btn_cancel:{
        backgroundColor:"#d3d3d8",

        
        borderRadius:6,
        paddingLeft:10,
        margin:10,
        width:100,
        height:30,
    },
    btn:{
        margin:30
    },
})
