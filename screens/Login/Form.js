import { StyleSheet, View, TextInput, Text, TouchableOpacity } from 'react-native'
import React,{useState} from 'react'
import DropDownPicker from 'react-native-dropdown-picker';
import { CommonActions, useNavigation } from '@react-navigation/native' 

const Form = () => {

    return (
        <View style={styles.form}>
<FullForm/>
        </View>
    )
}
const FullForm=()=>{
    return(
        <View style={{flexDirection:'row'}}>
        <LeftForm/>
     <RightForm/>
     </View>
    )
}
const RightForm=()=>{
return(
    <View>
 <TextInput
                style={styles.input}
                placeholder="user name"
      />
       <TextInput
                style={styles.input}
                placeholder="password"
      />
    </View>
)
}
const LeftForm=()=>{
    const [open, setOpen] = useState(false);
    const [value, setValue] = useState(null);
    const [items, setItems] = useState([
      {label: 'English', value: 'English'},
      {label: 'Wakanda', value: 'Wakanda'}
    ]);
    return(
        
        <View 
        // style={{flexDirection:'row'}}
        >
             <DropDownPicker
             style={styles.input}
      open={open}
      value={value}
      items={items}
      setOpen={setOpen}
      setValue={setValue}
      setItems={setItems}
      placeholder="Language"
    />
    <Buttons/>
           
        </View>
    )
}
const Buttons=()=>{
    const navigation = useNavigation() 

    return(
        <View style={{flexDirection:'row'}}>
              <TouchableOpacity
            style={styles.btn,styles.btn_register} 
            onPress={() => navigation.navigate('Register')}
            >
<Text>Get Started</Text>
            </TouchableOpacity>

            <TouchableOpacity
            style={styles.btn,styles.btn_success}>
<Text>Login</Text>
            </TouchableOpacity>
        </View>
    )
}
export default Form

const styles = StyleSheet.create({
    form:{
        marginLeft:5,
        marginRight:5,
    bottom:40,
    position:'absolute'
    },
    input:{
        color:"white",
        backgroundColor:"#59701e",
        fontSize:14,
        width:160,
        height:30,
        borderRadius:6,
        paddingLeft:15,
        margin:10
    },
    btn:{
        margin:20
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

        width:50,
        height:30,
    },
    btn_register:{
        backgroundColor:"#838b85",
        fontSize:14,
        borderRadius:6,
        paddingLeft:10,
        margin:10,
        width:100,
        height:30,
    }
})
