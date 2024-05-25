import Card from "components/card";
import InputField from "components/fields/InputField";
import logo from "assets/img/Logo.png";
import { useEffect, useState } from "react";
import { login } from "./Auth";
import { useNavigate } from "react-router-dom";
export default function SignIn(props) {

    const [email,setEmail]=useState("");
    const [password,setPassword]=useState("");
    const navigate = useNavigate();

    const handleSignIn = async ()=>{
        try {
            await fetch("http://localhost:8080/user/signIn?email="+email+"&password="+password).then(async response =>{
                if(response.status!=202){
                    setEmail("");
                    setPassword(""); 
                }else{
                    const token= response.headers.get("Authorization");
                    const user= await response.json();
                    const JsonUser=JSON.stringify(user);
                    login(token,JsonUser);
                    window.location.href = '/main/documents'
                
                }    
            });
        } catch (error) {
            console.error("Error fetchingdata:", error);
        }
    }
    const getUserName = (value)=>{
        setEmail(value)
    }
    const getPassword = (value)=>{
        setPassword(value)
    }
  return (
    <div className="flex justify-center  items-start bg-white h-screen">
        <Card extra="!p-[5%] w-[30%] flex justify-center ">
        <div className={`flex items-center justify-center`}>
        <img
              className="h-[20%] w-[20%]"
              src={logo}
            />
            <div className=" ml-2 h-9 font-poppins text-center text-[150%] font-bold uppercase text-navy-700 dark:text-white">
            GW <span className="font-medium">Monitoring</span>
            </div>
        </div>      
        <Card extra="!p-[5%] w-[100%]">
        
      {/* Sign in section */}
        <div className=" items-center">
            {/* Email */}
            <InputField
            variant="auth"
            extra="mb-3"
            placeholder="name.lastName@pwc.com"
            id="email"
            type="text"
            sendValue={getUserName}
            input={email}
            />

            {/* Password */}
            <InputField
            variant="auth"
            extra="mb-3"
            placeholder="password"
            id="password"
            type="password"
            sendValue={getPassword}
            input={password}
            />
            {/* Checkbox */}
            <button onClick={handleSignIn} className="linear mt-2 w-full rounded-xl bg-brand-500 py-[12px] text-base font-medium text-white transition duration-200 hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:text-white dark:hover:bg-brand-300 dark:active:bg-brand-200">
                Sign In
            </button>
        </div>
        
    </Card>
    </Card>

    </div>
  );
}