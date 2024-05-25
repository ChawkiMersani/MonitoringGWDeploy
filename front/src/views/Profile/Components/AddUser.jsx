
import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalBody,
  } from "@chakra-ui/modal";
  import { useDisclosure } from "@chakra-ui/hooks";
import Card from "components/card";
import InputField from "components/fields/InputField";
import { useState } from "react";
import Switch from "components/Switch";
import { getToken } from "views/SignIn/Auth";

const AddUser = () => {
    const { isOpen, onOpen, onClose } = useDisclosure();
    const token=getToken();
    const [email,setEmail]=useState("");
    const [password,setPassword]=useState("");
    const [role,setRole]=useState("USER");
    const getUserName = (value)=>{
      setEmail(value)
  }
  const getPassword = (value)=>{
      setPassword(value)
  }
  const getRole = (value)=>{
    if(value){
      setRole("ADMIN");
    }else{
      setRole("USER");
    }
}
  const saveUser = ()=>{
    fetch("http://localhost:8080/user/register",{
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        email:email,
        password: password,
        role: role
      })
    })
}
    return (
     
    <>
      <div onClick={onOpen}>
        <button className="flex linear rounded-[20px] bg-lightPrimary px-4 py-2 text-base font-medium text-brand-500 transition duration-200 hover:bg-gray-100 active:bg-gray-200 dark:bg-white/5 dark:text-white dark:hover:bg-white/10 dark:active:bg-white/20">
          Add user
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" className="w-6 h-6">
                <path stroke-linecap="round" stroke-linejoin="round" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0ZM3 19.235v-.11a6.375 6.375 0 0 1 12.75 0v.109A12.318 12.318 0 0 1 9.374 21c-2.331 0-4.512-.645-6.374-1.766Z" />
            </svg>
        </button>
      </div>
      <Modal isOpen={isOpen} onClose={onClose} className="!z-[1010]">
        <ModalOverlay className="bg-[#000] !opacity-30" />
        <ModalContent className="!z-[1002] !m-auto !w-max min-w-[350px] !max-w-[85%] md:top-[12vh]">
          <ModalBody>
            <Card extra="px-[30px] pt-[35px] pb-[40px] max-w-[450px] flex flex-col !z-[1004]">
              <h1 className="mb-[20px] text-2xl font-bold">Add new user</h1>
              <InputField
            variant="auth"
            extra="mb-3"
            placeholder="name.lastName@pwc.com"
            id="email"
            type="text"
            label="Email"
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
            label="Password"
            sendValue={getPassword}
            input={password}
            />
            <div className="flex p-[2%] ">
              <p className="text-brand-500">
                Admin privelege
              </p>
              <div className="pl-[40%]">
            <Switch sendRole={getRole}/>
            </div>
            </div>
            
              <div className="flex gap-2">
                <button
                  onClick={onClose}
                  className="linear rounded-xl border-2 border-red-500 px-5 py-3 text-base font-medium text-red-500 transition duration-200 hover:bg-red-600/5 active:bg-red-700/5 dark:border-red-400 dark:bg-red-400/10 dark:text-white dark:hover:bg-red-300/10 dark:active:bg-red-200/10"
                >
                  Close
                </button>
                <button onClick={saveUser} className="linear text-navy-700 rounded-xl bg-gray-100 px-5 py-3 text-base font-medium transition duration-200 hover:bg-gray-200 active:bg-gray-300 dark:bg-white/10 dark:text-white dark:hover:bg-white/20 dark:active:bg-white/30">
                  Save
                </button>
              </div>
              </Card>
          </ModalBody>
        </ModalContent>
      </Modal>
    </>
    );
};

export default AddUser;