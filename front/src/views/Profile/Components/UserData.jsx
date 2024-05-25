
import Card from "components/card";
import React, { useState } from "react";
import { getToken } from "views/SignIn/Auth";
import { getUser } from "views/SignIn/Auth";

const General = () => {
    const[firstName,setFirstName]=useState();
    const[lastName,setLastName]=useState();
    const[email,setEmail]=useState();
    const[password,setPassword]=useState();
    const [user,setUser]= useState(JSON.parse(getUser()));
    const token= getToken();
    const [showAlert, setShowAlert] = useState(false);

  const handleFirstNameChange = (event) => {
    const { value } = event.target;
    setFirstName(value);
  };
  const handleLastNameChange = (event) => {
    const { value } = event.target;
    setLastName(value);
  };
  const handleEmailChange = (event) => {
    const { value } = event.target;
    setEmail(value);
  };
  const handlePasswordChange = (event) => {
    const { value } = event.target;
    setPassword(value);
  };
    const handleUpdate = async ()=>{
        const response = await fetch("http://localhost:8080/user/updateUser?id="+user.id,{method:"POST", headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify( {
            id: user.id,
            firstName: firstName,
            lastName:lastName,
            email:email,
            password:password
          })});
          const JsonResponse= await response.json();
          setUser(JsonResponse);
          setShowAlert(!showAlert);
            if (!showAlert) {
            setTimeout(() => {
                setShowAlert(false);
            }, 3000); // 5 seconds
            }
    }
  return (
    <Card extra={"w-full h-full p-3"}>
      <div className="grid grid-cols-2 gap-4 px-2">
        <div className="flex flex-col items-start justify-center rounded-2xl bg-white bg-clip-border px-3 py-4 shadow-3xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
          <p className="text-sm text-gray-600">First Name</p>
          <input type="text" value={firstName} placeholder={user.firstName} onChange={handleFirstNameChange} autocomplete="given-name" className="block w-full border-none rounded-md px-3.5 py-2 text-navy-700 font-medium ring-gray-300 placeholder:text-navy-700 focus:ring-2 focus:ring-inset focus:ring-indigo-600 text-md"/>
        </div>

        <div className="flex flex-col justify-center rounded-2xl bg-white bg-clip-border px-3 py-4 shadow-3xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
          <p className="text-sm text-gray-600">Last Name</p>
          <input type="text"value={lastName} placeholder={user.lastName} onChange={handleLastNameChange} autocomplete="given-name" className="block w-full border-none rounded-md px-3.5 py-2 text-navy-700 font-medium ring-gray-300 placeholder:text-navy-700 focus:ring-2 focus:ring-inset focus:ring-indigo-600 text-md"/>

        </div>

        <div className="flex flex-col items-start justify-center rounded-2xl bg-white bg-clip-border px-3 py-4 shadow-3xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
          <p className="text-sm text-gray-600">Email</p>
          <input type="text" value={email} placeholder={user.email} onChange={handleEmailChange} autocomplete="given-name" className="block w-full border-none rounded-md px-3.5 py-2 text-navy-700 font-medium ring-gray-300 placeholder:text-navy-700 focus:ring-2 focus:ring-inset focus:ring-indigo-600 text-md"/>

        </div>

        
        <div className="flex flex-col justify-center rounded-2xl bg-white bg-clip-border px-3 py-4 shadow-3xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
          <p className="text-sm text-gray-600">Password</p>
          <input type="password" value={password} placeholder="Password" onChange={handlePasswordChange} autocomplete="given-name" className="block w-full border-none rounded-md px-3.5 py-2 text-navy-700 font-medium ring-gray-300 placeholder:text-navy-700 focus:ring-2 focus:ring-inset focus:ring-indigo-600 text-md"/>

        </div>
        <div className="flex flex-col justify-center rounded-2xl bg-white bg-clip-border px-3 py-4 shadow-3xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
          <p className="text-sm text-gray-600">Role</p>
          <input type="text" name="first-name" placeholder={user.role} autocomplete="given-name" className="block w-full border-none rounded-md px-3.5 py-2 text-navy-700 font-medium ring-gray-300 placeholder:text-navy-700 focus:ring-2 focus:ring-inset focus:ring-indigo-600 text-md"/>

        </div>

            <button onClick={handleUpdate} className="flex linear ml-[10%] mt-[3%] w-[80%] h-[50%] bg-brand-500 hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:bg-brand-200 rounded-xl px-5 py-3 text-base font-medium text-white transition duration-200 dark:text-white justify-center">
                Update user
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" className="w-6 h-6 pl-[1%]">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z" />
                </svg>
            </button>
            <div
        className={`flex items-center bg-blue-500 text-white text-sm font-bold px-4 py-3 fixed top-20 rounded-[10px] right-0 z-50 mt-10 mr-10 ${
          showAlert ? 'transition-all duration-500 transform translate-x-0' : 'hidden'
        }`}
        role="alert"
      >
  <svg className="fill-white w-4 h-4 mr-2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M12.432 0c1.34 0 2.01.912 2.01 1.957 0 1.305-1.164 2.512-2.679 2.512-1.269 0-2.009-.75-1.974-1.99C9.789 1.436 10.67 0 12.432 0zM8.309 20c-1.058 0-1.833-.652-1.093-3.524l1.214-5.092c.211-.814.246-1.141 0-1.141-.317 0-1.689.562-2.502 1.117l-.528-.88c2.572-2.186 5.531-3.467 6.801-3.467 1.057 0 1.233 1.273.705 3.23l-1.391 5.352c-.246.945-.141 1.271.106 1.271.317 0 1.357-.392 2.379-1.207l.6.814C12.098 19.02 9.365 20 8.309 20z"/></svg>
  <p>User updated successfully</p>
</div>

      </div>
    </Card>
  );
};

export default General;