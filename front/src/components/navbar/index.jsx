import React, { useEffect, useState } from "react";
import Dropdown from "components/dropdown";
import { FiAlignJustify } from "react-icons/fi";
import { Link } from "react-router-dom";
import { BsExclamationSquareFill } from "react-icons/bs";
import {
  IoMdNotificationsOutline,
} from "react-icons/io";
import avatar from "assets/img/Nft1.png";
import { getToken } from "views/SignIn/Auth";
import { getUser } from "views/SignIn/Auth";
import { logout } from "views/SignIn/Auth";

const Navbar = (props) => {
  const { onOpenSidenav, brandText } = props;
  const [data,setData]=useState([]);
  const [thresh,setThresh]=useState(false)
  const token = getToken();
  const user=JSON.parse(getUser());
  useEffect(()=>{
    const fetchdata= async ()=>{
      const response= await fetch("http://localhost:8080/error/getAll",{method:"GET",headers:{
        'Authorization': `Bearer ${token}`
      }});
      const dataJson= await response.json();
      setData(dataJson);
    }
    fetchdata();
  },[thresh])
  const errors=(data)=>{

    const setSeen= async (id)=>{
      try {
        const response = await fetch("http://localhost:8080/error/seen?id="+id, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
        });
        setThresh(!thresh);
      } catch (error) {
        console.error('Error:', error);
        throw error;
      }
    }
    
  
    return(data.ids && data.ids.map((id,index) => (

      <button id={id} className={data.errorList[index].seen ? 'p-[10px] flex w-full items-center bg-white rounded-md' : 'p-[10px] flex w-full items-center bg-red-100 rounded-md'} onClick={()=>{setSeen(data.errorList[index].id)}}>
        <div className="flex h-full w-[70px] items-center justify-center rounded-xl bg-transparent py-5 text-2xl text-white">
          <BsExclamationSquareFill color="red"/>
          </div>
        <div className="ml-2 flex h-full w-full flex-col justify-center rounded-lg px-1 text-sm">
            <p className="mb-1 text-left text-base font-bold text-gray-900 dark:text-white">
              {data.ids[index]}
            </p>
            <p className="font-base text-left text-xs text-gray-900 dark:text-white">
              {data.errorList[index].message}
            </p>
        </div>
      </button>
            )));
  }
  const logOut=()=>{
    logout();
  }
  return (
    <nav className="sticky top-4 z-40 flex flex-row flex-wrap items-center justify-between rounded-xl bg-white/10 p-2 backdrop-blur-xl dark:bg-[#0b14374d]">
      <div className="ml-[6px]">
        <p className="shrink text-[33px] capitalize text-navy-700 dark:text-white">
          <Link
            to="#"
            className="font-bold capitalize hover:text-navy-700 dark:hover:text-white"
          >
            {brandText}
          </Link>
        </p>
      </div>

      <div className="relative mt-[3px] flex h-[61px] flex-grow items-center justify-around gap-2 rounded-full bg-white px-2 py-2 shadow-xl shadow-shadow-500 dark:!bg-navy-800 dark:shadow-none md:] md:flex-grow-0 md:gap-1 xl: xl:gap-2">
        
        <span
          className="flex cursor-pointer text-xl text-gray-600 dark:text-white xl:hidden"
          onClick={onOpenSidenav}
        >
          <FiAlignJustify className="h-5 w-5" />
        </span>
        <Dropdown
          button={
            <img
              className="h-10 w-10 rounded-full"
              src={avatar}
              alt="Elon Musk"
            />
          }
          children={
            <div className="flex w-56 flex-col justify-start rounded-[20px] bg-white bg-cover bg-no-repeat shadow-xl shadow-shadow-500 dark:!bg-navy-700 dark:text-white dark:shadow-none">
              <div className="p-4">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-bold text-navy-700 dark:text-white">
                    Welcome, {user.firstName}
                  </p>{" "}
                </div>
              </div>
              <div className="h-px w-full bg-gray-200 dark:bg-white/20 " />

              <div className="flex flex-col p-4">
                <a
                  href="/main/profile"
                  className="text-sm text-gray-800 dark:text-white hover:dark:text-white"
                >
                  Profile Settings
                </a>
                <button onClick={logOut} className="text-left">
                <a
                  href="/SignIn"
                  className="mt-3 text-sm font-medium text-red-500 hover:text-red-500 transition duration-150 ease-out hover:ease-in"
                >
                  Log Out
                </a>
                </button>
              </div>
            </div>
          }
          classNames={"py-2 top-8 -left-[180px] w-max"}
        />

        <Dropdown
                  button={
                    <p className="cursor-pointer">
                      <IoMdNotificationsOutline className="h-4 w-4 text-gray-600 dark:text-white" />
                    </p>
                  }
                  animation="origin-[65%_0%] md:origin-top-right transition-all duration-300 ease-in-out"
                  children={
                    <div className="flex w-[360px] flex-col gap-3 rounded-[20px] bg-white p-4 shadow-xl shadow-shadow-500 dark:!bg-navy-700 dark:text-white dark:shadow-none sm:w-[460px]">
                      <div className="flex items-center justify-between">
                        <p className="text-base font-bold text-navy-700 dark:text-white">
                          Notifications
                        </p>
                      </div>


                     {errors(data)}
                    </div>
                  }
                  classNames={"py-2 top-4 -left-[230px] md:-left-[440px] w-max"}
        />
      </div>
    </nav>
  );
};

export default Navbar;
