import React, { useEffect, useMemo, useState } from "react";
import Nft1 from "assets/img/Nft1.png";
import Card from "components/card";
import { BsFillXCircleFill } from "react-icons/bs";
import Overlay from "components/overlay/index";
import { getToken } from "views/SignIn/Auth";
import AddUser from "./AddUser";

const UsersTable = () => {
    const[showOverlay,setShowOverlay]=useState(false);
    const [users,setUsers]=useState([]);
    const token=getToken();
    const [id,setId]=useState();
    const fetchUsers = async ()=>{
        const data= await fetch("http://localhost:8080/user/getAllUsers",{method:"GET",headers:{
            'Authorization': `Bearer ${token}`
          }});
        const jsonData= await data.json();
        setUsers(jsonData);
    }
    useEffect(()=>{fetchUsers()},[users]);
    const refreshDelete=()=>{
        fetchUsers();
    }
    const handleAlert= (id) =>{
    setId(id);
        setShowOverlay(!showOverlay);
    }
    const getOverlay = (value)=>{
        setShowOverlay(value)
    }

  return (
    <Card extra={"w-full h-full p-[16px] overflow-hidden"}>
      <div className="flex items-center justify-between rounded-t-3xl p-3">
        <div className="text-lg font-bold text-navy-700 dark:text-white">
          List of All users
        </div>
        <AddUser />
      </div>
      
      {users.map((data, index) => (
        <div className="flex h-full w-full items-start justify-between bg-white px-3 py-[20px] hover:shadow-2xl dark:!bg-navy-800 dark:shadow-none dark:hover:!bg-navy-700">
          <div className="flex items-center gap-3">
            <div className="flex h-16 w-16 items-center justify-center">
              <img
                className="h-full w-full rounded-xl"
                src={Nft1}
                alt=""
              />
            </div>
            <div className="flex flex-col">
              <h5 className="text-base font-bold text-navy-700 dark:text-white">
                {" "}
                {data.firstName+" "+data.lastName}
              </h5>
              <p className="mt-1 text-sm font-normal text-gray-600">
                {" "}
                {data.role}{" "}
              </p>
            </div>
          </div>

          <div className="mt-1 flex items-center justify-center text-navy-700 dark:text-white">
          <button onClick={()=>{handleAlert(data.id)}} className="linear flex rounded-[20px] bg-red-200 px-4 py-2 text-base font-medium text-red-600 transition duration-200 hover:bg-gray-100 active:bg-gray-200 dark:bg-white/5 dark:text-white dark:hover:bg-white/10 dark:active:bg-white/20">
          Delete
          <BsFillXCircleFill className="text-red-600 pl-[5px]" size={25}/>
            </button>
            {showOverlay &&  <Overlay setOverlay={getOverlay} user={id} setDelete={refreshDelete}/>}
        
          </div>
        </div>
      ))}
    </Card>
  );
};

export default UsersTable;