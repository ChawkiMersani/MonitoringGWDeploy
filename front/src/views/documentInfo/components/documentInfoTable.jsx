import Card from "components/card";
import Dropdown from "components/dropdown";
import React, { useEffect, useState } from "react";
import { BsExclamationCircleFill, BsFillXCircleFill } from "react-icons/bs";
import { MdCheckCircle, MdTimer } from "react-icons/md";
import { getToken } from "views/SignIn/Auth";

const DocumentInfoTable = (props) => {
  const [data,setData]=useState([]);
  const[open,setOpen]= useState(false);
  const [status,setStatus]=useState();
  const token=getToken();

  //Get Document Data

  useEffect(()=>{
    const fetchData = async()=>{
      try{
        const response = await fetch("http://localhost:8080/document/get/id="+props.id,{method:"GET",headers:{
          'Authorization': `Bearer ${token}`
        }})
        const newData= await response.json();
        setData(newData);
        updateStatus(newData);
      }catch(error){
        console.error("Failed",error);
      }
    };
  fetchData();
  
  },[])

  //Status component
  
  const updateStatus=(data)=>{
    switch(data.progress){
      case "Generated" :
        setStatus(<Dropdown
    button={
      <button
        onClick={() => setOpen(!open)}
        open={open}
        style={{ fontSize: '100%', color: '#4318FF' }}
        className={`flex items-center text-xl hover:cursor-pointer
        bg-blue-100 p-2 text-brand-500 hover:bg-blue-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
        linear justify-center rounded-lg font-bold transition duration-200`}
      >
        {data.progress}
        <MdCheckCircle className="text-blue-600" style={{paddingLeft:'2%'}} size={20} />
      </button>
    }
    animation={"origin-top-right transition-all duration-300 ease-in-out"}
    classNames={"top-11 right-0 w-max"}
    
  />)
        break;
      case "Transmitted" :
        setStatus(<Dropdown
    button={
      <button
        onClick={() => setOpen(!open)}
        open={open}
        style={{ fontSize: '100%', color: '#6AD2FF' }}
        className={`flex items-center text-xl hover:cursor-pointer
        bg-gray-100 p-2 text-brand-500 hover:bg-gray-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
        linear justify-center rounded-lg font-bold transition duration-200`}
      >
        {data.progress}
        <MdCheckCircle color="#6AD2FF" style={{paddingLeft:'2%'}} size={20} />
      </button>
    }
    animation={"origin-top-right transition-all duration-300 ease-in-out"}
    classNames={"top-11 right-0 w-max"}
  />)
        break;
      case "Uploaded" :
          setStatus(<Dropdown
      button={
        <button
          onClick={() => setOpen(!open)}
          open={open}
          style={{ fontSize: '100%', color: '#239B56' }}
          className={`flex items-center text-xl hover:cursor-pointer
          bg-green-100 p-2 text-brand-500 hover:bg-gray-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
          linear justify-center rounded-lg font-bold transition duration-200`}
        >
          {data.progress}
          <MdCheckCircle className="text-green-600" style={{paddingLeft:'2%'}} size={20} />
        </button>
      }
      animation={"origin-top-right transition-all duration-300 ease-in-out"}
      classNames={"top-11 right-0 w-max"}
    />)
        break;
      case "Sent" :
          setStatus(<Dropdown
      button={
        <button
          onClick={() => setOpen(!open)}
          open={open}
          style={{ fontSize: '100%', color: '#6C33A4' }}
          className={`flex items-center text-xl hover:cursor-pointer
          bg-purple-100 p-2 text-brand-500 hover:bg-gray-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
          linear justify-center rounded-lg font-bold transition duration-200`}
        >
          {data.progress}
          <MdCheckCircle color="#6C33A4" style={{paddingLeft:'2%'}} size={20} />
        </button>
      }
      animation={"origin-top-right transition-all duration-300 ease-in-out"}
      classNames={"top-11 right-0 w-max"}
    />)
        break;
      case "Archived" :
          setStatus(<Dropdown
    button={
      data.signatureMethod==="No Signature" ? 
      <button
        onClick={() => setOpen(!open)}
        open={open}
        style={{ fontSize: '100%', color: '#FFAA1D' }}
        className={`flex items-center text-xl hover:cursor-pointer
        bg-orange-100 p-2 text-brand-500 hover:bg-orange-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
        linear justify-center rounded-lg font-bold transition duration-200`}
      >
        {data.progress}
        <MdCheckCircle color="#FFAA1D" style={{paddingLeft:'2%'}} size={20} />
      </button>
       : data.signed ? 
       <div className="flex flex-col justify-center items-center"><button
        onClick={() => setOpen(!open)}
        open={open}
        style={{ fontSize: '100%', color: '#FFAA1D' }}
        className={`flex pl-5 pr-5 items-center text-xl hover:cursor-pointer
        bg-orange-100 p-2 text-brand-500 hover:bg-orange-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
        linear justify-center rounded-lg font-bold transition duration-200`}
      >
        {data.progress}
        <MdCheckCircle color="#FFAA1D" style={{paddingLeft:'2%'}} size={20} />
      </button>
      <button
      onClick={() => setOpen(!open)}
      open={open}
      style={{ fontSize: '100%', color: '#239B56', backgroundColor: '#DAF7A6'}}
      className={`flex pl-5 pr-5 items-center text-xl hover:cursor-pointer m-2 p-2 text-brand-500 hover:bg-orange-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
      linear justify-center rounded-lg font-bold transition duration-200`}
    >
      Signed <MdCheckCircle  className="ml-1 text-green-600"/>
    </button>

      </div>
     : 
      <div className="flex flex-col justify-center"><button
      onClick={() => setOpen(!open)}
      open={open}
      style={{ fontSize: '100%', color: '#FFAA1D' }}
      className={`flex items-center text-xl hover:cursor-pointer
      bg-orange-100 p-2 text-brand-500 hover:bg-orange-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
      linear justify-center rounded-lg font-bold transition duration-200`}
    >
      {data.progress} 
    </button>
    <button
      onClick={() => setOpen(!open)}
      open={open}
      style={{ fontSize: '100%', color: '#21618C', backgroundColor: '#85C1E9'}}
      className={`flex items-center text-xl hover:cursor-pointer m-2 p-2 text-brand-500 hover:bg-orange-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
      linear justify-center rounded-lg font-bold transition duration-200`}
    >
      Waiting for Signing<MdTimer className="ml-1 text-blue-900"/>
    </button>
    <div className="overflow-hidden pt-2" style={{color: '#21618C' }}>
     <p className="animate-bounce  text-xl font-medium dark:text-white"></p>
   </div>
    </div>
    }
    animation={"origin-top-right transition-all duration-300 ease-in-out"}
    classNames={"top-11 right-0 w-max"}
  />)
      break;
      default:
        setStatus(<Dropdown
    button={
      <button
        onClick={() => setOpen(!open)}
        open={open}
        style={{ fontSize: '100%', color: '#cc1c08' }}
        className={`flex items-center text-xl hover:cursor-pointer
        bg-red-200 p-2 text-brand-500 hover:bg-red-300 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
        linear justify-center rounded-lg font-bold transition duration-200`}
      >
        {data.progress.substring(0,5)} in {data.progress.substring(5,data.progress.length)}
      </button>
    }
    animation={"origin-top-right transition-all duration-300 ease-in-out"}
    classNames={"shadow-2xl top-11 right-0 w-max"}
    children={
      <div className="z-50 w-[1000px] border border-red-400 rounded-xl bg-red-100 py-3 px-4 text-sm shadow-xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
        <div className="flex flex-row relative">
        <BsFillXCircleFill className="text-red-600 mt-1" size={20}/>
        
        <h3 className="px-2 text-xl mb-3 font-bold text-red-600 dark:text-white">
          Error message
        </h3>
        <button
        style={{ fontSize: '100%',color:'Black' }}
        className={`flex items-center text-xl hover:cursor-pointer
        bg-gradient-to-r from-red-400 to-red-200 p-2 text-black-500 hover:bg-gray-200 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-gray/10
        linear justify-center rounded-lg font-bold transition duration-200 absolute top-0 right-0`}
      >
        {data.error.errorCode}
      </button>
      
      </div>
        <p className={"hover:text-black  flex cursor-pointer text-lg items-center gap-2 text-black-600 hover:font-medium"}>
          {data.error.errorMessage ? data.error.message +" : "+ data.error.errorMessage : data.error.message}
        </p>
        <div className="flex flex-row relative mt-3">
        <BsExclamationCircleFill className="text-blue-900 mt-1" size={20}/>
        <h3 className="px-2 text-xl mb-3 font-bold text-blue-900 dark:text-white">
        
        Reason
        </h3>
        </div>
        <p className={"hover:text-xl flex cursor-pointer text-lg items-center gap-2 text-black-600 hover:font-medium"}>
          {data.error.details ? data.error.details[0].toUpperCase()+data.error.details.substring(1): null}
        </p>
        
        <div className="mt-7 mb-7 h-px bg-gray-300 dark:bg-white/30" />
        <h3 className="px-2 text-xl mb-3 font-bold text-navy-700 dark:text-white">
          stack error
        </h3>
        <p style={{ whiteSpace: 'pre-line' }} className={"hover:text-black text-sm flex cursor-pointer items-center gap-2 text-black-600 hover:font-medium"}>
          {data.error.stackTrace}
        </p>
      </div>
    }
  />)
        break;
  }
  }
  return (
    <Card extra={"w-full h-full p-3"}>
      <div className="relative flex items-center justify-between pt-4">
        <h4 className="px-2 text-xl font-bold text-navy-700 dark:text-white">

          General Information
        </h4>
        {status}
        
      </div>
      <div className="grid grid-cols-2 gap-4 px-2">
        
        {Object.keys(data).map((key)=>(
          
            key!=="error" && key!="progress"
          && (key=="inbound" ?
          <div className="flex flex-col justify-center rounded-2xl bg-white bg-clip-border px-3 py-4 shadow-3xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
            <p className="text-sm text-gray-600">Type</p>
            <p className="text-base font-medium text-navy-700 dark:text-white">{data[key]? "Inbound": "Outbound"}</p>
          </div> : key == "signed" ? <div className="flex flex-col justify-center rounded-2xl bg-white bg-clip-border px-3 py-4 shadow-3xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
            <p className="text-sm text-gray-600">{key }</p>
            <p className="text-base font-medium text-navy-700 dark:text-white">{data[key]? "Yes" : "No"}</p>
          </div> : <div className="flex flex-col justify-center rounded-2xl bg-white bg-clip-border px-3 py-4 shadow-3xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
            <p className="text-sm text-gray-600">{key }</p>
            <p className="text-base font-medium text-navy-700 dark:text-white">{data[key]}</p>
          </div>)
        ))}
      </div>
    </Card>
  );
};

export default DocumentInfoTable;