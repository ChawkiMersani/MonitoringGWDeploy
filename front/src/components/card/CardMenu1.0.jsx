import React, { useEffect, useState } from "react";
import Dropdown from "components/dropdown";

function CardMenu1(props) {
  const { transparent } = props;
  const [open, setOpen] = React.useState(false);

  const handleClickGenerated = () => {
    if (props.status=="Generated"){
      props.sendData("All status");
    }else{
      props.sendData("Generated");
    }
  };
  const handleClickTransmitted = () => {
    if (props.status=="Transmitted"){
      props.sendData("All status");
    }else{
      props.sendData("Transmitted");}
  };
  const handleClickUploaded = () => {
    if (props.status=="Uploaded"){
      props.sendData("All status");
    }else{
    props.sendData("Uploaded");}
  };
  const handleClickSent = () => {
    if (props.status=="Sent"){
      props.sendData("All status");
    }else{
    props.sendData("Sent");}
  };
  const handleClickArchived = () => {
    if (props.status=="Archived"){
      props.sendData("All status");
    }else{
      props.sendData("Archived");}
  };
  const handleClickError = () => {
    if (props.status=="Error"){
      props.sendData("All status");
    }else{
    props.sendData("Error");}
  };
  return (
    <Dropdown
      button={
        <button
          onClick={() => setOpen(!open)}
          open={open}
          style={{ fontSize: '100%', color: '#899499' }}
          className={`flex items-center text-xl hover:cursor-pointer ${
            transparent
              ? "bg-none text-white hover:bg-none active:bg-none"
              : "bg-lightPrimary p-2 text-brand-500 hover:bg-gray-100 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-white/10"
          } linear justify-center rounded-lg font-bold transition duration-200`}
        >
          {props.status}
        </button>
      }
      animation={"origin-top-right transition-all duration-300 ease-in-out"}
      classNames={`${transparent ? "top-8" : "top-11"} right-0 w-max`}
      children={
        <div className="z-50 w-max rounded-xl bg-white py-3 px-4 text-sm shadow-xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
          <button onClick={handleClickGenerated}>
          <p className={`${!(props.status==="Generated") ? "hover:text-black flex cursor-pointer items-center gap-2 text-gray-600 hover:font-medium" : "hover:text-black flex cursor-pointer items-center gap-2 text-black-600 hover:font-medium"}`}>
            <span>
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="w-6 h-6">
              <path strokeLinecap="round" strokeLinejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10" />
            </svg>

            </span>
            Generated
          </p>
          </button>
          <button onClick={handleClickTransmitted}>
          <p className={`${!(props.status==="Transmitted") ? "hover:text-black flex cursor-pointer items-center gap-2 text-gray-600 hover:font-medium" : "hover:text-black flex cursor-pointer items-center gap-2 text-black-600 hover:font-medium"}`}>
            <span>
            < svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
              </svg>
            </span>
           Transmitted
          </p>
          </button>
          <button onClick={handleClickUploaded}>
          <p className={`${!(props.status==="Uploaded") ? "hover:text-black flex cursor-pointer items-center gap-2 text-gray-600 hover:font-medium" : "hover:text-black flex cursor-pointer items-center gap-2 text-black-600 hover:font-medium"}`}>
              <span>
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="w-6 h-6">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m6.75 12-3-3m0 0-3 3m3-3v6m-1.5-15H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z" />
            </svg>

            </span>
            Uploaded
          </p>
          </button>
          <button onClick={handleClickSent}>
          <p className={`${!(props.status==="Sent") ? "hover:text-black flex cursor-pointer items-center gap-2 text-gray-600 hover:font-medium" : "hover:text-black flex cursor-pointer items-center gap-2 text-black-600 hover:font-medium"}`}>
              <span>
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="w-6 h-6">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
            </svg>

            </span>
            Sent
          </p>
          </button>
          <button onClick={handleClickArchived}>
          <p className={`${!(props.status==="Archived") ? "hover:text-black flex cursor-pointer items-center gap-2 text-gray-600 hover:font-medium" : "hover:text-black flex cursor-pointer items-center gap-2 text-black-600 hover:font-medium"}`}>
              <span>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                  <path strokeLinecap="round" strokeLinejoin="round" d="m20.25 7.5-.625 10.632a2.25 2.25 0 0 1-2.247 2.118H6.622a2.25 2.25 0 0 1-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125Z" />
                </svg>
            </span>
            Archived
          </p>
          </button>
          
          <button onClick={handleClickError}>
          <p className={`${!(props.status==="Error") ? "hover:text-black flex cursor-pointer items-center gap-2 text-gray-600 hover:font-medium" : "hover:text-black flex cursor-pointer items-center gap-2 text-black-600 hover:font-medium"}`}>
              <span>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
                </svg>

            </span>
            Error
          </p>
          </button>
        </div>
      }
    />
  );
}

export default CardMenu1;
