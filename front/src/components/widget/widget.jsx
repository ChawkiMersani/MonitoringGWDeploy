import Card from "components/card";
import { useState } from "react";

const Widget = ({ icon, subtitle, status}) => {
  const [open,setOpen]= useState(false);
  return (
    <Card extra="!flex-row flex-grow items-center rounded-[20px] relative">
      <div className="ml-[18px] flex h-[90px] w-auto flex-row items-center">
        <div className="rounded-full bg-lightPrimary p-3 dark:bg-navy-700">
          <span className="flex items-center text-brand-500 dark:text-white">
            {icon}
          </span>
        </div>
      </div>

      <div className="h-50 ml-4 flex w-auto flex-col justify-center">
        <h4 className="text-xl font-bold text-navy-700 dark:text-white">
          {subtitle}
        </h4>
      </div>
      <div className="absolute right-5">
        {status[0] ?<button
        onClick={()=>{setOpen(!open)}}
          style={{ fontSize: '100%', color: 'green' }}
          className={`flex items-center text-xl hover:cursor-pointer ${
            "bg-lightPrimary p-2 text-brand-500 hover:bg-gray-100 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-white/10"
          } linear justify-center rounded-lg font-bold transition duration-200`}
        >
          working
        </button> : <button
          onClick={()=>{setOpen(!open)}}
          style={{ fontSize: '100%', color: 'red' }}
          className={`flex items-center text-xl hover:cursor-pointer ${
            "bg-lightPrimary p-2 text-brand-500 hover:bg-gray-100 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-white/10"
          } linear justify-center rounded-lg font-bold transition duration-200`}
        >
          suspended
        </button>}
        {open && (status[0] ? <div className="pl-4 animated-element transition-transform duration-10000 ease-in-out transform translate-y-0 opacity-100">{status[1][0] ?  (status[1][1] ? status[1][1] + " hour": status[1][2]+ " min"):  status[1][0] + " days"}</div>: <div className="pl-6 animated-element transition-transform duration-10000 ease-in-out transform translate-y-0 opacity-100">{status[1][0] ?  status[1][0] + " days" : (status[1][1] ? status[1][1] + " hour": status[1][2]+ " min")}</div>)}
      </div>
    </Card>
  );
};

export default Widget;