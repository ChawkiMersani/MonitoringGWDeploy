
import { Area, AreaChart, CartesianGrid, Tooltip, XAxis, YAxis } from "recharts";
import Card from "components/card";
import { MdOutlineCalendarToday } from "react-icons/md";
import { useEffect, useState } from "react";
import { getAreaChartData } from "../api";

const GwAreaChart =()=>{
  const [data,setData]=useState([]);
  const [isWeekly,setIsWeekly]=useState(true);
  const fetchdata  = async(isWeekly)=>{
    const response= await getAreaChartData(isWeekly);
    setData(response);
  }
  useEffect(()=>{fetchdata(isWeekly)},[data])
  
    return(
        <Card extra="!p-[20px] ">
        <div className="text-2xl font-bold text-navy-700 dark:text-white">
          Documents count per day
        </div>
       <div className="flex justify-between">
       <button onClick={()=>(setIsWeekly(!isWeekly))} className="linear mt-1 flex items-center justify-center gap-2 rounded-lg bg-lightPrimary p-2 text-gray-600 transition duration-200 hover:cursor-pointer hover:bg-gray-100 active:bg-gray-200 dark:bg-navy-700 dark:hover:opacity-90 dark:active:opacity-80">
          <MdOutlineCalendarToday />
          <span className="text-sm font-medium text-gray-600">{isWeekly ? "This week" : "This month"}</span>
        </button>
        </div>
        <div className="flex h-full w-full flex-row justify-between sm:flex-wrap lg:flex-nowrap 2xl:overflow-hidden">
        <div className="h-full w-full">
        <AreaChart width={1480} height={300} data={data}  margin={{ top: 10, right: 30, left: 0, bottom: 0 }} className="text-center">
        <defs>
          <linearGradient id="colorUv" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#00509d" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#00509d" stopOpacity={0}/>
          </linearGradient>
         
          <linearGradient id="colorPv" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ff6d00" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#ff6d00" stopOpacity={0}/>
          </linearGradient>
          <linearGradient id="colorBilling" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#6fffe9" stopOpacity={0.8}/>
            <stop offset="95%" stopColor="#6fffe9" stopOpacity={0}/>
          </linearGradient>
        </defs>
        <XAxis tick={{ fill: '#adb5bd' }}  className="mt-2 text-sm bg-gray-200" dataKey="name" axisLine={false} tickLine={false}/>
        <YAxis axisLine={false} tickLine={false} tick={{ fill: 'white' }}/>
        <Tooltip />
        <Area type="monotone" dataKey="Policy" stroke="#00509d" fillOpacity={1} fill="url(#colorUv)" />
        <Area type="monotone" dataKey="Claim" stroke="#ff6d00" fillOpacity={1} fill="url(#colorPv)" />
        <Area type="monotone" dataKey="Billing" stroke="#6fffe9" fillOpacity={1} fill="url(#colorBilling)" />
      </AreaChart>
        </div>
        </div>
      </Card>
    );
}
export default GwAreaChart;