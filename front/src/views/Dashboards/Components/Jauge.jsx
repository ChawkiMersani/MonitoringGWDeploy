import MiniCalendar from "components/calendar/MiniCalendar";
import Card from "components/card";
import { useEffect, useState } from "react";
import { Legend, RadialBar, RadialBarChart, Tooltip } from "recharts";
import { TEDropdown, TEDropdownMenu, TEDropdownToggle } from "tw-elements-react";
import { getJaugeData} from "../api";

 const  Jauge=(props)=>{
  const today=new Date();
  let [dates,setDates]=useState([new Date(today.getFullYear(),today.getMonth(),1),today])
  const [numbers,setNumbers]=useState([0,0])
    const data = [
        {
          "name": "error",
          "count": numbers[1],
          "fill": "#e5383b"
        },
        {
          "name": "Treated",
          "count": numbers[0],
          "fill": props.center == "Policy" ? "#00509d": props.center=="Claim" ? "#ff6d00" : "#6fffe9"
        }
      ]             
      useEffect(()=>{
        fetchdata();
      },[dates]);
      const fetchdata  = async()=>{
        const start = new Date(dates[0]);
        const startIso = start.toISOString().substring(0, 10) + ' ' + start.toISOString().substring(11, 23);
        const end=new Date(dates[1]);
        const endIso = end.toISOString().substring(0, 10) + ' ' + end.toISOString().substring(11, 23);
        const response= await getJaugeData(startIso,endIso,props.center);
        console.log(response);
        setNumbers(response);
      }
      function filterByDates(dates) {
        setDates(dates);
      }
    return(
        <>
        <Card extra="!p-[20px]">
        <Card extra="!p-[20px]">
        
        <div className="mb-6 flex items-center">
        <div className="text-xl font-bold text-navy-700 dark:text-white">
          Document/Errors count
        </div>
          <TEDropdown className="flex justify-end pl-[22%]">
            <TEDropdownToggle>
              <div style={{display: 'flex'}}>
                <text>
                  {dates[0].getDate()}/{dates[0].getMonth()+1} - {dates[1].getDate()}/{dates[1].getMonth()+1}
                </text>
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6" color="#4318FF">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 0 1 2.25-2.25h13.5A2.25 2.25 0 0 1 21 7.5v11.25m-18 0A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75m-18 0v-7.5A2.25 2.25 0 0 1 5.25 9h13.5A2.25 2.25 0 0 1 21 11.25v7.5" />
                </svg>
              </div>
            </TEDropdownToggle>
            <TEDropdownMenu>
              <MiniCalendar sendDates={filterByDates}/>
            </TEDropdownMenu>
          </TEDropdown>
        </div>
        <div className="text-center">
        {props.center} center
        </div>
            
            <RadialBarChart
            width={400} 
            height={250}
      cy='60%'
      innerRadius="20%" 
      outerRadius="100%" 
      data={data} 
      startAngle={180} 
      endAngle={0}
      className="text-center"
    >
      <RadialBar minAngle={15} label={{ fill: 'white', position: 'center'}} background clockWise={true} dataKey='count' />
      <Legend iconSize={10} layout='vertical' verticalAlign='middle' align="right" />
      <Tooltip />
    </RadialBarChart>
    </Card>
    </Card>
    </>
    );
}
export default Jauge;