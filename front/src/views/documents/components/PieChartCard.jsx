import PieChart from "components/charts/PieChart";
import { pieChartOptions } from "variables/charts";
import Card from "components/card";
import { TEDropdown, TEDropdownMenu, TEDropdownToggle} from "tw-elements-react";
import MiniCalendar from "components/calendar/MiniCalendar";
import { useEffect, useState } from "react";

 function PieChartCard(props){
  const data=[...props.data,props.error];
  const today=new Date();
  let [dates,setDates]=useState([new Date(today.getFullYear(),today.getMonth(),1),today])

  //Rerender Chart based on the change of the time period

  useEffect(()=>{
  },[dates]);
  function filterByDates(dates) {
    setDates(dates);
    props.sendDate(dates,props.name);
  }
  return (
    <Card extra="rounded-[20px] p-3">
      <div className="flex flex-row justify-between px-3 pt-2">
        <div>
          <h4 className="text-lg font-bold text-navy-700 dark:text-white">
            {props.name}
          </h4>
        </div>

        {/* Calandar*/}

        <div className="mb-6 flex items-center justify-center">
          <TEDropdown className="flex justify-center">
            <TEDropdownToggle>
              <div style={{display: 'flex'}}>
                <p>
                  {dates[0].getDate()}/{dates[0].getMonth()+1} - {dates[1].getDate()}/{dates[1].getMonth()+1}
                </p>
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
      </div>

      {/* Pie chart*/}

      <div className="mb-auto flex h-[220px] w-full items-center justify-center">
        <PieChart options={pieChartOptions} series={data} />
      </div>
      <div className="flex flex-col !justify-between rounded-2xl px-6 shadow-2xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none">
      <div className="flex flex-row">

<div className="flex flex-col w-[50%] items-center justify-center">
  <div className="flex items-center justify-center">
    <div className="h-2 w-2 rounded-full bg-[#FFAA1D]" />
    <p className="ml-1 text-sm font-normal text-gray-600">Archived</p>
  </div>
  <p className="mt-px text-xl font-bold text-navy-700 dark:text-white">
  {(props.sum != 0) ? parseInt(props.data[2]/props.sum*100) : 0}%
  </p>
</div>
<div className="h-11 w-px bg-gray-300 dark:bg-white/10" />

<div className="flex flex-col w-[50%] items-center justify-center">
  <div className="flex items-center justify-center">
    <div className="h-2 w-2 rounded-full bg-[#cc1c08]" />
    <p className="ml-1 text-sm font-normal text-gray-600">Error</p>
  </div>
  <p className="mt-px text-xl font-bold text-navy-700 dark:text-white">
  {(props.sum != 0) ? parseInt(props.error/props.sum*100) : 0}%
  </p>
</div>
</div>
        <div className="flex flex-row pt-[5%]">
          <p className="ml-1 text-base font-normal text-gray-700">
          Outbound
          </p>
          <div className="flex flex-col w-[50%] items-center justify-center">
            <div className="flex items-center justify-center">
              <div className="h-2 w-2 rounded-full bg-brand-500" />
              <p className="ml-1 text-sm font-normal text-gray-600">Generated</p>
            </div>
            <p className="mt-px text-xl font-bold text-navy-700  dark:text-white">
              {(props.sum != 0) ? parseInt(props.data[0]/props.sum*100) : 0}%
            </p>
          </div>

          <div className="h-11 w-px bg-gray-300 dark:bg-white/10" />

          <div className="flex flex-col w-[50%] items-center justify-center">
            <div className="flex items-center justify-center">
              <div className="h-2 w-2 rounded-full bg-[#6AD2FF]" />
              <p className="ml-1 text-sm font-normal text-gray-600">Transmitted</p>
            </div>
            <p className="mt-px text-xl font-bold text-navy-700 dark:text-white">
            {(props.sum != 0) ? parseInt(props.data[1]/props.sum*100) : 0}%
            </p>
          </div>
        </div>
        
        <div className="flex flex-row pt-[5%]">
          <p className="ml-1 text-base font-normal text-gray-700 pr-[3%]">
          Inbound
          </p>
          <div className="flex flex-col w-[50%] items-center justify-center">
            <div className="flex items-center justify-center">
              <div className="h-2 w-2 rounded-full bg-[#239B56]" />
              <p className="ml-1 text-sm font-normal text-gray-600">Uploaded</p>
            </div>
            <p className="mt-px text-xl font-bold text-navy-700 dark:text-white">
            {(props.sum != 0) ? parseInt(props.data[3]/props.sum*100) : 0}%
            </p>
          </div>
          <div className="h-11 w-px bg-gray-300 dark:bg-white/10" />
          <div className="flex flex-col w-[50%] items-center justify-center">
              <div className="flex items-center justify-center">
                <div className="h-2 w-2 rounded-full bg-[#6C33A4]" />
                <p className="ml-1 text-sm font-normal text-gray-600">Sent</p>
              </div>
              <p className="mt-px text-xl font-bold text-navy-700 dark:text-white">
              {(props.sum != 0) ? parseInt(props.data[4]/props.sum*100) : 0}%
              </p>
          </div>
          </div>
        
        
      </div>
    </Card>
  );
};

export default PieChartCard;
