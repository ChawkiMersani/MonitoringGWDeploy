import React, { useEffect, useState } from 'react';
import {
  Chart as ChartJS,
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend,
} from 'chart.js';
import { Radar } from 'react-chartjs-2';
import Card from 'components/card';
import { TEDropdown, TEDropdownMenu, TEDropdownToggle } from 'tw-elements-react';
import MiniCalendar from 'components/calendar/MiniCalendar';
import { getRadarData } from '../api';

ChartJS.register(
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend
);


const GwRadar=()=> {
  const options = {
    scales: {
      r:{ticks: {
        display: false
      }}
    }
  };
  const today=new Date();
  let [dates,setDates]=useState([new Date(today.getFullYear(),today.getMonth(),1),today])
  const [numbers,setNumbers]=useState([[],[],[]]);
  const data = {
    labels: ['Transmitting','Uploading', 'Archiving','Generating','Signing', 'Sending'],
    datasets: [
      {
        label: 'Policy',
        data: numbers[0],
        backgroundColor: 'rgb(0, 80, 157, 0.2)',
        borderColor: 'rgb(0, 80, 157, 1)',
        borderWidth: 1,
      },
      {
          label: 'Claim',
          data: numbers[1],
          backgroundColor: 'rgb(255, 109, 0, 0.2)',
          borderColor: 'rgb(255, 109, 0, 1)',
          borderWidth: 1,
        },
        {
          label: 'Billing',
          data: numbers[2],
          backgroundColor: 'rgb(111, 255, 233, 0.2)',
          borderColor: 'rgb(111, 255, 233, 1)',
          borderWidth: 1,
        },
    ],
  };

  useEffect(()=>{fetchdata();},[dates]);
  const fetchdata  = async()=>{
    const start = new Date(dates[0]);
    const startIso = start.toISOString().substring(0, 10) + ' ' + start.toISOString().substring(11, 23);
    const end=new Date(dates[1]);
    const endIso = end.toISOString().substring(0, 10) + ' ' + end.toISOString().substring(11, 23);
    const response= await getRadarData(startIso,endIso);
    setNumbers(response);
  };
  function filterByDates(dates) {
    setDates(dates);
  }
  return (
    <Card extra="!p-[20px] mt-[1%]">
      
      <div className="mb-6 flex items-center">
      <div className="text-2xl font-bold text-navy-700 dark:text-white">
          Error Areas
        </div>
          <TEDropdown className="flex justify-end pl-[63%]">
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
      <Radar className="w-[600px] max-h-[400px] text-center" data={data} options={options} />
  </Card>
  );
}
export default GwRadar;