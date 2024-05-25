import React, { useState, useEffect } from 'react';
import Card from 'components/card';
import BarChart from 'components/charts/BarChart';
import { barChartOptionsDailyTraffic } from 'variables/charts';
import Dropdown from 'components/dropdown';
import { getToken } from 'views/SignIn/Auth';

const BarChartCard = (props) => {
  const [chartData, setChartData] = useState([]);
  const [Data, setData] = useState([]);
  const [dateRange, setDateRange] = useState('Daily');
  const [days, setDays] = useState([]);
  const [open, setOpen] =useState(false);
  const { transparent } = props;
  const [daily,setDaily]=useState(false);
  const [monthly,setMonthly]=useState(true);
  const category =props.category;
  const token = getToken();

  useEffect(() => {
    fetchData();
  }, [dateRange,category]);

  useEffect(() => {
    setChartData([{ name: "Documents", data: Data }]);
  }, [Data, days]);

  const fetchData = async () => {
    const start = new Date();
    const end = new Date();
    if (dateRange == 'Daily') {
      end.setDate(start.getDate() - 7);
    } else if (dateRange == 'Monthly') {
      end.setMonth(start.getMonth() - 1);
    }

    const startIso = start.toISOString().substring(0,10)+' '+start.toISOString().substring(11,23);
    const endIso = end.toISOString().substring(0,10)+' '+end.toISOString().substring(11,23);
    try {
      let response;
      switch(category){
        case "policy":
          response = await fetch(`http://localhost:8080/document/PoliciescountsByDate/start=${endIso}&end=${startIso}`,{method:"GET",headers:{
            'Authorization': `Bearer ${token}`
          }});
          break;
        case "claim":
          response = await fetch(`http://localhost:8080/document/ClaimsCountsByDate/start=${endIso}&end=${startIso}`,{method:"GET",headers:{
            'Authorization': `Bearer ${token}`
          }});
          break;
        case "billing":
          response = await fetch(`http://localhost:8080/document/AccountscountsByDate/start=${endIso}&end=${startIso}?center=${props.center}`,{method:"GET",headers:{
            'Authorization': `Bearer ${token}`
          }});
          break;
        case "Account":
          response = await fetch(`http://localhost:8080/document/AccountscountsByDate/start=${endIso}&end=${startIso}?center=${props.center}`,{method:"GET",headers:{
            'Authorization': `Bearer ${token}`
          }});
          break;
        case "Policy":
          response = await fetch(`http://localhost:8080/document/PoliciescountsByDate/start=${endIso}&end=${startIso}`,{method:"GET",headers:{
            'Authorization': `Bearer ${token}`
          }});
          break;
        case "Submission":
          response = await fetch(`http://localhost:8080/document/SubbmissionscountsByDate/start=${endIso}&end=${startIso}`,{method:"GET",headers:{
            'Authorization': `Bearer ${token}`
          }});
          break;
      }
      
      const data = await response.json();
      setData(Object.values(data));
      setDays(Object.keys(data));
    } catch (error) {
      console.error(error);
    }
  };

  const handleDateRange = (e) => {
    if(dateRange!=e){
    setDateRange(e);
    setChartData([]);
    setData([]); // Reset data
    setDays([]);
    }
    
    if(e==='Daily'){
      setDaily(false);
      setMonthly(true)
    } else{
      setMonthly(false);
      setDaily(true);
    } // Reset chart data
     // Reset days
  };

  return (
    <Card extra="pb-7 p-10">
      <div className="w-full pt-4 pb-4">
      <Dropdown
      button={
        <button
          onClick={() => setOpen(!open)}
          open={open}
          style={{ fontSize: '100%', color: '#899499' }}
          className={`items-left text-xl hover:cursor-pointer ${
            transparent
              ? "bg-none text-white hover:bg-none active:bg-none"
              : "bg-lightPrimary p-2 text-brand-500 hover:bg-gray-100 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-white/10"
          } linear justify-left rounded-lg font-bold transition duration-200`}
        >
          {dateRange}
        </button>
      }
      animation={"origin-top-left transition-all duration-300 ease-in-out"}
      classNames={`${transparent ? "top-8" : "top-11"} w-max`}
      children={
        <div className="z-50 w-max rounded-xl bg-white py-3 px-4 text-sm shadow-xl shadow-shadow-500 dark:!bg-navy-700 dark:shadow-none" style={{ display: 'flex', flexDirection: 'column',textAlign:'left'}}>
          <button onClick={()=>{
            handleDateRange('Daily')
          }}>
          
          <p className={`${daily ? "hover:text-black  flex cursor-pointer items-left gap-2 text-gray-600 hover:font-medium" : "hover:text-black flex cursor-pointer item-left gap-2 text-black-600 hover:font-medium"}`}>
            Daily
          </p>
          </button>
          <button onClick={()=>{
            handleDateRange('Monthly')
          }}>
          <p className={`${monthly ? "hover:text-black flex cursor-pointer items-left gap-2 text-gray-600 hover:font-medium" : "hover:text-black flex cursor-pointer items-left gap-2 text-black-600 hover:font-medium"}`}>
            Monthly
          </p>
          </button>
        </div>
      }
    />
        <div className="w-full">
          <BarChart
            chartData={chartData}
            chartOptions={barChartOptionsDailyTraffic(days)}
          />
        </div>
      </div>
    </Card>
  );
};

export default BarChartCard;
