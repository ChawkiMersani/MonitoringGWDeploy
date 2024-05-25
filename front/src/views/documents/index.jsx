import PieChartCard from "views/documents/components/PieChartCard";
import { columnsDataComplex } from "views/documents/variables/columnsData";
import { useEffect, useState } from "react";
import DocumentsTable from "./components/DocumentsTable";
import {MdCheckCircle } from "react-icons/md";
import Widget from "components/widget/widget";
import {BsFillXCircleFill } from "react-icons/bs";
import { getToken } from "views/SignIn/Auth";

const Documents = () => {
  const [claimData, setClaimData] = useState([]);
  const [policyData, setPolicyData] = useState([]);
  const [billingData, setBillingData] = useState([]);
  const [claimSum,setClaimSum]= useState(0);
  const [policySum,setPolicySum]= useState(0);
  const [billingSum,setBillingSum]= useState(0);
  const [policyError,setPolicyError]= useState(0);
  const [claimError,setClaimError]= useState(0);
  const [billingError,setBillingError]= useState(0);
  const [documentData,setDocumentmData] = useState([]);
  let [center,setCenter]=useState("All centers");
  let [status,setStatus]=useState("All status");
  let[field,setField]=useState("Filter By Id/Object...");
  const [pageNumber,setPageNumber]=useState(0);
  const [change,setChange]=useState(false);
  const [working,setWorking]=useState("working");
  const [rms,setRms]=useState([true,[0,0,0]]);
  const [docProdReq,setDocProdRes]=useState([true,[0,0,0]]);
  const [eSignature,setESignature]=useState([true,[0,0,0]]);
  const token=getToken();

  useEffect(()=>{  console.log(token);},[]);
//Pie chart Data
  useEffect(() => {
    const fetchData = async () => {
      
      const today=new Date();
      let dates=[new Date(today.getFullYear(),today.getMonth(),1),today]
      const start = new Date(dates[0]);
      const startIso = start.toISOString().substring(0, 10) + ' ' + start.toISOString().substring(11, 23);
      const end=new Date(dates[1]);
      const endIso = end.toISOString().substring(0, 10) + ' ' + end.toISOString().substring(11, 23);
      try {
        const response = await fetch("http://localhost:8080/document/get/Numbers/start="+startIso+"&end="+endIso,{method:"GET",headers:{
          'Authorization': `Bearer ${token}`
        }});
        if (!response.ok) {
          throw new Error('Failed to fetch data');
        }
        const jsonData = await response.json();
        setClaimData(jsonData.claim);
        setPolicyData(jsonData.policy);
        setBillingData(jsonData.billing);
        setPolicyError(jsonData.error[0]);
        setClaimError(jsonData.error[2]);
        setBillingError(jsonData.error[1]);
        setPolicySum(jsonData.sum[0]);
        setBillingSum(jsonData.sum[1]);
        setClaimSum(jsonData.sum[2]);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    fetchData();
    messageQueuesStatus();   
  }, []);

  //Load more documents whene reaching the bottom of the table

  useEffect(() => {
    const handleScroll = () => {
      if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 10) {
        setPageNumber(pageNumber + 1)
      }
    };
    

    window.addEventListener('scroll', handleScroll);
    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, [pageNumber]);

  useEffect(()=>{fetchData(pageNumber)},[pageNumber,center,status,field])
  
  //Table Data based on filters by status, center and search object
  
  const fetchData = async (pageNumber) => {
    if(status=="All status"){
      if(center=="All centers"){
        if(field=="Filter By Id/Object..."){
          try {
            const response = await fetch("http://localhost:8080/document/getAll/pageNumber="+pageNumber+"&pageSize=10",{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              
              const jsonData = await response.json();
              if(!change){
                setDocumentmData((documentData)=>[...documentData,...jsonData]);
              }else{
                setDocumentmData(jsonData);
                setChange(false);
              }
              
              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }else if(field.startsWith("pc") || field.startsWith("cc") || field.startsWith("bc")){
          try {
            const response = await fetch("http://localhost:8080/document/get/id="+field,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              setDocumentmData([jsonData]);
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }else{
          try {
            const response = await fetch("http://localhost:8080/document/get/GW_ID="+field+"?pageNumber="+pageNumber,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              if(!change){
                setDocumentmData((documentData)=>[...documentData,...jsonData]);
              }else{
                setDocumentmData(jsonData);
                setChange(false);
              }
              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }
      }else{
        if(field=="Filter By Id/Object..."){
          try {
            const response = await fetch("http://localhost:8080/document/get/service="+center+"?pageNumber="+pageNumber,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              if(!change){
                setDocumentmData((documentData)=>[...documentData,...jsonData]);
              }else{
                setDocumentmData(jsonData);
                setChange(false);
              }
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }else if(field.startsWith("pc") || field.startsWith("cc") || field.startsWith("bc")){
          try {
            const response = await fetch("http://localhost:8080/document/get/GW_ID="+field+"?pageNumber="+pageNumber,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
                setDocumentmData(jsonData);              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }else{
          try {
            const response = await fetch("http://localhost:8080/document/get/service="+center+"/Gw_ID="+field+"?pageNumber="+pageNumber,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              if(!change){
                setDocumentmData((documentData)=>[...documentData,...jsonData]);
              }else{
                setDocumentmData(jsonData);
                setChange(false);
              }
              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }

      }
    }else{
      if(center=="All centers"){
        if(field=="Filter By Id/Object..."){
          try {
            const response = await fetch("http://localhost:8080/document/get/status="+status+"?pageNumber="+pageNumber,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              if(!change){
                setDocumentmData((documentData)=>[...documentData,...jsonData]);
              }else{
                setDocumentmData(jsonData);
                setChange(false);
              }
              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }else if(field.startsWith("pc") || field.startsWith("cc") || field.startsWith("bc")){
          try {
            const response = await fetch("http://localhost:8080/document/get/GW_ID="+field,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
                setDocumentmData(jsonData);
              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }else{
          try {
            const response = await fetch("http://localhost:8080/document/get/status="+status+"/Gw_ID="+field+"?pageNumber="+pageNumber,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              if(!change){
                setDocumentmData((documentData)=>[...documentData,...jsonData]);
              }else{
                setDocumentmData(jsonData);
                setChange(false);
              }
              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }
      }else{
        if(field=="Filter By Id/Object..."){
          try {
            const response = await fetch("http://localhost:8080/document/get/status="+status+"/service="+center+"?pageNumber="+pageNumber,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              if(!change){
                setDocumentmData((documentData)=>[...documentData,...jsonData]);
              }else{
                setDocumentmData(jsonData);
                setChange(false);
              }
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }else if(field.startsWith("pc") || field.startsWith("cc") || field.startsWith("bc")){
          try {
            const response = await fetch("http://localhost:8080/document/get/GW_ID="+field,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              setDocumentmData(jsonData);
              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }else{
          try {
            const response = await fetch("http://localhost:8080/document/get/status="+status+"/service="+center+"/Gw_ID="+field+"?pageNumber="+pageNumber,{method:"GET",headers:{
              'Authorization': `Bearer ${token}`
            }});
              if (!response.ok) {
                throw new Error('Failed to fetch data');
              }
              const jsonData = await response.json();
              if(!change){
                setDocumentmData((documentData)=>[...documentData,...jsonData]);
              }else{
                setDocumentmData(jsonData);
                setChange(false);
              }
              
            } catch (error) {
              console.error('Error fetching data:', error);
            }
        }

      }

    }
      
  };
  //Filter functions

  async function filterByCenter(center) {
    setCenter(center);
    setChange(true);
    setPageNumber(0);
  }
  async function filterByStatus(status) {
    setStatus(status);
    setChange(true);
    setPageNumber(0);
  }
  async function filterByField(field){
    setField(field);
    setChange(true);
    setPageNumber(0);
  }

  //Calendar change Date function
  
  async function dateFilter(dates,center){
    const start = new Date(dates[0]);
    const startIso = start.toISOString().substring(0, 10) + ' ' + start.toISOString().substring(11, 23);
    const end=new Date(dates[1]);
    const endIso = end.toISOString().substring(0, 10) + ' ' + end.toISOString().substring(11, 23);
    try {
      const response = await fetch("http://localhost:8080/document/get/Numbers/start="+startIso+"&end="+endIso,{method:"GET",headers:{
        'Authorization': `Bearer ${token}`
      }});
      if (!response.ok) {
        throw new Error('Failed to fetch data');
      }
      const jsonData = await response.json();
      switch(center){
        case "Policy Center":
          setPolicyData(jsonData.policy);
          setPolicySum(jsonData.sum[0]);
          setPolicyError(jsonData.error[0]);
          break;
        case "Claim Center":
          setClaimData(jsonData.claim);
          setClaimError(jsonData.error[2]);
          setClaimSum(jsonData.sum[2]);
          break;
        case "Billing Center":
          setBillingData(jsonData.billing);
          setBillingError(jsonData.error[1]);
          setBillingSum(jsonData.sum[1]);
          break;
          
      } 
        
    } catch (error) {
      console.error('Error fetching data:', error);
      
    }

  }

  //MessageQueues Status function

  async function messageQueuesStatus(){
    const docProdReqResponse = await fetch("http://localhost:8080/messagesqueues/getDocProdStatus",{method:"GET",headers:{
      'Authorization': `Bearer ${token}`
    }});
    const docProdReqString = await docProdReqResponse.text();
    const docProdReqduration = docProdReqString.split('/');
    if(docProdReqduration[0]>0){
      setDocProdRes([false,docProdReqduration]);
    }else{
      setDocProdRes([true,docProdReqduration])
    }
    const rmsResponse = await fetch("http://localhost:8080/messagesqueues/getRmsStatus",{method:"GET",headers:{
      'Authorization': `Bearer ${token}`
    }});
    const rmsString = await rmsResponse.text();
    const rmsduration = rmsString.split('/');
    if(rmsduration[0]>0){
      setRms([false,rmsduration]);
    }else{
      setRms([true,rmsduration]);
    }
    const eSigntureResponse = await fetch("http://localhost:8080/messagesqueues/getEsignatureStatus",{method:"GET",headers:{
      'Authorization': `Bearer ${token}`
    }});
    const eSigntureString = await eSigntureResponse.text();
    const eSigntureduration = eSigntureString.split('/');
    if(eSigntureduration[0]>0){
      setESignature([false,eSigntureduration]);
    }else{
      setESignature([true,eSigntureduration]);
    }
  }


  return (
    <div>
      

      {/* Pie charts */}

      <div className="grid grid-cols-1 gap-5 rounded-[20px] md:grid-cols-3">
        <PieChartCard name="Policy Center" data={policyData} sum = {policySum} error={policyError} sendDate={dateFilter}/>
        <PieChartCard name="Claim Center" data={claimData} sum = {claimSum} error={claimError} sendDate={dateFilter}/>
        <PieChartCard name="Billing Center" data={billingData} sum = {billingSum} error={billingError} sendDate={dateFilter}/>
      </div>

      {/* Message queues status*/}
      <div className="mt-3 grid grid-cols-1 gap-5 md:grid-cols-3">
        <Widget
          icon={docProdReq[0] ? <MdCheckCircle className="text-green-600 h-6 w-6 "/> : <BsFillXCircleFill className="text-red-600 h-6 w-6"/>}
          subtitle={"Document Production"}
          status={docProdReq}
        />
        <Widget
          icon={rms[0] ? <MdCheckCircle className="text-green-600 h-6 w-6 "/> : <BsFillXCircleFill className="text-red-600 h-6 w-6"/>}
          subtitle={"RmsDocUpdate"}
          status={rms}
        />
        <Widget
          icon={eSignature[0] ? <MdCheckCircle className="text-green-600 h-6 w-6 "/> : <BsFillXCircleFill className="text-red-600 h-6 w-6"/>}
          subtitle={"ESignature"}
          status={eSignature}
        />
        </div>
      
      {/* Table */}
      
      <div id= "isScrolling" className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-1">
        <DocumentsTable
          columnsData={columnsDataComplex}
          tableData={documentData}
          centerFilter={filterByCenter}
          statusFilter={filterByStatus}
          sendField={filterByField}
          center={center}
          status={status}
          field={field}
        />
      </div>
    </div>
  );
};

export default Documents;
