import { useEffect, useState } from "react";
import { outboundColumnsHeader,inboundColumnsHeader } from "../policyCenter/variables/columnsData";
import ProgressTable from "./Components/ProgressTable";
import { getToken } from "views/SignIn/Auth";

function Progress(){
  const [documentData,setDocumentmData] = useState([]);
  const [center,setCenter]=useState("All centers");
  const [status,setStatus]=useState("All status");
  const [field,setField]=useState("Filter By Id/Object...");
  const [inbound,setInboud]=useState(false);
  const [pageNumber,setPageNumber]=useState(0);
  const [change,setChange]=useState(false);
  const token = getToken();
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

  useEffect(()=>{fetchData(pageNumber);},[pageNumber,center,status,field,inbound])
  const fetchData = async (pageNumber) => {
    if(status=="All status"){
      if(center=="All centers"){
        if(field=="Filter By Id/Object..."){
          try {
            const response = await fetch("http://localhost:8080/document/getAllTyped/pageNumber="+pageNumber+"&pageSize=15?inbound="+inbound,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/id="+field+"?inbound="+inbound,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/GW_ID="+field+"?inbound="+inbound+"&pageNumber="+pageNumber,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/service="+center+"?inbound="+inbound+"&pageNumber="+pageNumber,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/id="+field+"?inbound="+inbound,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/service="+center+"/Gw_ID="+field+"?inbound="+inbound+"&pageNumber="+pageNumber,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/status="+status+"?inbound="+inbound+"&pageNumber="+pageNumber,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/id="+field+"?inbound="+inbound,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/status="+status+"/Gw_ID="+field+"?inbound="+inbound+"&pageNumber="+pageNumber,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/status="+status+"/service="+center+"?inbound="+inbound+"&pageNumber="+pageNumber,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/id="+field+"?inbound="+inbound,{method:"GET",headers:{
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
            const response = await fetch("http://localhost:8080/document/getTyped/status="+status+"/service="+center+"/Gw_ID="+field+"?inbound="+inbound+"&pageNumber="+pageNumber,{method:"GET",headers:{
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
  function handleType(type){
    if(inbound!=type){
      setInboud(!inbound);
      setChange(true);
      setPageNumber(0);
      setField("Filter By Id/Object...");
      setCenter("All centers");
      setStatus("All status");
    } 
    
  }
    
    return(
      <>
          <div className="flex justify-end">
          <div className="inline-block relative rounded-lg relative bg-brand-900">
          <button
            className={inbound ? "pr-3 center linear bg-gray-600 px-4 py-2 rounded-lg text-base font-medium text-white transition duration-200 hover:bg-gray-700 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:opacity-90": "inline-block pr-3 linear bg-brand-700 px-4 py-2 rounded-lg text-base font-medium text-white transition duration-200 hover:bg-brand-800 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:opacity-90"}
            onClick={()=>{handleType(false)}}
          >
            OutBound
          </button>
          <button
            className={!inbound ? "pr-3 pl-3 linear bg-gray-600 px-4 py-2 rounded-lg text-base font-medium text-white transition duration-200 hover:bg-gray-700 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:opacity-90": "inline-block pr-3 pl-3 linear bg-brand-700 px-4 py-2 rounded-lg text-base font-medium text-white transition duration-200 hover:bg-brand-800 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:opacity-90"}
            onClick={()=>{handleType(true)}}
          >
            Inbound
          </button>
         </div>
         </div>
         
        <div id="isScrolling" className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-1">
          
          {inbound ? <ProgressTable 
          columnsData={inboundColumnsHeader}
          tableData={documentData}
          centerFilter={filterByCenter}
          statusFilter={filterByStatus}
          sendField={filterByField}
            center={center}
            status={status}
            field={field}
          /> :
          <ProgressTable
            columnsData={outboundColumnsHeader}
            tableData={documentData}
            centerFilter={filterByCenter}
            statusFilter={filterByStatus}
            sendField={filterByField}
            center={center}
            status={status}
            field={field}
          />}
        </div>
        </>
    );

}
export default Progress;