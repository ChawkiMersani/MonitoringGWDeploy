import { useEffect, useState } from "react";
import { inboundColumnsHeader, outboundColumnsHeader } from "./variables/columnsData.js";
import { useLocation } from "react-router-dom";
import ProgressTable from "./Components/ProgressTable.jsx";
import { getToken } from "views/SignIn/Auth.js";

function Policy() {
  const location = useLocation();
  const id = location.state.id;
  const GwLinkedObject = location.state.GwLO;
  const [documentData,setDocumentmData] = useState([]);
  const [inbound, setInboud] = useState(false);
  const token=getToken();
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch("http://localhost:8080/document/getTyped/GW_ID="+id+"?category="+GwLinkedObject+"&inbound="+inbound,{method:"GET",headers:{
          'Authorization': `Bearer ${token}`
        }});
        console.error(response);

          if (!response.ok) {
            throw new Error('Failed to fetch data');
          }
          const jsonData = await response.json();
          setDocumentmData(jsonData);
          
        } catch (error) {
          console.error('Error fetching data:', error);
        }
    }
    setDocumentmData([]);
    fetchData();
    const interval = setInterval(fetchData, 10000);

    return () => clearInterval(interval);
  }, [inbound])

  function handleType(type) {
    if (inbound != type) {
      setInboud(!inbound);
    
    }

  }
  return (

      
    <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-1">

      <div>
        <div className="flex justify-end">
          <div className="inline-block relative rounded-lg relative bg-brand-900">
            <button
              className={inbound ? "pr-3 center linear bg-gray-600 px-4 py-2 rounded-lg text-base font-medium text-white transition duration-200 hover:bg-gray-700 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:opacity-90" : "inline-block pr-3 linear bg-brand-700 px-4 py-2 rounded-lg text-base font-medium text-white transition duration-200 hover:bg-brand-800 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:opacity-90"}
              onClick={() => { handleType(false) }}
            >
              OutBound
            </button>
            <button
              className={!inbound ? "pr-3 pl-3 linear bg-gray-600 px-4 py-2 rounded-lg text-base font-medium text-white transition duration-200 hover:bg-gray-700 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:opacity-90" : "inline-block pr-3 pl-3 linear bg-brand-700 px-4 py-2 rounded-lg text-base font-medium text-white transition duration-200 hover:bg-brand-800 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:opacity-90"}
              onClick={() => { handleType(true) }}
            >
              Inbound
            </button>
          </div>
        </div>
      </div>

      {inbound ? <ProgressTable
          id={id}
        columnsData={inboundColumnsHeader}
        tableData={documentData}

      /> :
        <ProgressTable
        id={id}
          columnsData={outboundColumnsHeader}
          tableData={documentData}

        />}
    </div>
  );

}
export default Policy;