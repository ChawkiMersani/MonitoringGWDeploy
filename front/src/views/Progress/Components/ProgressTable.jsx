import Card from "components/card";
import {
  useGlobalFilter,
  usePagination,
  useSortBy,
  useTable,
} from "react-table";
import { useEffect, useMemo, useState } from "react";
import { MdCheckCircle } from "react-icons/md";
import {BsFillXCircleFill } from "react-icons/bs";
import PopoverHorizon from "components/popover";
import { useNavigate } from "react-router-dom";
import CardMenu from "components/card/CardMenu";
import CardMenu1 from "components/card/CardMenu1.0";
import { FiSearch } from "react-icons/fi";
import { getToken } from "views/SignIn/Auth";
const ProgressTable = (props) => {
  const { columnsData, tableData } = props;
  const columns = useMemo(() => columnsData, [columnsData]);
  const data = useMemo(() => tableData, [tableData]);
  const [content,setContent]=useState();
  const navigate= useNavigate();
  const [field,setField]= useState(props.field);
  const token=getToken();
  useEffect(()=>{
  },[data])
  const tableInstance = useTable(
    {
      columns,
      data,
    },
    useGlobalFilter,
    useSortBy,
  );

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    rows,
    prepareRow,
  } = tableInstance;
  const showError = async (id) => {
    try{
      const response= await fetch("http://localhost:8080/error/id="+id,{method:"GET",headers:{
        'Authorization': `Bearer ${token}`
      }});
    const data= await response.json();
    data.message.endsWith("NON_RETRYABLE_EXT") ? setContent("Blocked in Queue : "+data.details) :data.message ? setContent(data.message) : setContent(data.errorMessage);
    }catch(error){
      console.error("failed to fetch data",error)
    }
    
  }
  function filterByCenter(centerfilter){
    props.centerFilter(centerfilter);
  }
  function filterByStatus(statusFilter){
    props.statusFilter(statusFilter);
  }
  const handleChange=(event)=>{
    setField(event.target.value);
  }
  const handleKeyDown=async (event)=>{
    if(event.key === 'Enter' && field===""){
      props.sendField("Filter By Id/Object...");
    }else if(event.key === 'Enter'){;
      props.sendField(field);
    }
  }
  const handleClick = (id)=>{
    navigate("/main/docinfo", { state: { prop: id } });
  }
  return (
    <Card extra={"w-full h-full px-6 pb-6 sm:overflow-x-auto"}>
      <div className="relative flex items-center justify-between pt-4">
        <div className="text-xl font-bold text-navy-700 dark:text-white">
          All Documents
        </div>
          <CardMenu sendData={filterByCenter} center={props.center}/>
          <CardMenu1 sendData={filterByStatus} status={props.status}/>
          <div className="flex h-full items-center rounded-full bg-lightPrimary text-navy-700 dark:bg-navy-900 dark:text-white xl:w-[225px]">
            <p className="pl-3 pr-2 text-xl">
              <FiSearch className="h-4 w-4 text-gray-400 dark:text-white" />
            </p>
            <input
              type="text"
              placeholder={props.field}
              onChange={handleChange}
              onKeyDown={handleKeyDown}
              className="block h-full w-full rounded-full bg-lightPrimary text-sm font-medium text-navy-700 outline-none placeholder:!text-gray-400 dark:bg-navy-900 dark:text-white dark:placeholder:!text-white sm:w-fit"
            />
          </div>
      </div>
      <div className="mt-8 overflow-x-scroll xl:overflow-hidden">
        <table {...getTableProps()} className="w-full">
          <thead>
            {headerGroups.map((headerGroup, index) => (
              <tr {...headerGroup.getHeaderGroupProps()} key={index}>
                {headerGroup.headers.map((column, index) => (
                  column.Header !== "Progress" && 
                  <th
                    {...column.getHeaderProps(column.getSortByToggleProps())}
                    key={index}
                    className="border-b border-gray-200 pr-28 pb-[10px] text-start dark:!border-navy-700 "
                  >
                    <p className="text-xs tracking-wide text-gray-600">
                      {column.render("Header")}
                    </p>
                  </th>
                ))}
                
              </tr>
            ))}
          </thead>
          <tbody {...getTableBodyProps()}>
            {rows.map((row, index) => {
              prepareRow(row);
              return (
                
                <tr {...row.getRowProps()} key={index} >
                  {row.cells.map((cell, index) => {
                    let data = "";
                    if (cell.column.Header === "TimeStamp") {
                      const date = new Date(cell.value);
                      const formattedDate = date.toLocaleDateString(undefined, {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                      });
                      data = (
                        <button   style={{ textAlign: 'left' }} onClick={()=>{handleClick(row.values["publicID"])}}>
                        <p className="text-sm font-bold text-navy-700 dark:text-white">
                          {formattedDate}
                        </p>
                        </button>
                      );
                    } else if (cell.column.Header === "Name") {
                      data = (
                        <button   style={{ textAlign: 'left' }} onClick={()=>{handleClick(row.values["publicID"])}}>
                        <p className="text-sm font-bold text-navy-700 dark:text-white">
                          {cell.value}
                        </p>
                        </button>
                      );
                    }else if (cell.column.Header === "PublicID") {
                      data = (
                        <button onClick={()=>{handleClick(row.values["publicID"])}}>                       
                          <p className="text-sm font-bold text-navy-700 dark:text-white">
                          {cell.value}
                        </p>
                        </button>
 
                      );
                    }else if (cell.column.Header === "Generated") {
                      if(row.values["progress"]=== "ErrorGenerating" ){
                              data= <button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%'}}><BsFillXCircleFill className="text-red-600" size={30}/></div></button>
                      }else{
                        data= <button><div style={{paddingLeft:'5%'}}><MdCheckCircle className="text-green-600"  size={30}/></div></button>
                      }                            
                            
                            
                    }else if (cell.column.Header === "Uploaded") {
                      if(row.values["progress"]=== "ErrorUploading" ){
                              data= <button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%'}}><BsFillXCircleFill className="text-red-600" size={30}/></div></button>
                      }else{
                        data= <button><div style={{paddingLeft:'5%'}}><MdCheckCircle className="text-green-600"  size={30}/></div></button>
                      }                            
                            
                            
                    }else if (cell.column.Header === "Sent") {
                      if(row.values["progress"]=== "ErrorSending" ){
                        data= <button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%'}}><BsFillXCircleFill className="text-red-600" size={30}/></div></button>
                      }else if (row.values["progress"]=== "Sent"|| row.values["progress"]=== "Archived" || row.values["progress"]=== "ErrorArchiving" || row.values["progress"]=== "ErrorSigning"){
                        data= <button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%'}}><MdCheckCircle className="text-green-600" size={30}/></div></button>
                      }else{
                        data=<button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%',maxWidth:"2%"}}><MdCheckCircle className="text-gray-600" size={30}/></div></button>
                      }                            
                            
                            
                    }else if (cell.column.Header === "Transmitted") {
                      if(row.values["progress"]=== "ErrorDelivering"){
                        data= <button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%',width:"10%"}}><BsFillXCircleFill className="text-red-600" size={30}/></div></button>
                      }else if (row.values["progress"]=== "Transmitted" || row.values["progress"]=== "Archived" || row.values["progress"]=== "ErrorArchiving" || row.values["progress"]=== "ErrorSigning"){
                        data= <button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%'}}><MdCheckCircle className="text-green-600" size={30}/></div></button>
                      }else{
                        data=<button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%',maxWidth:"2%"}}><MdCheckCircle className="text-gray-600" size={30}/></div></button>
                      } 
                            
                    }else if (cell.column.Header === "Archived") {
                      if(row.values["progress"]=== "ErrorArchiving" || row.values["progress"]=== "ErrorSigning"){
                        data= <button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%'}}><BsFillXCircleFill className="text-red-600" size={30}/></div></button>
                      }else if(row.values["progress"]=== "Archived"){
                        data= <button onClick={()=>{handleClick(row.values["publicID"])}}><div style={{paddingLeft:'5%'}}>
                          <MdCheckCircle className="text-green-600" size={30}/>
                          </div>
                          </button>
                        
                      }else {
                        data=
                        <button><div style={{paddingLeft:'5%'}}><MdCheckCircle className="text-gray-600" size={30}/></div></button>
                      }
                      
              }else if (cell.column.Header === "Progress") {
                if (cell.value.startsWith("Error")){
                  data=
                  <PopoverHorizon trigger={
                <button
                  className="linear rounded-[10px] bg-red-600 px-3 py-2 text-sm sm:text text-white transition duration-200 hover:bg-red-800 active:bg-red-700 dark:bg-red-400 dark:hover:bg-red-300 dark:active:opacity-90"
                  onClick={()=>showError(row.values["publicID"])}
                >
                  Show error
                </button>}
                content={<p className="dark:text-white text-lg">{content}</p>} placement="left-end"
                />
                  
                }
              };
                    return (
                      <td
                        className={(cell.column.Header==="PublicID")? "pt-[14px] pr-[10px] pb-[18px] sm:text-[12px] whitespace-nowrap":"pt-[14px] pb-[18px] sm:text-[12px] "}
                        {...cell.getCellProps()}
                        key={index}
                      >
                        {data}
                      </td>
                    );
                  })}

                </tr>
               
              );
            })} 
          </tbody>
          
        </table>
      </div>
    </Card>
  );
};

export default ProgressTable;
