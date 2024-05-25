import CardMenu from "components/card/CardMenu";
import Card from "components/card";
import {
  useGlobalFilter,
  useSortBy,
  useTable,
} from "react-table";
import { useEffect, useMemo, useState } from "react";
import CardMenu1 from "components/card/CardMenu1.0";
import { FiSearch } from "react-icons/fi";
import { useNavigate } from "react-router-dom";
const DocumentsTable = (props) => {
  const { columnsData, tableData } = props;
  const columns = useMemo(() => columnsData, [columnsData]);
  const data = useMemo(() => tableData, [tableData]);
  const [field,setField]= useState(props.field)
  const navigate=useNavigate();
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


  //Filter functions

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

      <div className="mt-8 overflow-y-scroll xl:overflow-hidden">
        <table {...getTableProps()} className="w-full">
          <thead>
            {headerGroups.map((headerGroup, index) => (
              <tr {...headerGroup.getHeaderGroupProps()} key={index}>
                {headerGroup.headers.map((column, index) => (
                  <th
                    {...column.getHeaderProps(column.getSortByToggleProps())}
                    key={index}
                    className="border-b border-gray-200 pr-28 pb-[10px] text-start dark:!border-navy-700"
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
                
                <tr {...row.getRowProps()} key={index}>
                  {}
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
                        <button onClick={()=>{handleClick(row.values["publicID"])}}>
                        <p className="text-sm font-bold text-navy-700 dark:text-white">
                          {formattedDate}
                        </p>
                        </button>
                      );
                    } else if (cell.column.Header === "PublicID") {
                      data = (
                        <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700 dark:text-white">
                          {cell.value}
                        </p></button>
                      );
                    } else if (cell.column.Header === "Service") {
                      data = (
                        <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700 dark:text-white">
                          {cell.value}
                        </p></button>
                      );
                    }else if (cell.column.Header === "LinkedObject") {
                      data = (
                        <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700 dark:text-white">
                          {cell.value}
                        </p></button>
                      );
                    }  else if (cell.column.Header === "Type") {
                      data = (
                        <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700 dark:text-white">
                          {cell.value==null ? "null": (cell.value ? "Inboud" : "Outbound")}
                        </p></button>
                      );
                    }else if (cell.column.Header === "Status") {
                      switch(cell.value){
                          case 'Generated':
                            data= <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700" style={{color: "#4318FF"}}>
                            {cell.value}
                          </p></button>
                            break;
                          case 'Transmitted':
                            data= <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700" style={{color: "#6AD2FF"}}>
                            {cell.value}
                          </p></button>
                            break;
                          case 'Archived':
                            data= <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700" style={{color: "#FFAA1D"}}>
                            {cell.value}
                          </p></button>
                            break;
                          case 'Uploaded':
                            data= <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700" style={{color: "#239B56"}}>
                              {cell.value}
                            </p></button>
                              break;
                          case 'Sent':
                            data= <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700" style={{color: "#6C33A4"}}>
                              {cell.value}
                            </p></button>
                            break;
                          default:
                            data= <button onClick={()=>{handleClick(row.values["publicID"])}}><p className="text-sm font-bold text-navy-700" style={{color: "#cc1c08"}}>
                            Error
                          </p></button>
                        }
                      }else if (cell.column.Header === "Signature") {
                        data=<button onClick={()=>{handleClick(row.values["publicID"])}}>
                        <p className="text-sm font-bold text-navy-700 dark:text-white">
                          {cell.value}
                        </p>
                        </button>
                      }
                    return (
                      <td
                        className="pt-[14px] pb-[18px] sm:text-[14px]"
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

export default DocumentsTable;
