import React, { useState, useEffect, useRef } from "react";
import { IoDocumentText } from "react-icons/io5";
import Card from "components/card";
import BarChartCard from "./BarChartCard.jsx";
import {
  fetchAccountData,
  fetchSubmissionData,
  fetchPolicyData,
  fetchAllData,
  fetchAllClaimData,
  fetchAllBillingData,
  fetchDataByGwLinkedObject
} from "../data/api.js";
import "react-datepicker/dist/react-datepicker.css";
import { useNavigate } from "react-router-dom";
import { FiSearch } from "react-icons/fi";

const GwLOTable = (props) => {
  const columnsData = props.columnsData;
  const [category, setCategory] = useState(props.center);
  const [data, setData] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [field,setField]= useState("Filter By Object")
  const [pageNumber, setPageNumber] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const loader = useRef(null);
  const navigate= useNavigate();
  useEffect(()=>{setCategory(props.center)},[props.center])

  useEffect(() => {
    fetchData();
  }, [category, pageNumber]);

  const fetchData = async () => {
    try {
      let newData = [];
      switch (category) {
        case "claim":
          newData= await fetchAllClaimData(pageNumber);
          break;
        case "billing":
          newData = await fetchAccountData(pageNumber,props.center);
          break;
        case "Account":
          newData = await fetchAccountData(pageNumber,props.center);
          break;
        case "policy":
          newData = await fetchPolicyData(pageNumber);
          break;
        case "Submission":
          newData = await fetchSubmissionData(pageNumber);
          break;
        case "":
          newData=await fetchDataByGwLinkedObject(field);
          break;
        default:
          break;
      }
      setData(newData);
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };

  const handleCategoryChange = (newCategory) => {
    if (category!=newCategory){
      setCategory(newCategory);
      setData([]);
      setPageNumber(0);
    }
   
  };


  const filteredData = data.filter((row) =>
    Object.values(row).some(
      (value) =>
        value && value.toString().toLowerCase().includes(searchQuery.toLowerCase())
    )
  );
  const handleClick = (id)=>{
    navigate("/main/gwLinkedObject", { state: { id: id, GwLO: category} });
  }
  const handleChange=(event)=>{
    setField(event.target.value);
  }
  const handleKeyDown=async (event)=>{
    if(event.key === 'Enter'){;
      setCategory("");
      setData([]);
      setPageNumber(0);
    }
  }
  return (
    <>
    <Card extra="w-full mb-4 p-4 h-full">
    <div>
        <BarChartCard category={category} center={props.center}/>
    </div>
    </Card>
    <Card extra="w-full pb-10 p-4 h-full">
    <div className="relative flex items-center justify-between pt-4">
      <div className="text-xl font-bold text-navy-700 dark:text-white">
        Linked objects
      </div>
        {props.center === "policy" && 
        <>
        
          
          
          <button
            className={`mt-4 flex items-center justify-center rounded-xl px-5 py-3 text-lg font-medium transition duration-200  ${category === "policy"  
            ? "bg-brand-500 text-white hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:bg-brand-200"
            : "bg-gray-200 hover:bg-gray-300 active:bg-gray-400 text-gray-800"
              }`}
            onClick={() => handleCategoryChange("policy")}
          >
            Policies
          </button>
          <button
            className={`mt-4 flex items-center justify-center rounded-xl px-5 py-3 text-lg font-medium transition duration-200  ${category === "Submission"
            ? "bg-brand-500 text-white hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:bg-brand-200"
            : "bg-gray-200 hover:bg-gray-300 active:bg-gray-400 text-gray-800"
              }`}
            onClick={() => handleCategoryChange("Submission")}
          >
            Submissions
          </button>
          <button
           className={`mt-4 flex items-center justify-center rounded-xl px-5 py-3 text-lg font-medium transition duration-200 
           ${category === "Account"
             ? "bg-brand-500 text-white hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:bg-brand-200"
             : "bg-gray-200 hover:bg-gray-300 active:bg-gray-400 text-gray-800"
           }`}
         
          

              
            onClick={() => handleCategoryChange("Account")}
          >
            Accounts
          </button>
          </>
          }
          {
            props.center==="claim" && <><button
            className={`mt-4 flex items-center justify-center rounded-xl px-5 py-3 text-lg font-medium transition duration-200  ${category === "claim"  
            ? "bg-brand-500 text-white hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:bg-brand-200"
            : "bg-gray-200 hover:bg-gray-300 active:bg-gray-400 text-gray-800"
              }`}
            onClick={() => handleCategoryChange("claim")}
          >
            Claims
          </button>
          <button
            className={`mt-4 flex items-center justify-center rounded-xl px-5 py-3 text-lg font-medium transition duration-200  ${category === "Account"
            ? "bg-brand-500 text-white hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:bg-brand-200"
            : "bg-gray-200 hover:bg-gray-300 active:bg-gray-400 text-gray-800"
              }`}
            onClick={() => handleCategoryChange("Account")}
          >
            Accounts
          </button>
          </>
          }
          {
            props.center==="billing" && <button
            className={`mt-4 flex items-center justify-center rounded-xl px-5 py-3 text-lg font-medium transition duration-200  ${(category === "billing" || category === "Account")
            ? "bg-brand-500 text-white hover:bg-brand-600 active:bg-brand-700 dark:bg-brand-400 dark:hover:bg-brand-300 dark:active:bg-brand-200"
            : "bg-gray-200 hover:bg-gray-300 active:bg-gray-400 text-gray-800"
              }`}
            onClick={() => handleCategoryChange("Account")}
          >
            Accounts
          </button>
          }
          <div className="flex h-full items-center rounded-full bg-lightPrimary text-navy-700 dark:bg-navy-900 dark:text-white xl:w-[225px]">
            <p className="pl-3 pr-2 text-xl">
              <FiSearch className="h-4 w-4 text-gray-400 dark:text-white" />
            </p>
            <input
              type="text"
              placeholder={field}
              onChange={handleChange}
              onKeyDown={handleKeyDown}
              className="block h-12 w-full rounded-full bg-lightPrimary text-sm font-medium text-navy-700 outline-none placeholder:!text-gray-400 dark:bg-navy-900 dark:text-white dark:placeholder:!text-white sm:w-fit"
            />
          </div>
          
        </div>

      


      <div className="mt-8 overflow-x-scroll xl:overflow-x-hidden">
        {/* Search button */}

        <div className="flex justify-center w-full">
          <table className="w-full max-w-4xl">
            {/* Table header */}
            <thead>
              <tr>
                {columnsData.map((column, index) => (
                  <th
                    key={index}
                    className="border-b border-gray-200 pr-6 pb-4 text-lg font-semibold text-start dark:border-navy-700"
                  >
                    <div className="text-gray-600">{column.Header}</div>
                  </th>
                ))}
              </tr>
            </thead>
            {/* Table body */}
            <tbody>
              {data.map((row, index) => (
                <tr key={index}>
                  {columnsData.map((column, colIndex) => (
                    <td key={colIndex} className="pt-6 pb-4 text-lg">
                      {column.accessor === "ViewDocument" ? (
                        <div className="flex items-center">
                          <button
                            onClick={() => {
                              handleClick(filteredData[index].id)
                            }}
                            className="text-blue-500"
                          >
                            <IoDocumentText className="text-blue-500 text-3xl" />
                          </button>
                        </div>
                      ) : (
                        row[column.accessor]
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {hasMore && (
            <div ref={loader} className="flex justify-center my-4">
              <div className="loader"></div>
            </div>
          )}
        </div>
      </div>



    </Card>
    </>
  );
};

export default GwLOTable;
