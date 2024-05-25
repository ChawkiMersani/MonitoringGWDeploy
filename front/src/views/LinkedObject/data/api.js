import { getToken } from "views/SignIn/Auth";

export const token = getToken();
export const fetchAllClaimData = async () => {
  try {
    const response = await fetch("http://localhost:8080/claim/getAll?pageNumber="+0+"&pageSize=8",{method:"GET",headers:{
      'Authorization': `Bearer ${token}`
    }});
    if (!response.ok) {
      throw new Error("Network response was not ok");
    }
    const data = await response.json();
    return data.content;
  } catch (error) {
    console.error("Error fetching submission data:", error);
    return [];
  }
};
export const fetchAllBillingData = async () => {
  try {
    const response = await fetch("http://localhost:8080/GwLinkedObject/getAll?pageNumber="+0+"&pageSize=8",{method:"GET",headers:{
      'Authorization': `Bearer ${token}`
    }});
    if (!response.ok) {
      throw new Error("Network response was not ok");
    }
    const data = await response.json();
    return data.content;
  } catch (error) {
    console.error("Error fetching submission data:", error);
    return [];
  }
};
export const fetchAccountData = async (pageNumber,center) => {
    try {
      console.log(center);
      const response = await fetch("http://localhost:8080/accounts/getAll?pageNumber="+pageNumber+"&pageSize=100&center="+center,{method:"GET",headers:{
        'Authorization': `Bearer ${token}`
      }});
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      
      const data = await response.json();
      console.log(data);
      return data.content;
    } catch (error) {
      console.error("Error fetching account data:", error);
      return [];
    }
  };
  
  export const fetchSubmissionData = async () => {
    try {
      const response = await fetch("http://localhost:8080/submissions/getAll?pageNumber=0&pageSize=100",{method:"GET",headers:{
        'Authorization': `Bearer ${token}`
      }});
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      const data = await response.json();
      return data.content;
    } catch (error) {
      console.error("Error fetching submission data:", error);
      return [];
    }
  };
  
  export const fetchPolicyData = async () => {
    try {
      const response = await fetch("http://localhost:8080/policies/getAll?pageNumber=0&pageSize=10",{method:"GET",headers:{
        'Authorization': `Bearer ${token}`
      }});
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      const data = await response.json();
      console.log(data.content);
      return data.content;
    } catch (error) {
      console.error("Error fetching policy data:", error);
      return [];
    }
  };
  export const fetchDataByGwLinkedObject = async (field) => {
    let arr=[];
    try {
      const response = await fetch("http://localhost:8080/GwLinkedObject/get?id="+field,{method:"GET",headers:{
        'Authorization': `Bearer ${token}`
      }});
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      const data = await response.json();
      return [data];
    } catch (error) {
      console.error("Error fetching submission data:", error);
      return [];
    }
  };
  