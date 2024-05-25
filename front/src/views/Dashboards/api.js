import { getToken } from "views/SignIn/Auth";

export const token=getToken();
export const getAreaChartData = async (isWeekly) => {
    try {
      const response = await fetch("http://localhost:8080/document/DocumentsByWeekorMonth?isWeek="+isWeekly,{method:"GET",headers:{
        'Authorization': `Bearer ${token}`
      }});
      const data = await response.json();
      return data;
    } catch (error) {
      console.error("Error fetchingdata:", error);
      return [];
    }
  };

export const getPieChartData = async (start,end) => {
  try {
    const response = await fetch("http://localhost:8080/document/CentersNumbers?start="+start+"&end="+end,{method:"GET",headers:{
      'Authorization': `Bearer ${token}`
    }});
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Error fetching data:", error);
    return [];
  }
};

export const getRadarData = async (start,end) => {
  try {
    const response = await fetch("http://localhost:8080/document/ErrorsNumbers?start="+start+"&end="+end,{method:"GET",headers:{
      'Authorization': `Bearer ${token}`
    }});
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Error fetching data:", error);
    return [];
  }
};
export const getJaugeData = async (start,end,center) => {
  try {
    const response = await fetch("http://localhost:8080/document/DocumentsErrors?start="+start+"&end="+end+"&center="+center,{method:"GET",headers:{
      'Authorization': `Bearer ${token}`
    }});
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Error fetching data:", error);
    return [];
  }
};