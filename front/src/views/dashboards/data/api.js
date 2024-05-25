// src/api/api.js
export const fetchDocumentCounts = async ({ service, inbound, startDate, endDate }) => {
  const url = `http://localhost:8080/document/countByServiceTypeAndDate?service=${encodeURIComponent(service)}&inbound=${inbound}&startDate=${encodeURIComponent(startDate)}&endDate=${encodeURIComponent(endDate)}`;
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error('Failed to fetch data');
    return await response.json();
  } catch (error) {
    console.error('Error fetching document counts:', error);
    throw error;
  }
};
