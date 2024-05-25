import React, { useState, useEffect } from 'react';
import Card from "components/card";
import BarChart from "components/charts/BarChart";
import { TEDropdown, TEDropdownMenu, TEDropdownToggle } from "tw-elements-react";
import MiniCalendar from "components/calendar/MiniCalendar";
import { barChartOptionsWeeklyRevenue } from "variables/charts"; // Ensure this import is correct
import { getToken } from 'views/SignIn/Auth';

const BarChartCard = (props) => {
    const today = new Date();
    const [dates, setDates] = useState({
        startDate: new Date(today.getFullYear(), today.getMonth(), 1),
        endDate: today
    });

    const [chartData, setChartData] = useState({
        series: [],
        options: barChartOptionsWeeklyRevenue // Use predefined options from charts.js
    });
    const token = getToken();

    useEffect(() => {
        const fetchData = async (service, inbound) => {
            const startDateFormatted = `${dates.startDate.getFullYear()}-${dates.startDate.getMonth() + 1}-${dates.startDate.getDate()}`;
            const endDateFormatted = `${dates.endDate.getFullYear()}-${dates.endDate.getMonth() + 1}-${dates.endDate.getDate()}`;
            const url = `http://localhost:8080/document/countByServiceTypeAndDate?service=${service}&inbound=${inbound}&startDate=${startDateFormatted}&endDate=${endDateFormatted}`;
            try {
                const response = await fetch(url, {
                    method: "GET", headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                const count = await response.json();
                return count;
            } catch (error) {
                console.error("Error fetching data:", error);
                return [];
            }
        };

        const updateChartData = async () => {
            const services = ['PolicyCenter', 'ClaimCenter', 'BillingCenter'];
            let inboundData = [];
            let outboundData = [];

            for (const service of services) {
                const inboundCount = await fetchData(service, 1); // true for inbound
                const outboundCount = await fetchData(service, 0); // false for outbound
                inboundData.push(inboundCount);
                outboundData.push(outboundCount);
            }

            setChartData({
                ...chartData,
                series: [
                    { name: "Inbound", data: inboundData, color: "#6AD2Fa" },
                    { name: "Outbound", data: outboundData, color: "#4318FF" },
                    { name: "Total", data: inboundData.map((value, index) => value + outboundData[index]), color: "#EFF4FB" }
                ]
            });
        };

        updateChartData();
    }, [dates]);

    const handleDateChange = (newDates) => {
        setDates({
            startDate: newDates[0],
            endDate: newDates[1]
        });
    };

    return (
        <Card extra="flex flex-col bg-white w-full rounded-3xl py-6 px-2 text-center">
            <div className="mb-auto flex items-center justify-between px-6">
                <h2 className="text-lg font-bold text-navy-700 dark:text-white">Documents Type:</h2>

                <div className="mb-6 flex items-center justify-center">
                    <TEDropdown className="flex justify-center">
                        <TEDropdownToggle>
                            <div style={{ display: 'flex' }}>
                                <text>
                                    {dates.startDate.getDate() + " - " + dates.startDate.getMonth() + " / " + dates.endDate.getDate() + " - " + dates.endDate.getMonth()}
                                </text>
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6" color="#4318FF">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 0 1 2.25-2.25h13.5A2.25 2.25 0 0 1 21 7.5v11.25m-18 0A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75m-18 0v-7.5A2.25 2.25 0 0 1 5.25 9h13.5A2.25 2.25 0 0 1 21 11.25v7.5" />
                                </svg>
                            </div>
                        </TEDropdownToggle>
                        <TEDropdownMenu>
                            <MiniCalendar sendDates={handleDateChange} />
                        </TEDropdownMenu>
                    </TEDropdown>
                </div>
            </div>
            <BarChart chartData={chartData.series} chartOptions={chartData.options} />
        </Card>
    );
};

export default BarChartCard;
