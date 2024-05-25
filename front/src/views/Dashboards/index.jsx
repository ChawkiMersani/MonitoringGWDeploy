import Stats from "components/stats/stats";
import GwAreaChart from "./components/GwAreaChart";
import Jauge from "./components/Jauge";
import Radar from "./components/Radar";
import { MdBarChart, MdDangerous, MdDashboard, MdError } from "react-icons/md";
import { IoMdHome } from "react-icons/io";
import { IoDocuments } from "react-icons/io5";
import PieChart from "./components/PieChart";
import { getAreaChartData } from "./api";
import { useEffect } from "react";
import BarChartCard from "./components/BarChartCard";


const Dashboards = () => {



    return (
        <>
            <div className="mt-3 mb-3 grid grid-cols-1 gap-5 md:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-3 3xl:grid-cols-6">
                <Stats
                    icon={<IoDocuments className="h-7 w-7" />}
                    title={"Daily documents"}
                    subtitle={"20"}
                />
                <Stats
                    icon={<IoDocuments className="h-6 w-6" />}
                    title={"Monthly documents"}
                    subtitle={"600"}
                />
                <Stats
                    icon={<MdDangerous className="h-7 w-7" />}
                    title={"Daily errors"}
                    subtitle={"3"}
                />
                <Stats
                    icon={<MdDangerous className="h-6 w-6" />}
                    title={"Monthly errors"}
                    subtitle={"90"}
                />
                <Stats
                    icon={<MdError className="h-7 w-7" />}
                    title={"Critical phase"}
                    subtitle={"Archiving"}
                />

                <Stats
                    icon={<MdError className="h-6 w-6" />}
                    title={"Critical center"}
                    subtitle={"Policy"}
                />
            </div>
            <GwAreaChart />
            <div className="pl-[7%] flex gap-5" >

                <Radar />
                <PieChart />
            </div>
            <div className="grid grid-cols-1 gap-5 rounded-[20px] md:grid-cols-3 pt-[1%]">
                <Jauge center="Policy" />
                <Jauge center="Claim" />
                <Jauge center="Billing" />
            </div>
            <div className="grid grid-cols-1 gap-5 rounded-[20px] md:grid-cols-2">
                <BarChartCard />

            </div>

        </>
    );

};
export default Dashboards;