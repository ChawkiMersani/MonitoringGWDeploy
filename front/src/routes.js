import React from "react";

import {
  MdHome,
  MdQueryStats,
  MdWebStories,
} from "react-icons/md";
import Dashboards from "views/dashboards";
import Progress from "views/Progress";
import Documents from "views/documents";

const routes = [
  {
    name: "Documents",
    layout: "/main",
    path: "documents",
    icon: <MdHome className="h-6 w-6" />,
    component: <Documents />,
  },
  {
    name: "Progress",
    layout: "/main",
    path: "progress",
    icon: <MdWebStories className="h-6 w-6" />,
    component: <Progress />,
  },
  {
    name: "Dashboards",
    layout: "/main",
    path: "dashboards",
    icon: <MdQueryStats className="h-6 w-6" />,
    component: <Dashboards />,
  }
];
export default routes;
