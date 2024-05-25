import React from "react";

import {
  MdBusiness,
} from "react-icons/md";
import Center from "views/LinkedObject";

const routes = [
  {
    name: "Policy Center",
    layout: "/main",
    path: "policy",
    icon: <MdBusiness className="h-6 w-6"/>,
    component: <Center center="policy"/>,
  },
  {
    name: "Claim Center",
    layout: "/main",
    icon: <MdBusiness className="h-6 w-6"/>,
    path: "claim",
    component:<Center center="claim"/>,
  },
  {
    name: "Billing Center",
    layout: "/main",
    path: "billing",
    icon: <MdBusiness className="h-6 w-6"/>,
    component: <Center center="billing"/>,
  }
];
export default routes;
