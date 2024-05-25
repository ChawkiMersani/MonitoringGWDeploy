import React, { useEffect } from "react";
import avatar from "assets/img/Nft1.png";
import banner from "assets/img/banner.png";
import Card from "components/card";
import UsersTable from "./Components/UsersTable";
import General from "./Components/UserData";
import { getUser } from "views/SignIn/Auth";

const Profile = () => {
    const user= JSON.parse(getUser());
  return (
    <Card extra={"items-center w-full h-full p-[16px] bg-cover"}>
      <div
        className="relative mt-1 flex h-32 w-full justify-center rounded-xl bg-cover"
        style={{ backgroundImage: `url(${banner})` }}
      >
        <div className="absolute -bottom-12 flex h-[87px] w-[87px] items-center justify-center rounded-full border-[4px] border-white bg-pink-400 dark:!border-navy-700">
          <img className="h-full w-full rounded-full" src={avatar} alt="" />
        </div>
      </div>
      <div className="mt-16 flex flex-col items-center">
        <h4 className="text-xl font-bold text-navy-700 dark:text-white">
          {user.firstName+" "+user.lastName}
        </h4>
        <p className="text-base font-normal text-gray-600">{user.role}</p>
      </div>
      <General />
      <div
        className="relative mt-1 flex w-full justify-center rounded-xl"
      >
      <UsersTable/>
      </div>
    </Card>
  );
};

export default Profile;