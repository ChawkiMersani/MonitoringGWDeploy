import React, { useEffect, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";

import Main from "main";
import SignIn from "views/SignIn/SignIn";
import { isAuthenticated } from "views/SignIn/Auth";
const App = () => {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/SignIn" replace />} />
      <Route path="SignIn" element={<SignIn/>} />
      <Route path="main/*" element={isAuthenticated() && <Main />} />
    </Routes>
  );
};

export default App;


