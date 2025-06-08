
import React, { useEffect, lazy, useState, Suspense } from "react";

import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";

import Dashboard from "./pages/Dashboard";
import Threats from "./pages/Threats";
import Network from "./pages/Network";
import Logs from "./pages/Logs";
import Models from "./pages/Models";
import System from "./components/live-system/System";
import Users from "./pages/Users";
import Settings from "./pages/Settings";
import AttackSimulations from "./pages/AttackSimulations";

import MainLayout from "./components/layout/MainLayout";
import NotFound from "./pages/NotFound";

import LoginPage from "./pages/Login";
import { ThreatCve } from "./pages/threats/ThreatCve";
import { ThreatMitre } from "./pages/threats/ThreatMitre";
import { ThreatIntel } from "./pages/threats/ThreatIntel";
import { ThreatOsint } from "./pages/threats/ThreatOsint";
import Alerts from "./alert/Alerts";
// import useSocket from "./hooks/useSocket"; // Assuming this is not the primary socket hook for app connectivity status
import usePacketSniffer from "./hooks/usePacketSnifferSocket";
import RegisterPage from "./pages/Register";
import CyberLoader from "./utils/Loader"
import AuthModal from "./pages/AuthModal";
// import LoadingSpinner from "./utils/LoadingSpinner";
import { useSelector } from "react-redux"
import { RootState } from "@/app/store"


const App = () => {
  const { isConnected, connectionError, socket } = usePacketSniffer();

  const [showLoader, setShowLoader] = useState(true);

  useEffect(() => {
    // Show loader for 3 minutes then reload the page
    const timer = setTimeout(() => {
      window.location.reload();
    }, 3 * 60 * 1000); // 180000ms = 3 minutes

    return () => clearTimeout(timer); // Cleanup on unmount
  }, []);

  // Optional: stop loader manually if backend is confirmed up before timeout
  const isBackendUp = useSelector((state: RootState) => state.display.isBackendUp);
  useEffect(() => {
    if (isBackendUp) {
      setShowLoader(false);
    }
  }, [isBackendUp]);

  if (showLoader) {
    return <CyberLoader isLoading={true} />;
  }

  return (
    <>
      <Routes>
        <Route path="/" element={<Index />} />
        <Route path="/loading" element={<CyberLoader />} />
        <Route element={<MainLayout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/system" element={<System />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/network" element={<Network />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/models" element={<Models />} />
          <Route path="/users" element={<Users />} />
          <Route path="/threats/cve" element={<ThreatCve />} />
          <Route path="/threats/intel" element={<ThreatIntel />} />
          <Route path="/threats/mitre" element={<ThreatMitre />} />
          <Route path="/threats/osint" element={<ThreatOsint />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/attack-simulations" element={<AttackSimulations />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
      <AuthModal />
    </>
  );
};

export default App