import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import Dashboard from "./pages/Dashboard";
import Threats from "./pages/Threats";
import Network from "./pages/Network";
import Logs from "./pages/Logs";
import Models from "./pages/Models";
import Users from "./pages/Users";
import Settings from "./pages/Settings";
import PacketFeed from "./pages/Packet"
import WebSocketNotifications from "./pages/WebSocketNotifications";
import NotFound from "./pages/NotFound";
import MainLayout from "./components/layout/MainLayout";
import Login from './pages/Login';
import { cyberWatchWebSocket } from "./services/websocket";
import ThreatList from "./test/ThreatList";
import NetworkStats from "./test/NetworkStats";
const queryClient = new QueryClient();
import useSocket from "./hooks/useSocket";
import { usePacketSnifferSocket } from "./hooks/usePacketSnifferSocket";

const App = () => {

  useSocket();
  // usePacketSnifferSocket()
  // socketPacketListener()

  return (
    
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          {/* Public route without sidebar */}
          <Route path="/" element={<Index />} />
          <Route path="/login" element={<Login/>} />
          <Route path="/socket" element={<WebSocketNotifications/>} />
          <Route path="/packet" element={<PacketFeed/>} />
          <Route path="/stats" element={<NetworkStats/>} />

          {/* Routes with sidebar */}
          <Route element={<MainLayout />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/network" element={<Network />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/models" element={<Models />} />
            <Route path="/users" element={<Users />} />
            <Route path="/settings" element={<Settings />} />
          </Route>

          {/* 404 Page */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
  )
}

export default App;
