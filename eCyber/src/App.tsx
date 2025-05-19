
import React, { useEffect } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
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
import { ThemeProvider } from "./components/theme/ThemeProvider";

import { ThreatCve } from "./pages/threats/ThreatCve";
import { ThreatMitre } from "./pages/threats/ThreatMitre";
import { ThreatIntel } from "./pages/threats/ThreatIntel";
import { ThreatOsint } from "./pages/threats/ThreatOsint";
import Alerts from "./alert/Alerts";
import useSocket from "./hooks/useSocket";

// Create a new query client with correct configuration
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

const App = () => {


  useSocket();
  
  // Apply theme on initial load
  useEffect(() => {
    const root = window.document.documentElement;
    const theme = localStorage.getItem('theme') || 'system';
    
    if (theme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
      root.classList.add(systemTheme);
    } else {
      root.classList.add(theme);
    }
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider defaultTheme="system" storageKey="theme">
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <Routes>
              {/* Public route without sidebar */}
              <Route path="/" element={<Index />} />
    
              {/* Routes with sidebar */}
              <Route element={<MainLayout />}>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/system" element={<System/>} />
                <Route path="/alerts" element={<Alerts/>} />
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
    
              {/* 404 Page */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </BrowserRouter>
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
};

export default App;
