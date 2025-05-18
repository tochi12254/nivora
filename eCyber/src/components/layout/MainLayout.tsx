
import React, { useState, useEffect } from 'react';
import Sidebar from "./Sidebar";
import { Outlet } from "react-router-dom";
import Header from './Header';
import AIAssistant from "../common/AIAssistant";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { Shield, Bell } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Separator } from "@/components/ui/separator";

const MainLayout = () => {
  const [isMounted, setIsMounted] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [notificationCount, setNotificationCount] = useState(3);
  
  useEffect(() => {
    setIsMounted(true);
  }, []);

  const toggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  return (
    <div className="flex h-screen w-full bg-background">
      {/* Sidebar with responsive width */}
      <div 
        className={`hidden md:flex bg-gray-100 dark:bg-gray-900 border-r border-border transition-all duration-300 ${
          sidebarCollapsed ? "w-[60px]" : "w-[250px]"
        }`}
      >
        <Sidebar />
      </div>

      {/* Main content takes remaining width */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Header*/}
        <header className="h-14 border-b border-border flex items-center justify-between px-4 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
          <div className="flex items-center">
            
            <h1 className="text-lg font-semibold hidden md:block">Security Operations Center</h1>
          </div>
          
          <div>
            <Header/>
          </div>
    
        </header>
        
        {/* Main content area */}
        <main className="flex-1 overflow-y-auto p-4">
          <Outlet />
        </main>
        
        {/* AI Assistant only renders after initial mount to prevent hydration issues */}
        {isMounted && <AIAssistant />}
      </div>
    </div>
  );
};

export default MainLayout;
