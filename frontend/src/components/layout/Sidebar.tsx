
import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import axios from 'axios';

import { 
  LayoutDashboard, 
  ShieldAlert, 
  Globe, 
  FileBarChart, 
  Cpu, 
  Users, 
  Settings,
  Bell,
  AlertOctagon,
  Shield,
  Activity,
  Zap
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { 
  Sidebar as ShadcnSidebar,
  SidebarContent,
  SidebarHeader,
  SidebarFooter,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarSeparator
} from "@/components/ui/sidebar";
import { SidebarProvider } from "@/components/ui/sidebar";

// Enhanced nav items with badge counts and severity
const navItems = [
  { icon: LayoutDashboard, label: 'Dashboard', path: '/dashboard', badge: null },
  { 
    icon: ShieldAlert, 
    label: 'Threat Intel', 
    path: '/threats', 
    badge: { count: 8, severity: 'critical' } 
  },
  { 
    icon: Globe, 
    label: 'Network Map', 
    path: '/network', 
    badge: { count: 3, severity: 'warning' }
  },
  { 
    icon: FileBarChart, 
    label: 'Logs', 
    path: '/logs', 
    badge: { count: 156, severity: 'info' } 
  },
  { icon: Cpu, label: 'ML & AI Models', path: '/models', badge: null },
  { icon: Users, label: 'Access Control', path: '/users', badge: null },
  { icon: Settings, label: 'Settings', path: '/settings', badge: null },
];

const threatFeeds = [
  { id: 1, name: 'MITRE ATT&CK', status: 'active', icon: Shield },
  { id: 2, name: 'OSINT Feed', status: 'active', icon: Globe },
  { id: 3, name: 'Threat Intel', status: 'warning', icon: AlertOctagon },
  { id: 4, name: 'CVE Database', status: 'active', icon: Activity },
];

const Sidebar = () => {
  const location = useLocation();

  const [systemInfo, setSystemInfo] = useState<any[]>();

  useEffect(() => {
    (
      async () => {
        try {
          const info = await axios.get("http://127.0.0.1:8000/api/system/system_info");
          if (info.data) {
            setSystemInfo(info.data);

          }
        } catch (error: any) {
          console.error("Error getting system info: ", error)
        }
      }
    )();
  }, []);


  return (
    <SidebarProvider defaultOpen={true}>
      <ShadcnSidebar className="bg-sidebar border-r border-sidebar-border z-20 w-[22%]">
        <SidebarHeader className="p-0">
          <div className="flex items-center justify-between p-4 border-b border-sidebar-border">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 rounded-md bg-isimbi-purple flex items-center justify-center">
                <span className="text-white font-bold">CW</span>
              </div>
              <span className="text-lg font-semibold text-white tracking-wider">C.WATCH</span>
            </div>
          </div>
        </SidebarHeader>
        
        <SidebarContent className="px-0 py-4">
          <SidebarMenu>
            {navItems.map((item) => (
              <SidebarMenuItem key={item.path}>
                <SidebarMenuButton
                  isActive={location.pathname === item.path}
                  tooltip={item.label}
                  asChild
                >
                  <Link to={item.path} className="flex w-full items-center justify-between">
                    <div className="flex items-center">
                      <item.icon className="mr-2" size={20} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <Badge 
                        variant="outline" 
                        className={cn(
                          "ml-2 h-5 min-w-5",
                          item.badge.severity === 'critical' && "border-red-500 text-red-500 bg-red-500/10",
                          item.badge.severity === 'warning' && "border-amber-500 text-amber-500 bg-amber-500/10",
                          item.badge.severity === 'info' && "border-blue-500 text-blue-500 bg-blue-500/10"
                        )}
                      >
                        {item.badge.count}
                      </Badge>
                    )}
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
          
          <SidebarSeparator className="my-4" />
          
          <div className="px-4 mb-2">
            <h3 className="text-xs font-medium text-muted-foreground mb-2 flex items-center">
              <Bell size={14} className="mr-1" />
              THREAT FEEDS
              <Badge variant="outline" className="ml-2 bg-isimbi-purple/20 border-isimbi-purple text-isimbi-purple text-[10px] h-4 px-1">
                LIVE
              </Badge>
            </h3>
            
            <div className="space-y-1.5">
              {threatFeeds.map((feed) => (
                <TooltipProvider key={feed.id} delayDuration={300}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div 
                        className={cn(
                          "flex items-center justify-between p-2 rounded-md text-xs hover:bg-white/5 cursor-pointer group",
                          feed.status === 'warning' && "bg-amber-500/5"
                        )}
                      >
                        <div className="flex items-center">
                          <feed.icon size={14} className="mr-2" />
                          <span>{feed.name}</span>
                        </div>
                        <div className="flex items-center">
                          <div 
                            className={cn(
                              "w-2 h-2 rounded-full",
                              feed.status === 'active' ? "bg-green-500" : "bg-amber-500 animate-pulse"
                            )}
                          />
                        </div>
                      </div>
                    </TooltipTrigger>
                    <TooltipContent side="right">
                      <p>{feed.status === 'active' ? 'Feed is active and synced' : 'Warning: Feed has outdated data'}</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              ))}
            </div>
          </div>
          
          <SidebarSeparator className="my-4" />
          
         <div className="px-4">
  <h3 className="text-xs font-medium text-muted-foreground mb-2 flex items-center">
    <Zap size={14} className="mr-1" />
    SYSTEM STATUS
  </h3>
  <div className="space-y-2">
    {systemInfo && (
      <>
        <div className="flex items-center justify-between text-xs p-2">
            <span className="text-muted-foreground">CPU Load</span>
            <span className="text-white">{systemInfo?.cpu?.percent}%</span>
          </div>
          <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
            <div 
              className="h-full bg-green-500 rounded-full"
              style={{ width: `${systemInfo?.cpu?.percent}%` }}
            ></div>
          </div>

          <div className="flex items-center justify-between text-xs p-2">
            <span className="text-muted-foreground">Memory</span>
            <span className="text-white">{systemInfo?.memory?.percent}%</span>
          </div>
          <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
            <div 
              className="h-full bg-amber-500 rounded-full"
              style={{ width: `${systemInfo.memory.percent}%` }}
            ></div>
          </div>

          <div className="flex items-center justify-between text-xs p-2">
            <span className="text-muted-foreground">Disk</span>
            <span className="text-white">{systemInfo?.disk.percent?.toFixed(1)}%</span>
          </div>
          <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
            <div 
              className="h-full bg-blue-500 rounded-full"
              style={{ width: `${systemInfo?.disk?.percent}%` }}
            ></div>
          </div>
        </>
      )}
      {!systemInfo && (
        <p className="text-xs text-muted-foreground">Loading system info...</p>
      )}
    </div>
  </div>

        </SidebarContent>
        
        <SidebarFooter>
          <div className="p-4 border-t border-sidebar-border">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-xs text-sidebar-foreground/70">System Online</span>
              </div>
              <Badge variant="outline" className="text-xs border-isimbi-purple text-isimbi-purple">
                v1.4.2
              </Badge>
            </div>
          </div>
        </SidebarFooter>
      </ShadcnSidebar>
    </SidebarProvider>
  );
};

export default Sidebar;
