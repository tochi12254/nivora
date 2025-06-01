
import React, { useEffect, useState } from 'react';
import { Socket } from 'socket.io-client';
import { useTheme } from '@/components/theme/ThemeProvider';
import { 
  Shield, AlertTriangle, Network, Database, User, 
  Package, Globe, Terminal, Monitor 
} from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

// Import simulation components
import DDoSSimulation from '@/components/attack-simulations/DDoSSimulation';
import PortScanningSimulation from '@/components/attack-simulations/PortScanningSimulation';
import SQLInjectionSimulation from '@/components/attack-simulations/SQLInjectionSimulation';
import PhishingSimulation from '@/components/attack-simulations/PhishingSimulation';
import UnauthorizedAccessSimulation from '@/components/attack-simulations/UnauthorizedAccessSimulation';
import MalwareSimulation from '@/components/attack-simulations/MalwareSimulation';
import DataExfiltrationSimulation from '@/components/attack-simulations/DataExfiltrationSimulation';
import BehavioralDeviationSimulation from '@/components/attack-simulations/BehavioralDeviationSimulation';
import NetworkTrafficVisualizer from '@/components/attack-simulations/NetworkTrafficVisualizer';
import ManualScanComponent from '@/components/attack-simulations/ManualScanComponent';
import HoneypotsInterface from '@/components/attack-simulations/HoneypotsInterface';
import UserEducationCenter from '@/components/attack-simulations/UserEducationCenter';
import PrivacyPolicy from '@/components/attack-simulations/PrivacyPolicy';
import ContactSupport from '@/components/attack-simulations/ContactSupport';
import SystemMonitoring from '@/components/attack-simulations/SystemMonitoring';
import DomainMonitor from '@/components/attack-simulations/DomainMonitor';
import VulnerabilityScanner from '@/components/attack-simulations/VulnerabilityScanner';
import URLClassifier from '@/components/attack-simulations/URLClassifier';

import { useTelemetrySocket } from '@/components/live-system/lib/socket';

const AttackSimulations = () => {

  const {
    getSocket
  } = useTelemetrySocket();

  const { theme } = useTheme();
  const [activeTab, setActiveTab] = useState("attack-simulations");
  const socket: Socket | null = getSocket()

  useEffect(() => {
    if (socket) {
      socket.on('interfaces', (data: any) => {
        console.log("Network Interfaces: ", data)
      })

      return () => {
        socket.off('interfaces');
      }
    }
    
  },[socket])

  return (
    <div className="container mx-auto py-8 animate-fade-in">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-isimbi-purple mb-2">
          Attacks Playground
        </h1>
        <p className="text-muted-foreground">
          Interactive security testing environment for simulating various cyber attacks and monitoring system responses
        </p>
        <Separator className="my-4" />
      </header>
      
      <Tabs defaultValue="attack-simulations" className="w-full" onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-4 md:grid-cols-8 mb-8">
          <TabsTrigger value="attack-simulations" className="gap-2">
            <Shield size={16} />
            <span className="hidden md:inline">Attacks</span>
          </TabsTrigger>
          <TabsTrigger value="network">
            <Network size={16} />
            <span className="hidden md:inline">Network</span>
          </TabsTrigger>
          {/* <TabsTrigger value="scans">
            <AlertTriangle size={16} />
            <span className="hidden md:inline">Scans</span>
          </TabsTrigger> */}
          {/* <TabsTrigger value="honeypots">
            <Database size={16} />
            <span className="hidden md:inline">Honeypots</span>
          </TabsTrigger> */}
          {/* <TabsTrigger value="education">
            <User size={16} />
            <span className="hidden md:inline">Education</span>
          </TabsTrigger> */}
          <TabsTrigger value="system">
            <Monitor size={16} />
            <span className="hidden md:inline">System</span>
          </TabsTrigger>
          {/* <TabsTrigger value="domain">
            <Globe size={16} />
            <span className="hidden md:inline">Domains</span>
          </TabsTrigger> */}
          {/* <TabsTrigger value="tools">
            <Terminal size={16} />
            <span className="hidden md:inline">Tools</span>
          </TabsTrigger> */}
        </TabsList>
        
        <TabsContent value="attack-simulations" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <DDoSSimulation />
            <PortScanningSimulation />
            <SQLInjectionSimulation />
            <PhishingSimulation />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <UnauthorizedAccessSimulation />
            <MalwareSimulation />
            <DataExfiltrationSimulation />
            <BehavioralDeviationSimulation />
          </div>
        </TabsContent>
        
        <TabsContent value="network">
          <NetworkTrafficVisualizer />
        </TabsContent>
        
        {/* <TabsContent value="scans">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 ">
            <ManualScanComponent />
            <VulnerabilityScanner />
          </div>
        </TabsContent> */}
{/*         
        <TabsContent value="honeypots">
          <HoneypotsInterface />
        </TabsContent> */}
        
        <TabsContent value="education">
          <UserEducationCenter />
        </TabsContent>
        
        <TabsContent value="system">
          <SystemMonitoring />
        </TabsContent>
        
        {/* <TabsContent value="domain">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <DomainMonitor />
            <URLClassifier />
          </div>
        </TabsContent> */}
        
        {/* <TabsContent value="tools">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Privacy Policy & Legal</CardTitle>
                <CardDescription>Legal information about data usage and privacy</CardDescription>
              </CardHeader>
              <CardContent>
                <PrivacyPolicy />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Contact & Support</CardTitle>
                <CardDescription>Get help or provide feedback</CardDescription>
              </CardHeader>
              <CardContent>
                <ContactSupport />
              </CardContent>
            </Card>
          </div>
        </TabsContent> */}
      </Tabs>
    </div>
  );
};

export default AttackSimulations;
