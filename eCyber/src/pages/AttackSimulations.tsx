
import React, { useEffect, useState } from 'react';
import { Socket } from 'socket.io-client';
import { useTheme } from '@/components/theme/ThemeProvider';

// Define AlertData interface
interface AlertData {
  id: string;
  timestamp: string;
  severity: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  description: string;
  threat_type: string;
  rule_id?: string;
  metadata?: any;
  // For anomaly alerts
  anomaly_score?: number;
  threshold?: number;
  is_anomaly?: number;
}

// Interface for Firewall Block events
interface FirewallAlertData {
  id: string;
  timestamp: string;
  ip_address: string;
  reason: string;
  duration_seconds: number;
  source_component: string;
  packet_info?: {
    dst_ip?: string;
    protocol?: string;
    // Potentially other packet fields if available and relevant
  };
  action_taken: string;
}

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

  // State for alerts
  const [alerts, setAlerts] = useState<Record<string, AlertData[]>>({
    DDoS: [],
    Port_Scan: [],
    SQL_Injection: [],
    Infiltration: [],
    Bot: [],
    Brute_Force: [],
    DoS: [],
    Heartbleed: [],
    Web_Attack: [],
    Anomaly: [],
    Firewall: [] // Added key for Firewall alerts
  });

  useEffect(() => {
    if (socket) {
      socket.on('interfaces', (data: any) => {
        console.log("Network Interfaces: ", data);
      });

      const attackTypesToListen = [
        "DDoS", "Port_Scan", "Infiltration", "Bot",
        "Brute_Force", "DoS", "Heartbleed", "Web_Attack", "SQL_Injection"
      ];
      const anomalyEventName = "ANOMALY_ALERT";

      const eventListeners: { eventName: string, handler: (data: AlertData) => void }[] = [];

      attackTypesToListen.forEach(attackType => {
        // Backend events are like "PORT_SCAN_ALERT", state keys are "Port_Scan"
        // For state key, we use attackType directly as it matches the desired keys.
        const eventName = `${attackType.toUpperCase()}_ALERT`;
        const handler = (data: AlertData) => {
          console.log(`Received ${eventName}:`, data);
          setAlerts(prevAlerts => ({
            ...prevAlerts,
            [attackType]: [data, ...(prevAlerts[attackType] || [])].slice(0, 20)
          }));
        };
        socket.on(eventName, handler);
        eventListeners.push({ eventName, handler });
      });

      const anomalyHandler = (data: AlertData) => {
        console.log(`Received ${anomalyEventName}:`, data);
        setAlerts(prevAlerts => ({
          ...prevAlerts,
          Anomaly: [data, ...(prevAlerts.Anomaly || [])].slice(0, 20)
        }));
      };
      socket.on(anomalyEventName, anomalyHandler);
      eventListeners.push({ eventName: anomalyEventName, handler: anomalyHandler });

      // Listener for Firewall Blocked events
      const firewallEventName = "firewall_blocked";
      const firewallHandler = (data: FirewallAlertData) => {
        console.log(`Received ${firewallEventName}:`, data);
        const mappedAlert: AlertData = {
          id: data.id,
          timestamp: data.timestamp,
          severity: "High", // Default severity for firewall blocks
          source_ip: data.ip_address, // The IP that was blocked
          destination_ip: data.packet_info?.dst_ip || "N/A",
          destination_port: 0, // Not directly available, or use packet_info if relevant
          protocol: data.packet_info?.protocol || "N/A",
          description: data.reason,
          threat_type: "Firewall Block",
          rule_id: data.source_component, // Using source_component as a general identifier
          metadata: {
            duration_seconds: data.duration_seconds,
            action_taken: data.action_taken,
            original_packet_info: data.packet_info, // Store original packet_info if needed
            source_component: data.source_component,
          }
        };
        setAlerts(prevAlerts => ({
          ...prevAlerts,
          Firewall: [mappedAlert, ...(prevAlerts.Firewall || [])].slice(0, 20)
        }));
      };
      socket.on(firewallEventName, firewallHandler);
      eventListeners.push({ eventName: firewallEventName, handler: firewallHandler as any }); // Use 'as any' to simplify handler type matching if needed

      return () => {
        socket.off('interfaces');
        eventListeners.forEach(({ eventName, handler }) => {
          socket.off(eventName, handler);
        });
      };
    }
  }, [socket]);

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
            <DDoSSimulation alerts={alerts.DDoS || []} />
            <PortScanningSimulation alerts={alerts.Port_Scan || []} />
            <SQLInjectionSimulation alerts={alerts.SQL_Injection || []} />
            {/* Assuming SQLInjectionSimulation might listen to alerts.Web_Attack or a specific SQL_INJECTION_ALERT */}
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
          {/* Consider if anomaly alerts should be visualized here too */}
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
          <SystemMonitoring anomalyAlerts={alerts.Anomaly || []} />
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