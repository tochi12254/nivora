
import React, { useState, useEffect } from 'react';
import { AlertCircle, ShieldAlert, Zap, Loader2 } from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { SimulationAlert } from '@/components/common/ai-assistant/types';
import { 
  ChartContainer, 
  ChartTooltip, 
  ChartTooltipContent, 
  ChartLegend, 
} from "@/components/ui/chart"; 
import { 
  ResponsiveContainer, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend 
} from "recharts";

import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";

// Interface for DDoS alerts
interface DDoSAlert {
  id: string;
  timestamp: string;
  source_ip?: string; // DDoS source can be distributed/spoofed
  description: string;
  severity: 'High' | 'Critical' | 'Medium' | 'Low'; // Example severities
  target_info?: string; // e.g., targeted IP or service
  packet_rate?: string | number;
  protocol?: string;
}

const DDoSSimulation = () => {
  const { toast } = useToast();
  const [ddosAlerts, setDDoSAlerts] = useState<DDoSAlert[]>([]);

  useEffect(() => {
    const handleDDoSAlert = (data: any) => {
      // Assuming data structure from a potential 'security_alert' event
      // where data.type might be "DDoS Attack" or similar
      if (data && data.type && data.type.toLowerCase().includes('ddos')) {
        const newAlert: DDoSAlert = {
          id: data.id || `ddos-alert-${Date.now()}-${Math.random()}`,
          timestamp: data.timestamp || new Date().toISOString(),
          source_ip: data.source_ip || 'N/A (Distributed/Spoofed)',
          description: data.description || 'High volume of traffic detected.',
          severity: data.severity || 'High',
          target_info: data.target_info || data.metadata?.destination_ip || 'Unknown Target',
          packet_rate: data.packet_rate || data.metadata?.packet_rate || 'N/A',
          protocol: data.protocol || data.metadata?.protocol || 'N/A',
        };
        setDDoSAlerts(prev => [newAlert, ...prev.slice(0, 49)]); // Keep last 50
      }
    };

    // TODO: Replace with actual socket listeners for 'security_alert' or specific DDoS events
    // Example:
    // if (socket) {
    //   socket.on('security_alert', handleDDoSAlert); // General security alert
    //   // Or a specific event like: socket.on('ddos_detected', handleDDoSAlert);
    // }
    // console.log("DDoSSimulation: Would listen for DDoS-related socket events here.");

    // Mock data for subtask UI verification
    if (process.env.NODE_ENV === 'development' && !(window as any).__mockDDoSAlertsAdded) {
      (window as any).__mockDDoSAlertsAdded = true;
      setTimeout(() => {
        handleDDoSAlert({
          id: 'mockddos1', type: 'DDoS Attack', timestamp: new Date().toISOString(),
          description: 'Volumetric attack targeting web server cluster.',
          severity: 'Critical', target_info: 'Web Server Pool (10.0.1.0/24)', packet_rate: '1.2M pps', protocol: 'UDP Flood'
        });
        setTimeout(() => {
          handleDDoSAlert({
            id: 'mockddos2', type: 'ddos', timestamp: new Date().toISOString(),
            source_ip: 'Multiple (Botnet Z)', description: 'SYN Flood against login services.',
            severity: 'High', target_info: 'auth.example.com', packet_rate: '800K pps', protocol: 'TCP/SYN'
          });
        }, 2000);
      }, 1000);
    }

    return () => {
      // TODO: socket.off('security_alert', handleDDoSAlert);
      // TODO: socket.off('ddos_detected', handleDDoSAlert);
      // delete (window as any).__mockDDoSAlertsAdded;
    };
  }, []);

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader className="bg-gradient-to-r from-isimbi-navy to-isimbi-dark-charcoal">
        <CardTitle className="flex items-center gap-2 text-white">
          <ShieldAlert className="h-5 w-5 text-isimbi-purple" />
          Detected DDoS Activity
        </CardTitle>
        <CardDescription className="text-gray-300">
          Real-time monitoring of detected Distributed Denial of Service attacks.
        </CardDescription>
      </CardHeader>

      <CardContent className="p-6">
        {ddosAlerts.length === 0 ? (
          <div className="text-center text-muted-foreground py-8">
            <ShieldAlert size={48} className="mx-auto mb-2 opacity-30" />
            No DDoS activity detected recently.
          </div>
        ) : (
          <ScrollArea className="h-[400px] border rounded-md">
            <div className="divide-y">
              {ddosAlerts.map((alert) => (
                <Alert key={alert.id} className={`p-3 m-0 border-0 border-b rounded-none ${
                  alert.severity === 'Critical' ? 'bg-red-900/20 border-red-700' : 
                  alert.severity === 'High' ? 'bg-orange-700/20 border-orange-600' : 
                  'bg-yellow-600/20 border-yellow-500'}`
                }>
                  <ShieldAlert className={`h-5 w-5 mt-1 ${
                    alert.severity === 'Critical' ? 'text-red-400' : 
                    alert.severity === 'High' ? 'text-orange-400' : 
                    'text-yellow-400'}`
                  } />
                  <div className="ml-2">
                    <AlertTitle className="font-semibold text-sm mb-0.5">
                      {alert.description} {alert.target_info && `(Target: ${alert.target_info})`}
                    </AlertTitle>
                    <AlertDescription className="text-xs text-muted-foreground space-y-0.5">
                      <div>Timestamp: {new Date(alert.timestamp).toLocaleString()}</div>
                      <div>Severity: <Badge variant={
                          alert.severity === 'Critical' || alert.severity === 'High' ? 'destructive' : 'warning'
                        } className="text-xs px-1 py-0 h-auto leading-tight">
                          {alert.severity}
                        </Badge>
                      </div>
                      {alert.source_ip && <div>Source IP(s): {alert.source_ip}</div>}
                      {alert.packet_rate && <div>Packet Rate: {alert.packet_rate}</div>}
                      {alert.protocol && <div>Protocol: {alert.protocol}</div>}
                    </AlertDescription>
                    <Button 
                      variant="outline" 
                      size="xs" 
                      className="mt-2 h-6 text-xs"
                      onClick={() => toast({ title: 'Mitigation Action', description: `Initiating mitigation for alert ID: ${alert.id.substring(0,8)}`})}
                    >
                      Initiate Mitigation
                    </Button>
                  </div>
                </Alert>
              ))}
            </div>
          </ScrollArea>
        )}
      </CardContent>
      <CardFooter className="bg-card/50 border-t border-border/50 py-3">
        <div className="text-xs text-muted-foreground">
          Monitoring for DDoS attack indicators...
        </div>
      </CardFooter>
    </Card>
  );
};

export default DDoSSimulation;
