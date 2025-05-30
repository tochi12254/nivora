import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Activity, AlertCircle } from 'lucide-react'; // AlertCircle might be unused
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area"; // Added ScrollArea
import { useToast } from "@/hooks/use-toast";

// Assuming a socket context or global instance like:
// import { socket } from '@/lib/socket'; // Fictional socket instance
// For this subtask, actual socket connection is commented out in useEffect.

interface PortScanAlert {
  id: string;
  timestamp: string;
  source_ip: string;
  description: string;
  target_port?: number;
  target_ip?: string;
  severity: string;
}

const PortScanningSimulation = () => {
  const { toast } = useToast();
  const [portScanAlerts, setPortScanAlerts] = useState<PortScanAlert[]>([]);

  useEffect(() => {
    const handleSecurityAlert = (alertData: any) => {
      if (alertData && alertData.type && alertData.type.toLowerCase().includes('port scan')) {
        const newAlert: PortScanAlert = {
          id: alertData.id || `alert-${Date.now()}-${Math.random()}`, // Ensure unique ID
          timestamp: alertData.timestamp,
          source_ip: alertData.source_ip,
          description: alertData.description,
          target_port: alertData.metadata?.destination_port,
          target_ip: alertData.metadata?.destination_ip,
          severity: alertData.severity,
        };
        setPortScanAlerts(prevAlerts => [newAlert, ...prevAlerts.slice(0, 49)]); // Keep last 50
      }
    };

    // This is where you would integrate with your actual Socket.IO client
    // Example:
    // if (socket) {
    //   socket.on('security_alert', handleSecurityAlert);
    // }
    // console.log("PortScanningSimulation: Would listen for 'security_alert' socket events here.");

    // For testing the UI structure, let's add some mock data
    if (process.env.NODE_ENV === 'development' && portScanAlerts.length === 0) {
      // Set a flag to prevent repeated mock data addition in strict mode
      if (!(window as any).__mockPortScanAlertsAdded) {
        (window as any).__mockPortScanAlertsAdded = true;
        setTimeout(() => {
          handleSecurityAlert({
            id: 'dev-alert-1', timestamp: new Date().toISOString(), source_ip: '192.168.1.101',
            description: 'SYN Scan on multiple ports', type: 'Port Scan', severity: 'High',
            metadata: { destination_port: 'Various', destination_ip: '192.168.1.10' }
          });
          setTimeout(() => {
            handleSecurityAlert({
              id: 'dev-alert-2', timestamp: new Date().toISOString(), source_ip: '10.0.0.52',
              description: 'TCP Connect Scan on port 22', type: 'Port Scan', severity: 'Medium',
              metadata: { destination_port: 22, destination_ip: '192.168.1.10' }
            });
            setTimeout(() => {
              handleSecurityAlert({
                id: 'dev-alert-3', timestamp: new Date().toISOString(), source_ip: '172.16.30.10',
                description: 'UDP Scan on port 53', type: 'Port Scan', severity: 'Low',
                metadata: { destination_port: 53, destination_ip: '192.168.1.10' }
              });
            }, 1500);
          }, 1000);
        }, 500);
      }
    }

    return () => {
      // if (socket) {
      //   socket.off('security_alert', handleSecurityAlert);
      // }
      // Reset mock data flag on unmount if needed for hot reloading dev environment
      // delete (window as any).__mockPortScanAlertsAdded; 
    };
  }, []); // portScanAlerts removed from dependency array to avoid re-triggering mock data load

  return (
    <Card className="overflow-hidden shadow-lg border-orange-500/20">
      <CardHeader className="bg-gradient-to-r from-orange-500/10 to-transparent">
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-orange-500" />
          Detected Port Scan Activity
        </CardTitle>
        <CardDescription>
          Real-time list of detected port scanning events against the network.
        </CardDescription>
      </CardHeader>

      <CardContent className="p-6">
        {portScanAlerts.length === 0 ? (
          <div className="text-center text-muted-foreground py-8">
            <Shield size={48} className="mx-auto mb-2 opacity-50" />
            No port scan activity detected recently.
          </div>
        ) : (
          <div className="border rounded-lg overflow-hidden">
            <div className="grid grid-cols-6 bg-muted p-2 text-xs font-medium">
              <div>Timestamp</div>
              <div>Source IP</div>
              <div>Target IP</div>
              <div>Target Port</div>
              <div>Description</div>
              {/* <div>Severity</div> */}
              <div>Actions</div>
            </div>
            <ScrollArea className="h-[400px]">
              <div className="divide-y">
                {portScanAlerts.map((alert) => (
                  <div key={alert.id} className="grid grid-cols-6 p-2 text-sm items-center hover:bg-muted/50">
                    <div>{new Date(alert.timestamp).toLocaleString()}</div>
                    <div className="font-mono">{alert.source_ip}</div>
                    <div className="font-mono">{alert.target_ip || 'N/A'}</div>
                    <div className="font-mono break-all">{alert.target_port?.toString() || 'N/A'}</div>
                    <div className="break-words">{alert.description}</div>
                    {/* 
                    // Severity display can be added back if desired
                    <div>
                      <Badge variant={
                        alert.severity.toLowerCase() === 'high' ? 'destructive' :
                        alert.severity.toLowerCase() === 'medium' ? 'warning' : 
                        'info'
                      }>
                        {alert.severity}
                      </Badge>
                    </div> 
                    */}
                    <div>
                      <Button 
                        variant="outline" 
                        size="sm" 
                        className="h-7 text-xs"
                        onClick={() => toast({ title: 'Block Action', description: `Request to block ${alert.source_ip}`})}
                      >
                        Block IP
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default PortScanningSimulation;
