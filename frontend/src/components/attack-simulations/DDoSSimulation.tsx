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

const DDoSSimulation = () => {
  const [isSimulating, setIsSimulating] = useState(false);
  const [progress, setProgress] = useState(0);
  const [alerts, setAlerts] = useState<SimulationAlert[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<string[]>([]);
  const [trafficData, setTrafficData] = useState<{ time: string; packets: number; baseline: number }[]>([]);
  
  // Generate initial data
  useEffect(() => {
    const initialData = Array.from({ length: 20 }).map((_, i) => ({
      time: `${i}s`,
      packets: Math.floor(Math.random() * 100) + 100,
      baseline: 120
    }));
    setTrafficData(initialData);
  }, []);
  
  const startSimulation = () => {
    setIsSimulating(true);
    setProgress(0);
    setAlerts([]);
    
    // Simulation timer
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsSimulating(false);
          return 100;
        }
        return prev + 5;
      });
      
      // Update traffic data
      setTrafficData(prev => {
        const newData = [...prev];
        newData.shift();
        
        const lastTime = parseInt(newData[newData.length - 1].time);
        const spikeMultiplier = progress > 20 ? (progress > 70 ? 10 : 5) : 1;
        
        newData.push({
          time: `${lastTime + 1}s`,
          packets: Math.floor(Math.random() * 500 * spikeMultiplier) + 100,
          baseline: 120
        });
        
        return newData;
      });
      
      // Generate random alert at 30% and 70% progress
      if (progress === 30 || progress === 70) {
        const randomIP = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        
        const newAlert: SimulationAlert = {
          id: `ddos-${Date.now()}`,
          type: 'ddos',
          message: `DDoS attack detected from IP ${randomIP}`,
          severity: progress === 70 ? 'critical' : 'warning',
          timestamp: new Date(),
          details: {
            sourceIP: randomIP,
            packetRate: `${Math.floor(Math.random() * 10000) + 5000}/sec`,
            protocol: 'SYN',
          }
        };
        
        setAlerts(prev => [...prev, newAlert]);
      }
    }, 500);
    
    return () => clearInterval(interval);
  };
  
  const blockIP = (ip: string) => {
    if (!blockedIPs.includes(ip)) {
      setBlockedIPs(prev => [...prev, ip]);
    }
  };
  
  const unblockIP = (ip: string) => {
    setBlockedIPs(prev => prev.filter(blockedIp => blockedIp !== ip));
  };
  
  const stopSimulation = () => {
    setIsSimulating(false);
    setProgress(0);
  };
  
  const chartConfig = {
    packets: {
      label: "Packet Rate",
      color: "#9b87f5"
    },
    baseline: {
      label: "Baseline",
      color: "#6E59A5"
    }
  };

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader className="bg-gradient-to-r from-isimbi-navy to-isimbi-dark-charcoal">
        <div className="flex justify-between items-center">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-isimbi-purple" />
              DDoS / SYN Flood
            </CardTitle>
            <CardDescription>Simulate volumetric network attacks and monitor traffic spikes</CardDescription>
          </div>
          <Badge variant={isSimulating ? "destructive" : "outline"} className="ml-2">
            {isSimulating ? "ACTIVE" : "Ready"}
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="p-6">
        {/* Traffic Graph */}
        <div className="h-[200px] w-full mb-4">
          <ChartContainer config={chartConfig}>
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(155, 135, 245, 0.1)" />
              <XAxis dataKey="time" stroke="#6E59A5" />
              <YAxis stroke="#6E59A5" />
              <ChartTooltip content={<ChartTooltipContent />} />
              <ChartLegend />
              <Line 
                type="monotone" 
                dataKey="packets" 
                stroke="#9b87f5"
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 6, strokeWidth: 0 }}
              />
              <Line 
                type="monotone" 
                dataKey="baseline" 
                stroke="#6E59A5" 
                strokeDasharray="5 5" 
                strokeWidth={1.5}
                dot={false}
              />
            </LineChart>
          </ChartContainer>
        </div>
        
        {/* Alerts Section */}
        <div className="mb-4">
          <h3 className="text-sm font-medium mb-2">Attack Alerts</h3>
          <div className="space-y-2 max-h-[150px] overflow-y-auto">
            {alerts.length > 0 ? (
              alerts.map(alert => (
                <Alert key={alert.id} className={`${
                  alert.severity === 'critical' ? 'border-red-500/50 bg-red-500/10' : 
                  alert.severity === 'warning' ? 'border-amber-500/50 bg-amber-500/10' : 
                  'border-blue-500/50 bg-blue-500/10'}`
                }>
                  <AlertCircle className={`h-4 w-4 ${
                    alert.severity === 'critical' ? 'text-red-500' : 
                    alert.severity === 'warning' ? 'text-amber-500' : 
                    'text-blue-500'}`
                  } />
                  <AlertTitle className="text-sm">{alert.message}</AlertTitle>
                  <AlertDescription className="text-xs">
                    <div className="flex flex-wrap gap-2 mt-1">
                      <span>Source: {alert.details?.sourceIP}</span>
                      <span>Rate: {alert.details?.packetRate}</span>
                      <span>Protocol: {alert.details?.protocol}</span>
                      <div className="w-full flex gap-2 mt-2">
                        {blockedIPs.includes(alert.details?.sourceIP) ? (
                          <Button 
                            size="sm" 
                            variant="outline" 
                            onClick={() => unblockIP(alert.details?.sourceIP)}
                          >
                            Unblock IP
                          </Button>
                        ) : (
                          <Button 
                            size="sm" 
                            variant="destructive" 
                            onClick={() => blockIP(alert.details?.sourceIP)}
                          >
                            Block IP
                          </Button>
                        )}
                      </div>
                    </div>
                  </AlertDescription>
                </Alert>
              ))
            ) : (
              <div className="text-center py-4 text-sm text-muted-foreground">
                No alerts detected
              </div>
            )}
          </div>
        </div>
        
        {/* Blocked IPs */}
        {blockedIPs.length > 0 && (
          <div className="mb-4">
            <h3 className="text-sm font-medium mb-2">Blocked IPs</h3>
            <div className="flex flex-wrap gap-2">
              {blockedIPs.map(ip => (
                <Badge key={ip} variant="secondary" className="flex items-center gap-1">
                  {ip}
                  <Button 
                    variant="ghost" 
                    size="icon" 
                    className="h-4 w-4 ml-1 hover:bg-transparent" 
                    onClick={() => unblockIP(ip)}
                  >
                    <span className="sr-only">Remove</span>
                    <AlertCircle className="h-3 w-3" />
                  </Button>
                </Badge>
              ))}
            </div>
          </div>
        )}
        
        {/* Progress indicator during simulation */}
        {isSimulating && (
          <div className="w-full bg-secondary rounded-full h-2.5 mb-4">
            <div 
              className="bg-isimbi-purple h-2.5 rounded-full transition-all duration-500" 
              style={{ width: `${progress}%` }}
            ></div>
          </div>
        )}
      </CardContent>
      
      <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between">
        <div className="text-xs text-muted-foreground">
          {blockedIPs.length > 0 ? `${blockedIPs.length} IPs blocked` : "No IPs blocked"}
        </div>
        <div>
          {isSimulating ? (
            <Button variant="outline" onClick={stopSimulation} className="gap-2">
              <Loader2 className="h-4 w-4 animate-spin" />
              Stop Simulation
            </Button>
          ) : (
            <Button onClick={startSimulation} className="gap-2">
              <Zap className="h-4 w-4" />
              Simulate Flood
            </Button>
          )}
        </div>
      </CardFooter>
    </Card>
  );
};

export default DDoSSimulation;
