
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Shield, Activity, AlertCircle } from 'lucide-react';
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";

const PortScanningSimulation = () => {
  const { toast } = useToast();
  const [targetIP, setTargetIP] = useState('192.168.1.1');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [scanComplete, setScanComplete] = useState(false);
  
  // Type for port status
  type PortStatus = "open" | "closed" | "filtered";
  
  // Define port scan results with proper typing
  const [scanResults, setScanResults] = useState<Array<{
    port: number;
    service: string;
    status: PortStatus;
    heat: number;
  }>>([]);

  // Common ports and services for the simulation
  const commonPorts = [
    { port: 21, service: "FTP" },
    { port: 22, service: "SSH" },
    { port: 23, service: "Telnet" },
    { port: 25, service: "SMTP" },
    { port: 80, service: "HTTP" },
    { port: 443, service: "HTTPS" },
    { port: 445, service: "SMB" },
    { port: 3306, service: "MySQL" },
    { port: 3389, service: "RDP" },
    { port: 8080, service: "HTTP-ALT" }
  ];

  // Start port scanning simulation
  const startScan = () => {
    // Validate IP address (simple validation)
    if (!targetIP.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) {
      toast({
        title: "Invalid IP Address",
        description: "Please enter a valid IPv4 address",
        variant: "destructive"
      });
      return;
    }

    setScanResults([]);
    setScanning(true);
    setProgress(0);
    setScanComplete(false);
    
    // Show starting toast
    toast({
      title: "Port Scan Initiated",
      description: `Scanning ${targetIP} for open ports...`,
      variant: "default"
    });
  };

  // Simulate scan progress
  useEffect(() => {
    if (!scanning) return;

    let currentPort = 0;
    const totalPorts = commonPorts.length;
    const scanInterval = setInterval(() => {
      if (currentPort >= totalPorts) {
        clearInterval(scanInterval);
        setScanning(false);
        setScanComplete(true);
        
        // Show completion toast - use default variant instead of success
        toast({
          title: "Port Scan Complete",
          description: `Scanned ${totalPorts} ports on ${targetIP}`,
          variant: "default"
        });
        return;
      }

      const port = commonPorts[currentPort];
      const portStatus = Math.random() > 0.7 
        ? "open" 
        : Math.random() > 0.5 ? "filtered" : "closed";
        
      // Heat value between 0-1, with open ports having higher values
      const heatValue = portStatus === "open" 
        ? 0.7 + (Math.random() * 0.3) 
        : portStatus === "filtered" 
          ? 0.3 + (Math.random() * 0.4) 
          : Math.random() * 0.3;

      setScanResults(prev => [
        ...prev,
        { 
          port: port.port, 
          service: port.service, 
          status: portStatus as PortStatus,
          heat: heatValue 
        }
      ]);

      currentPort++;
      setProgress((currentPort / totalPorts) * 100);
      
      // If we find an open high-risk port, show an alert
      if (portStatus === "open" && (port.port === 23 || port.port === 445)) {
        toast({
          title: `Critical: Port ${port.port} (${port.service}) Open`,
          description: "This port should be secured immediately",
          variant: "destructive"
        });
      }
    }, 600);

    return () => clearInterval(scanInterval);
  }, [scanning, targetIP, toast]);

  // Get status badge based on port status
  const getStatusBadge = (status: PortStatus) => {
    switch (status) {
      case "open":
        return <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">Open</Badge>;
      case "filtered":
        return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">Filtered</Badge>;
      case "closed":
        return <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">Closed</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  return (
    <Card className="overflow-hidden shadow-lg border-orange-500/20">
      <CardHeader className="bg-gradient-to-r from-orange-500/10 to-transparent">
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-orange-500" />
          Port Scanning Simulation
        </CardTitle>
        <CardDescription>
          Simulate port scanning detection and response capabilities
        </CardDescription>
      </CardHeader>
      
      <CardContent className="p-6">
        <div className="space-y-6">
          {/* IP Input and Scan Button */}
          <div className="flex space-x-2">
            <div className="flex-1">
              <Input
                value={targetIP}
                onChange={(e) => setTargetIP(e.target.value)}
                placeholder="Target IP Address"
                disabled={scanning}
              />
            </div>
            <Button
              onClick={startScan}
              disabled={scanning}
              className="bg-orange-500 hover:bg-orange-600"
            >
              {scanning ? "Scanning..." : "Start Port Scan"}
            </Button>
          </div>
          
          {/* Scanning Progress */}
          {scanning && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Scanning {targetIP}...</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <Progress value={progress} className="w-full h-2" />
            </div>
          )}
          
          {/* Results Table */}
          {scanResults.length > 0 && (
            <div className="border rounded-lg overflow-hidden">
              <div className="grid grid-cols-5 bg-muted p-2 text-xs font-medium">
                <div>Port</div>
                <div>Service</div>
                <div>Status</div>
                <div>Risk Level</div>
                <div>Actions</div>
              </div>
              
              <div className="divide-y">
                {scanResults.map((result, index) => (
                  <div key={index} className="grid grid-cols-5 p-2 text-sm items-center hover:bg-muted/50">
                    <div className="font-mono">{result.port}</div>
                    <div>{result.service}</div>
                    <div>{getStatusBadge(result.status)}</div>
                    <div>
                      <div className="w-full bg-muted rounded-full h-1.5">
                        <div 
                          className={`h-full rounded-full ${
                            result.heat > 0.7 ? 'bg-red-500' : 
                            result.heat > 0.3 ? 'bg-amber-500' : 
                            'bg-green-500'
                          }`} 
                          style={{ width: `${result.heat * 100}%` }}
                        ></div>
                      </div>
                    </div>
                    <div>
                      <Button variant="outline" size="sm" className="h-7 text-xs">
                        Block
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Vulnerability Assessment */}
          {scanComplete && (
            <div className="bg-orange-500/5 border border-orange-500/20 rounded-lg p-4">
              <div className="flex items-center gap-2 text-orange-500 font-medium mb-2">
                <AlertCircle size={16} />
                <span>Vulnerability Assessment</span>
              </div>
              <p className="text-sm mb-2">
                {scanResults.filter(r => r.status === "open").length} open ports detected on {targetIP}
              </p>
              <div className="text-sm">
                {scanResults.filter(r => r.status === "open").length > 0 ? (
                  <span className="text-red-500">
                    Open ports may indicate potential security vulnerabilities.
                  </span>
                ) : (
                  <span className="text-green-500">
                    No open ports detected. Good security posture.
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      </CardContent>
      
      <CardFooter className="bg-muted/30 px-6 py-4">
        <div className="flex items-center text-xs text-muted-foreground">
          <Shield className="h-3 w-3 mr-1" />
          Port scanning detection helps identify reconnaissance activity
        </div>
      </CardFooter>
    </Card>
  );
};

export default PortScanningSimulation;
