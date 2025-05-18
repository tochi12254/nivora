import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Network, AlertTriangle, ExternalLink, Shield, Filter } from 'lucide-react';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  AreaChart,
  Area
} from 'recharts';

// Mock packet data for simulation
const generateMockPacketData = () => {
  // Sample domains to simulate real traffic
  const domains = [
    'github.com', 'cdn.gpteng.co', 'fonts.googleapis.com', 
    'bam.nr-data.net', 'clients4.google.com', 'beacons2.gvt2.com',
    'client.wns.windows.com', 'gitforwindows.org', 'api.example.com',
    'suspicious-domain.xyz'
  ];
  
  // Generate a random domain
  const randomDomain = domains[Math.floor(Math.random() * domains.length)];
  
  // Randomly decide if this is a suspicious connection (10% chance)
  const isSuspicious = Math.random() < 0.1;
  
  // Generate a random IP in the range
  const ip = `192.168.43.${Math.floor(Math.random() * 254) + 1}`;
  
  const methods = ['GET', 'POST', 'CONNECT', 'PUT', 'DELETE'];
  const randomMethod = methods[Math.floor(Math.random() * methods.length)];
  
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Postman/11.44.0 Electron/31.3.1 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15'
  ];
  const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
  
  // Current timestamp in ISO format
  const now = new Date();
  
  return {
    timestamp: now.toISOString(),
    source_ip: ip,
    host: `${randomDomain}:443`,
    path: `${randomDomain}:443`,
    method: randomMethod,
    user_agent: randomUserAgent,
    suspicious_headers: isSuspicious,
    protocol: Math.random() > 0.5 ? 'HTTPS' : 'HTTP',
    bytes_transferred: Math.floor(Math.random() * 10000) + 100
  };
};

// Generate traffic metrics data
const generateTrafficMetrics = (minutes = 10) => {
  return Array.from({ length: minutes }, (_, i) => {
    return {
      time: `${i} min ago`,
      connections: Math.floor(Math.random() * 40) + 10,
      bandwidth: Math.floor(Math.random() * 500) + 100,
      packets: Math.floor(Math.random() * 200) + 50,
      anomalyScore: Math.random() > 0.8 ? (Math.random() * 80) + 20 : (Math.random() * 20)
    };
  }).reverse();
};

const NetworkTrafficVisualizer = () => {
  const { toast } = useToast();
  const [packets, setPackets] = useState<any[]>([]);
  const [filter, setFilter] = useState('all');
  const [trafficMetrics, setTrafficMetrics] = useState(generateTrafficMetrics());
  const [activeTab, setActiveTab] = useState('live-traffic');

  // Simulate receiving packets every few seconds
  useEffect(() => {
    const interval = setInterval(() => {
      const newPacket = generateMockPacketData();
      setPackets(prev => {
        // Keep the last 100 packets
        const updatedPackets = [newPacket, ...prev].slice(0, 100);
        return updatedPackets;
      });
      
      // Show toast for suspicious traffic
      if (newPacket.suspicious_headers) {
        toast({
          title: "Suspicious Traffic Detected",
          description: `Connection to ${newPacket.host} from ${newPacket.source_ip}`,
          variant: "destructive"
        });
      }
      
      // Update traffic metrics every 10 packets
      if (packets.length % 10 === 0) {
        setTrafficMetrics(prev => {
          const newMetrics = [...prev.slice(1), {
            time: "now",
            connections: Math.floor(Math.random() * 40) + 10,
            bandwidth: Math.floor(Math.random() * 500) + 100,
            packets: Math.floor(Math.random() * 200) + 50,
            anomalyScore: Math.random() > 0.8 ? (Math.random() * 80) + 20 : (Math.random() * 20)
          }];
          return newMetrics;
        });
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [packets.length, toast]);

  const filteredPackets = filter === 'all' 
    ? packets 
    : filter === 'suspicious' 
      ? packets.filter(p => p.suspicious_headers) 
      : packets.filter(p => p.method === filter);

  const getProtocolBadge = (protocol: string) => {
    switch (protocol) {
      case 'HTTPS':
        return <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">HTTPS</Badge>;
      case 'HTTP':
        return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">HTTP</Badge>;
      default:
        return <Badge variant="outline">{protocol}</Badge>;
    }
  };

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5 text-isimbi-purple" />
          Real-Time Network Traffic
        </CardTitle>
        <CardDescription>Visualize network traffic patterns and detect anomalies</CardDescription>
      </CardHeader>
      
      <div className="border-b border-border">
        <Tabs defaultValue="live-traffic" onValueChange={setActiveTab} className="w-full">
          <div className="px-6">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="live-traffic">Live Traffic</TabsTrigger>
              <TabsTrigger value="metrics">Traffic Metrics</TabsTrigger>
              <TabsTrigger value="anomalies">Anomaly Detection</TabsTrigger>
            </TabsList>
          </div>
          
          <TabsContent value="live-traffic" className="space-y-4 p-6">
            <div className="flex justify-between items-center">
              <h3 className="text-sm font-medium">Traffic Log</h3>
              <div className="flex gap-2">
                <Select value={filter} onValueChange={setFilter}>
                  <SelectTrigger className="w-[150px] h-8">
                    <SelectValue placeholder="Filter" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Traffic</SelectItem>
                    <SelectItem value="suspicious">Suspicious Only</SelectItem>
                    <SelectItem value="GET">GET Requests</SelectItem>
                    <SelectItem value="POST">POST Requests</SelectItem>
                    <SelectItem value="CONNECT">CONNECT Requests</SelectItem>
                  </SelectContent>
                </Select>
                <Button variant="outline" size="sm" className="h-8">
                  <Filter size={14} className="mr-1" /> Filters
                </Button>
              </div>
            </div>
            
            <div className="border rounded-md">
              <div className="grid grid-cols-12 gap-2 py-2 px-3 bg-muted text-xs font-medium">
                <div className="col-span-2">Timestamp</div>
                <div className="col-span-2">Source IP</div>
                <div className="col-span-3">Host</div>
                <div className="col-span-1">Method</div>
                <div className="col-span-2">Protocol</div>
                <div className="col-span-2">Action</div>
              </div>
              
              <ScrollArea className="h-[300px]">
                <div className="divide-y">
                  {filteredPackets.length > 0 ? (
                    filteredPackets.map((packet, i) => (
                      <div 
                        key={i} 
                        className={`grid grid-cols-12 gap-2 py-2 px-3 text-xs ${packet.suspicious_headers ? 'bg-red-500/5' : ''} hover:bg-muted/50`}
                      >
                        <div className="col-span-2 font-mono">
                          {new Date(packet.timestamp).toLocaleTimeString()}
                        </div>
                        <div className="col-span-2 font-mono">{packet.source_ip}</div>
                        <div className="col-span-3 truncate" title={packet.host}>
                          {packet.host}
                        </div>
                        <div className="col-span-1">{packet.method}</div>
                        <div className="col-span-2">
                          {getProtocolBadge(packet.protocol)}
                        </div>
                        <div className="col-span-2 flex gap-1">
                          <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                            Block
                          </Button>
                          <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                            Details
                          </Button>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="py-8 text-center text-sm text-muted-foreground">
                      No traffic data available
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </TabsContent>
          
          <TabsContent value="metrics" className="p-6">
            <div className="space-y-6">
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={trafficMetrics} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(155, 155, 155, 0.1)" />
                    <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                    <YAxis tick={{ fontSize: 12 }} />
                    <Tooltip />
                    <Legend />
                    <Line 
                      type="monotone" 
                      dataKey="connections" 
                      stroke="#8884d8" 
                      strokeWidth={2}
                      dot={{ r: 3 }}
                      activeDot={{ r: 8 }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="bandwidth" 
                      stroke="#82ca9d" 
                      strokeWidth={2}
                      dot={{ r: 3 }}
                      activeDot={{ r: 8 }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="packets" 
                      stroke="#ffc658" 
                      strokeWidth={2}
                      dot={{ r: 3 }}
                      activeDot={{ r: 8 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
              
              <div className="grid grid-cols-3 gap-4">
                <div className="border rounded-md p-4">
                  <div className="text-2xl font-bold">
                    {filteredPackets.length > 0 ? filteredPackets[0].bytes_transferred : 0} KB/s
                  </div>
                  <div className="text-sm text-muted-foreground">Current Bandwidth</div>
                </div>
                <div className="border rounded-md p-4">
                  <div className="text-2xl font-bold">
                    {filteredPackets.length}
                  </div>
                  <div className="text-sm text-muted-foreground">Active Connections</div>
                </div>
                <div className="border rounded-md p-4">
                  <div className="text-2xl font-bold">
                    {filteredPackets.filter(p => p.suspicious_headers).length}
                  </div>
                  <div className="text-sm text-muted-foreground">Suspicious Packets</div>
                </div>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="anomalies" className="p-6">
            <div className="space-y-6">
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trafficMetrics} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(155, 155, 155, 0.1)" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <defs>
                      <linearGradient id="anomalyColor" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#FF4D4D" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#FF4D4D" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <Area 
                      type="monotone" 
                      dataKey="anomalyScore" 
                      stroke="#FF4D4D" 
                      strokeWidth={2}
                      fill="url(#anomalyColor)" 
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              
              <div className="border rounded-md p-4 bg-red-500/5">
                <h3 className="font-medium flex items-center">
                  <AlertTriangle size={16} className="text-red-500 mr-2" />
                  Anomaly Detection
                </h3>
                <p className="mt-2 text-sm">
                  The system has detected unusual traffic patterns in the last 10 minutes. 
                  Potential indicators of suspicious activity include:
                </p>
                <ul className="list-disc list-inside mt-2 space-y-1 text-sm">
                  <li>Unusual connection attempts from 192.168.43.131</li>
                  <li>Multiple DNS queries to client.wns.windows.com</li>
                  <li>Unexpected traffic to beacons2.gvt2.com</li>
                </ul>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
      
      <CardFooter className="bg-muted/30 flex justify-between items-center p-4">
        <div className="flex items-center text-xs text-muted-foreground">
          <Shield size={14} className="mr-1" />
          Real-time network monitoring helps detect intrusion attempts early
        </div>
        <Button size="sm" variant="outline" className="text-xs">
          <ExternalLink size={12} className="mr-1" />
          Export Log
        </Button>
      </CardFooter>
    </Card>
  );
};

export default NetworkTrafficVisualizer;