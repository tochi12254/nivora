// import React, { useState, useEffect } from 'react';
// import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
// import { Button } from "@/components/ui/button";
// import { Input } from "@/components/ui/input";
// import { Label } from "@/components/ui/label";
// import { Progress } from "@/components/ui/progress";
// import { Shield, AlertTriangle, User, Lock, Clock, MapPin, Laptop, CheckCircle, XCircle, Ban, Loader2 } from 'lucide-react';
// import { Badge } from "@/components/ui/badge";
// import { useToast } from "@/hooks/use-toast";
// import { ScrollArea } from "@/components/ui/scroll-area";
// import { Separator } from "@/components/ui/separator";
// import {
//   ChartContainer,
//   ChartTooltip,
//   ChartTooltipContent,
//   ChartLegend,
// } from "@/components/ui/chart";
// import {
//   ResponsiveContainer,
//   LineChart,
//   Line,
//   XAxis,
//   YAxis,
//   CartesianGrid,
//   Tooltip,
//   Legend
// } from "recharts";

// // Define the LoginAttempt type if not already defined
// export interface LoginAttempt {
//   id: string;
//   timestamp: Date;
//   ip: string;
//   username: string;
//   country: string;
//   status: 'success' | 'failed' | 'blocked';
//   browser: string;
//   os: string;
// }

// interface ActiveSession {
//   id: string;
//   username: string;
//   ip: string;
//   loginTime: Date;
//   location: string;
//   device: string;
//   status: 'active' | 'expired';
// }

// const UnauthorizedAccessSimulation = () => {
//   const { toast } = useToast();
//   const [isSimulating, setIsSimulating] = useState(false);
//   const [progress, setProgress] = useState(0);
//   const [loginAttempts, setLoginAttempts] = useState<LoginAttempt[]>([]);
//   const [activeSessions, setActiveSessions] = useState<ActiveSession[]>([]);
//   const [blockedIPs, setBlockedIPs] = useState<string[]>([]);
//   const [loginHistoryData, setLoginHistoryData] = useState<{ time: string; attempts: number; blocked: number }[]>([]);
  
//   // Generate initial data
//   useEffect(() => {
//     const initialData = Array.from({ length: 20 }).map((_, i) => ({
//       time: `${i}s`,
//       attempts: Math.floor(Math.random() * 5) + 5,
//       blocked: Math.floor(Math.random() * 2)
//     }));
//     setLoginHistoryData(initialData);
//   }, []);

//   // Function to generate a random IP address
//   const generateRandomIP = () => {
//     return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
//   };

//   // Function to get a random username
//   const getRandomUsername = () => {
//     const usernames = ['john.doe', 'jane.smith', 'admin', 'test.user', 'security'];
//     return usernames[Math.floor(Math.random() * usernames.length)];
//   };

//   // Function to get a random country
//   const getRandomCountry = () => {
//     const countries = ['United States', 'Canada', 'United Kingdom', 'Germany', 'France', 'Australia', 'Japan', 'China', 'India', 'Brazil'];
//     return countries[Math.floor(Math.random() * countries.length)];
//   };

//   // Function to get a random browser
//   const getRandomBrowser = () => {
//     const browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'];
//     return browsers[Math.floor(Math.random() * browsers.length)];
//   };

//   // Function to get a random OS
//   const getRandomOS = () => {
//     const operatingSystems = ['Windows', 'macOS', 'Linux', 'Android', 'iOS'];
//     return operatingSystems[Math.floor(Math.random() * operatingSystems.length)];
//   };

//   // Function to simulate login attempts
//   const simulateLoginAttempts = () => {
//     // Generate random login attempt
//     const successful = Math.random() > 0.6;
//     const blocked = !successful && Math.random() > 0.7;
    
//     const newAttempt: LoginAttempt = {
//       id: `login-${Date.now()}`,
//       timestamp: new Date(),
//       ip: generateRandomIP(),
//       username: getRandomUsername(),
//       country: getRandomCountry(),
//       status: blocked ? 'blocked' : (successful ? 'success' : 'failed'),
//       browser: getRandomBrowser(),
//       os: getRandomOS()
//     };

//     // Add to login attempts
//     setLoginAttempts(prev => [...prev, newAttempt]);
    
//     // If suspicious or successful, add to active sessions
//     if (successful) {
//       setActiveSessions(prev => [...prev, {
//         id: `session-${Date.now()}`,
//         username: newAttempt.username,
//         ip: newAttempt.ip,
//         loginTime: new Date(),
//         location: newAttempt.country,
//         device: `${newAttempt.os} / ${newAttempt.browser}`,
//         status: 'active'
//       }]);
//     }

//     // If it's suspicious, show a toast notification
//     if (!successful && !blocked && Math.random() > 0.7) {
//       toast({
//         title: "Suspicious Login Attempt",
//         description: `Failed login attempt for ${newAttempt.username} from ${newAttempt.country}`,
//         variant: "destructive"
//       });
//     }
//   };

//   // Function to block an IP address
//   const blockIP = (ip: string) => {
//     if (!blockedIPs.includes(ip)) {
//       setBlockedIPs(prev => [...prev, ip]);
//     }
//   };

//   // Function to unblock an IP address
//   const unblockIP = (ip: string) => {
//     setBlockedIPs(prev => prev.filter(blockedIp => blockedIp !== ip));
//   };

//   // Function to start the simulation
//   const startSimulation = () => {
//     setIsSimulating(true);
//     setProgress(0);
//     setLoginAttempts([]);
//     setActiveSessions([]);
//     setBlockedIPs([]);

//     // Simulation timer
//     const interval = setInterval(() => {
//       setProgress(prev => {
//         if (prev >= 100) {
//           clearInterval(interval);
//           setIsSimulating(false);
//           return 100;
//         }
//         return prev + 5;
//       });

//       // Simulate login attempts
//       simulateLoginAttempts();
      
//       // Update login history data
//       setLoginHistoryData(prev => {
//         const newData = [...prev];
//         newData.shift();
        
//         const lastTime = parseInt(newData[newData.length - 1].time);
//         const attempts = Math.floor(Math.random() * 5) + 5;
//         const blocked = Math.floor(Math.random() * 2);
        
//         newData.push({
//           time: `${lastTime + 1}s`,
//           attempts: attempts,
//           blocked: blocked
//         });
        
//         return newData;
//       });
//     }, 500);
    
//     return () => clearInterval(interval);
//   };

//   // Function to stop the simulation
//   const stopSimulation = () => {
//     setIsSimulating(false);
//     setProgress(0);
//   };
  
//   const chartConfig = {
//     attempts: {
//       label: "Login Attempts",
//       color: "#9b87f5"
//     },
//     blocked: {
//       label: "Blocked",
//       color: "#f472b6"
//     }
//   };

//   return (
//     <Card className="overflow-hidden shadow-lg border-red-500/20">
//       <CardHeader className="bg-gradient-to-r from-red-500/10 to-transparent">
//         <div className="flex justify-between items-center">
//           <div>
//             <CardTitle className="flex items-center gap-2">
//               <Shield className="h-5 w-5 text-red-500" />
//               Unauthorized Access
//             </CardTitle>
//             <CardDescription>Simulate and detect unauthorized login attempts and active sessions</CardDescription>
//           </div>
//           <Badge variant={isSimulating ? "destructive" : "outline"} className="ml-2">
//             {isSimulating ? "ACTIVE" : "Ready"}
//           </Badge>
//         </div>
//       </CardHeader>

//       <CardContent className="p-6">
//         {/* Login History Graph */}
//         <div className="h-[200px] w-full mb-4">
//           <ChartContainer config={chartConfig}>
//             <LineChart data={loginHistoryData}>
//               <CartesianGrid strokeDasharray="3 3" stroke="rgba(155, 135, 245, 0.1)" />
//               <XAxis dataKey="time" stroke="#6E59A5" />
//               <YAxis stroke="#6E59A5" />
//               <ChartTooltip content={<ChartTooltipContent />} />
//               <ChartLegend />
//               <Line
//                 type="monotone"
//                 dataKey="attempts"
//                 stroke="#9b87f5"
//                 strokeWidth={2}
//                 dot={false}
//                 activeDot={{ r: 6, strokeWidth: 0 }}
//               />
//               <Line
//                 type="monotone"
//                 dataKey="blocked"
//                 stroke="#f472b6"
//                 strokeWidth={2}
//                 dot={false}
//                 activeDot={{ r: 6, strokeWidth: 0 }}
//               />
//             </LineChart>
//           </ChartContainer>
//         </div>
        
//         {/* Login Attempts */}
//         <div className="mb-4">
//           <h3 className="text-sm font-medium mb-2">Recent Login Attempts</h3>
//           <ScrollArea className="max-h-[200px]">
//             {loginAttempts.length > 0 ? (
//               <div className="divide-y">
//                 {loginAttempts.map(attempt => (
//                   <div key={attempt.id} className="py-2">
//                     <div className="flex items-center justify-between">
//                       <div className="flex items-center gap-2">
//                         {attempt.status === 'success' && <CheckCircle className="h-4 w-4 text-green-500" />}
//                         {attempt.status === 'failed' && <XCircle className="h-4 w-4 text-red-500" />}
//                         {attempt.status === 'blocked' && <Ban className="h-4 w-4 text-orange-500" />}
//                         <span className="text-sm font-medium">{attempt.username}</span>
//                       </div>
//                       <div className="text-xs text-muted-foreground">
//                         <Clock className="h-3 w-3 inline-block mr-1" />
//                         {attempt.timestamp.toLocaleTimeString()}
//                       </div>
//                     </div>
//                     <div className="text-xs text-muted-foreground mt-1">
//                       <MapPin className="h-3 w-3 inline-block mr-1" />
//                       {attempt.country} | <Laptop className="h-3 w-3 inline-block mr-1" />
//                       {attempt.os} / {attempt.browser} | IP: {attempt.ip}
//                       {blockedIPs.includes(attempt.ip) && (
//                         <Badge variant="secondary" className="ml-1">Blocked</Badge>
//                       )}
//                     </div>
//                     {attempt.status === 'failed' && !blockedIPs.includes(attempt.ip) && (
//                       <Button variant="destructive" size="xs" className="mt-2" onClick={() => blockIP(attempt.ip)}>
//                         Block IP
//                       </Button>
//                     )}
//                   </div>
//                 ))}
//               </div>
//             ) : (
//               <div className="text-center py-4 text-sm text-muted-foreground">
//                 No login attempts recorded
//               </div>
//             )}
//           </ScrollArea>
//         </div>

//         {/* Active Sessions */}
//         <div className="mb-4">
//           <h3 className="text-sm font-medium mb-2">Active Sessions</h3>
//           <ScrollArea className="max-h-[150px]">
//             {activeSessions.length > 0 ? (
//               <div className="divide-y">
//                 {activeSessions.map(session => (
//                   <div key={session.id} className="py-2">
//                     <div className="flex items-center justify-between">
//                       <div className="flex items-center gap-2">
//                         <User className="h-4 w-4 text-blue-500" />
//                         <span className="text-sm font-medium">{session.username}</span>
//                       </div>
//                       <div className="text-xs text-muted-foreground">
//                         <Clock className="h-3 w-3 inline-block mr-1" />
//                         {session.loginTime.toLocaleTimeString()}
//                       </div>
//                     </div>
//                     <div className="text-xs text-muted-foreground mt-1">
//                       <MapPin className="h-3 w-3 inline-block mr-1" />
//                       {session.location} | <Laptop className="h-3 w-3 inline-block mr-1" />
//                       {session.device} | IP: {session.ip}
//                     </div>
//                   </div>
//                 ))}
//               </div>
//             ) : (
//               <div className="text-center py-4 text-sm text-muted-foreground">
//                 No active sessions
//               </div>
//             )}
//           </ScrollArea>
//         </div>

//         {/* Blocked IPs */}
//         {blockedIPs.length > 0 && (
//           <div className="mb-4">
//             <h3 className="text-sm font-medium mb-2">Blocked IPs</h3>
//             <div className="flex flex-wrap gap-2">
//               {blockedIPs.map(ip => (
//                 <Badge key={ip} variant="secondary" className="flex items-center gap-1">
//                   {ip}
//                   <Button
//                     variant="ghost"
//                     size="icon"
//                     className="h-4 w-4 ml-1 hover:bg-transparent"
//                     onClick={() => unblockIP(ip)}
//                   >
//                     <span className="sr-only">Remove</span>
//                     <AlertTriangle className="h-3 w-3" />
//                   </Button>
//                 </Badge>
//               ))}
//             </div>
//           </div>
//         )}

//         {/* Progress indicator during simulation */}
//         {isSimulating && (
//           <div className="w-full bg-secondary rounded-full h-2.5 mb-4">
//             <div
//               className="bg-red-500 h-2.5 rounded-full transition-all duration-500"
//               style={{ width: `${progress}%` }}
//             ></div>
//           </div>
//         )}
//       </CardContent>

//       <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between">
//         <div className="text-xs text-muted-foreground">
//           {activeSessions.length} active sessions | {blockedIPs.length} IPs blocked
//         </div>
//         <div>
//           {isSimulating ? (
//             <Button variant="outline" onClick={stopSimulation} className="gap-2">
//               <Loader2 className="h-4 w-4 animate-spin" />
//               Stop Simulation
//             </Button>
//           ) : (
//             <Button onClick={startSimulation} className="gap-2">
//               <Lock className="h-4 w-4" />
//               Simulate Attempts
//             </Button>
//           )}
//         </div>
//       </CardFooter>
//     </Card>
//   );
// };

// export default UnauthorizedAccessSimulation;



import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Terminal, ShieldAlert, Download } from 'lucide-react';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface LogEntry {
  timestamp: string;
  event: string;
  severity: 'info' | 'warning' | 'error';
}

const UnauthorizedAccessSimulation = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    let intervalId: NodeJS.Timeout;

    if (isRunning) {
      intervalId = setInterval(() => {
        const newLog: LogEntry = {
          timestamp: new Date().toLocaleTimeString(),
          event: `Unauthorized access attempt from IP: ${generateRandomIp()}`,
          severity: Math.random() > 0.5 ? 'warning' : 'error',
        };
        setLogs((prevLogs) => [newLog, ...prevLogs]);
      }, 1500);
    }

    return () => clearInterval(intervalId);
  }, [isRunning]);

  const startSimulation = () => {
    setIsRunning(true);
    setLogs([]);
  };

  const stopSimulation = () => {
    setIsRunning(false);
  };

  const generateRandomIp = () => {
    return Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');
  };

  const handleDownloadLogs = () => {
    const logContent = logs.map(log => `[${log.timestamp}] ${log.severity.toUpperCase()}: ${log.event}`).join('\n');
    const blob = new Blob([logContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'unauthorized_access_logs.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <ShieldAlert className="h-5 w-5" />
          <span>Unauthorized Access Simulation</span>
        </CardTitle>
        <CardDescription>Simulate unauthorized access attempts to test security measures.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex space-x-4">
          <Button variant="outline" onClick={isRunning ? stopSimulation : startSimulation}>
            {isRunning ? 'Stop Simulation' : 'Start Simulation'}
          </Button>
          <Button 
            variant="outline" 
            size="sm" // Changed from "xs" to "sm"
            className="text-xs h-6" 
            onClick={handleDownloadLogs}
          >
            Download Logs
          </Button>
        </div>
        <div className="overflow-auto max-h-64">
          {logs.length === 0 ? (
            <div className="text-center text-gray-500">No logs generated. Start the simulation.</div>
          ) : (
            <ul className="space-y-2">
              {logs.map((log, index) => (
                <li key={index} className="flex items-center space-x-2">
                  <span className="text-xs text-gray-600">{log.timestamp}</span>
                  <Badge variant={log.severity === 'error' ? 'destructive' : 'secondary'}>
                    {log.severity.toUpperCase()}
                  </Badge>
                  <span className="text-sm">{log.event}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default UnauthorizedAccessSimulation;