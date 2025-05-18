import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Shield, 
  Users, 
  Globe, 
  Database,
  AlertOctagon,
  Bell,
  Info,
  ArrowRight
} from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import Header from '../components/layout/Header';
import MetricsCard from '../components/dashboard/MetricsCard';
import ThreatMap from '../components/dashboard/ThreatMap';
import ActivityStream from '../components/dashboard/ActivityStream';
import AIAssistant from '../components/common/AIAssistant';

// Mock data for activity stream
const mockActivities = [
  {
    id: "1",
    type: "threat" as const,
    severity: "critical" as const,
    message: "Unusual authentication pattern detected",
    details: "Multiple failed login attempts followed by successful access",
    source: "185.93.2.41",
    timestamp: new Date(Date.now() - 3 * 60 * 1000),
  },
  {
    id: "2",
    type: "network" as const,
    severity: "warning" as const,
    message: "Suspicious outbound connection",
    details: "Connection to known malicious IP address",
    source: "10.0.1.4",
    destination: "103.56.112.8",
    timestamp: new Date(Date.now() - 15 * 60 * 1000),
  },
  {
    id: "3",
    type: "system" as const,
    severity: "info" as const,
    message: "System update completed",
    details: "All system components updated to latest version",
    timestamp: new Date(Date.now() - 35 * 60 * 1000),
  },
  {
    id: "4",
    type: "threat" as const,
    severity: "blocked" as const,
    message: "Malware connection blocked",
    details: "Attempted connection to command & control server prevented",
    source: "10.0.3.56",
    destination: "91.243.85.12",
    timestamp: new Date(Date.now() - 47 * 60 * 1000),
  },
  {
    id: "5",
    type: "auth" as const,
    severity: "warning" as const,
    message: "User password expired",
    details: "Admin user 'jsmith' needs to update credentials",
    timestamp: new Date(Date.now() - 120 * 60 * 1000),
  },
];

// Simulated emerging threat data
const emergingThreats = [
  {
    id: 1,
    name: "DragonFly APT",
    severity: "critical",
    type: "Advanced Persistent Threat",
    details: "Targeting energy sector with spear-phishing campaign",
    affectedSystems: ["Windows Server 2019", "VMWare ESXi"],
    timestamp: new Date(Date.now() - 75 * 60 * 1000),
    detectionCount: 3
  },
  {
    id: 2,
    name: "CosmicRaven Ransomware",
    severity: "critical",
    type: "Ransomware",
    details: "New variant with enhanced encryption and data exfiltration",
    affectedSystems: ["Linux", "Windows"],
    timestamp: new Date(Date.now() - 120 * 60 * 1000),
    detectionCount: 1
  },
  {
    id: 3,
    name: "ShadowScript Injection",
    severity: "warning",
    type: "Web Vulnerability",
    details: "Targeting Node.js applications with prototype pollution",
    affectedSystems: ["Web Services", "Node.js"],
    timestamp: new Date(Date.now() - 240 * 60 * 1000),
    detectionCount: 8
  }
];

// Map routes to tab values
const routeToTabMap = {
  '/dashboard': 'overview',
  '/threats': 'threat-intel',
  '/network': 'network',
  '/logs': 'logs',
  '/models': 'models',
  '/users': 'users',
  '/settings': 'settings'
};

const Dashboard = () => {
  const location = useLocation();
  const navigate = useNavigate();
  
  // State for last updated time and dynamic data
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [threatMetrics, setThreatMetrics] = useState({
    critical: 8,
    warning: 14,
    info: 15,
    blocked: 23
  });
  const [isAnomalyDetected, setIsAnomalyDetected] = useState(false);
  
  // Determine active tab based on current route
  const activeTab = routeToTabMap[location.pathname] || 'overview';
  
  // Handle tab change
  const handleTabChange = (value: string) => {
    // Map tab values back to routes
    const tabToRouteMap: Record<string, string> = {
      'overview': '/dashboard',
      'threat-intel': '/threats',
      'network': '/network',
      'logs': '/logs',
      'models': '/models',
      'users': '/users',
      'settings': '/settings'
    };
    
    if (tabToRouteMap[value]) {
      navigate(tabToRouteMap[value]);
    }
  };
  
  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setLastUpdated(new Date());
      
      // Simulate fluctuating threat metrics
      setThreatMetrics(prev => ({
        critical: prev.critical + Math.floor(Math.random() * 3) - 1,
        warning: prev.warning + Math.floor(Math.random() * 5) - 2,
        info: prev.info + Math.floor(Math.random() * 7) - 3,
        blocked: prev.blocked + Math.floor(Math.random() * 4) - 1
      }));
      
      // Simulate random anomaly detection (10% chance)
      if (Math.random() < 0.1 && !isAnomalyDetected) {
        setIsAnomalyDetected(true);
        toast({
          title: "Network Anomaly Detected",
          description: "Unusual traffic pattern from 192.168.1.45",
          variant: "destructive"
        });
        
        // Auto-reset after 10 seconds
        setTimeout(() => setIsAnomalyDetected(false), 10000);
      }
      
    }, 30000); // Update every 30 seconds
    
    return () => clearInterval(interval);
  }, [isAnomalyDetected]);
  
  return (
    <div className="flex relative h-screen bg-background">
    
      
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        
        <main className="flex-1 overflow-auto p-6">
          <div className="max-w-7xl mx-auto">
            {/* Dashboard header with anomaly indicator */}
            <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold tracking-tight">
                    {location.pathname === '/dashboard' ? 'Security Dashboard' : 
                     location.pathname === '/threats' ? 'Threat Intelligence' :
                     location.pathname === '/network' ? 'Network Map' :
                     location.pathname === '/logs' ? 'Logs & Analysis' :
                     location.pathname === '/models' ? 'ML & AI Models' :
                     location.pathname === '/users' ? 'Access Control' :
                     location.pathname === '/settings' ? 'System Settings' : 'Security Dashboard'}
                  </h1>
                  {isAnomalyDetected && (
                    <Badge variant="outline" className="bg-red-500/10 border-red-500 text-red-400 animate-pulse">
                      <AlertOctagon className="mr-1 h-3 w-3" /> Anomaly Detected
                    </Badge>
                  )}
                </div>
                <p className="text-muted-foreground">
                  {location.pathname === '/dashboard' ? 'Monitor and analyze your security posture in real-time' :
                   location.pathname === '/threats' ? 'Track and respond to emerging security threats' :
                   location.pathname === '/network' ? 'Visualize and monitor network traffic' : 
                   location.pathname === '/logs' ? 'Search and analyze security event logs' :
                   location.pathname === '/models' ? 'Manage and train AI security models' :
                   location.pathname === '/users' ? 'Manage user access and permissions' :
                   location.pathname === '/settings' ? 'Configure system settings and integrations' :
                   'Monitor and analyze your security posture in real-time'}
                </p>
              </div>
              
              <div className="mt-4 md:mt-0 text-xs text-muted-foreground flex items-center">
                <Bell className="mr-1 h-3 w-3" />
                Last updated: {lastUpdated.toLocaleTimeString()}
              </div>
            </div>
            
            {/* Metrics cards */}
            {location.pathname === '/dashboard' && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <MetricsCard 
                  title="Traffic Volume" 
                  value="1.8 TB"
                  description="Total network traffic in last 24h"
                  icon={<Activity size={16} />}
                  trend={{ direction: 'up', value: '12%', label: 'vs yesterday' }}
                  variant="info"
                />
                
                <MetricsCard 
                  title="Threats Today" 
                  value={threatMetrics.critical + threatMetrics.warning + threatMetrics.info}
                  description={`${threatMetrics.critical} critical, ${threatMetrics.warning} warning, ${threatMetrics.info} info`}
                  icon={<Shield size={16} />}
                  trend={{ direction: 'down', value: '5%', label: 'vs yesterday' }}
                  variant="warning"
                />
                
                <MetricsCard 
                  title="Active Users" 
                  value="184"
                  description="23 admins, 161 standard users"
                  icon={<Users size={16} />}
                  trend={{ direction: 'neutral', value: '0%', label: 'unchanged' }}
                />
                
                <MetricsCard 
                  title="ML Accuracy" 
                  value="99.7%"
                  description="Based on last 10,000 events"
                  icon={<Database size={16} />}
                  trend={{ direction: 'up', value: '0.2%', label: 'since last training' }}
                  variant="success"
                />
              </div>
            )}
            
            {/* Emerging threats section */}
            {(location.pathname === '/dashboard' || location.pathname === '/threats') && (
              <Card className="mb-6 border-red-500/20 shadow-lg animate-fade-in">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium flex items-center">
                    <AlertOctagon className="mr-2 text-red-400" size={18} />
                    Emerging Threats
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {emergingThreats.map((threat) => (
                      <div 
                        key={threat.id}
                        className={cn(
                          "glass-card p-4 border rounded-lg",
                          threat.severity === 'critical' ? "border-red-500/20" : "border-amber-500/20"
                        )}
                      >
                        <div className="flex justify-between items-start mb-2">
                          <h3 className="font-medium text-sm">{threat.name}</h3>
                          <Badge 
                            variant="outline"
                            className={cn(
                              "text-xs",
                              threat.severity === 'critical' ? "border-red-500 text-red-400" : "border-amber-500 text-amber-400"
                            )}
                          >
                            {threat.severity.toUpperCase()}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mb-2">{threat.type}</p>
                        <p className="text-xs mb-3">{threat.details}</p>
                        <div className="text-xs text-muted-foreground">
                          <span>Affected: </span>
                          {threat.affectedSystems.map((sys, i) => (
                            <Badge key={i} variant="secondary" className="mr-1 text-[10px]">
                              {sys}
                            </Badge>
                          ))}
                        </div>
                        <div className="flex items-center justify-between mt-3 pt-2 border-t border-border/50">
                          <span className="text-xs text-muted-foreground">
                            {threat.detectionCount} {threat.detectionCount === 1 ? 'detection' : 'detections'}
                          </span>
                          <Button variant="ghost" size="sm" className="h-6 text-xs">
                            Investigate <ArrowRight className="ml-1" size={12} />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
            
            {/* Main content - tabs */}
            <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-4">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="threat-intel">Threat Intelligence</TabsTrigger>
                <TabsTrigger value="network">Network</TabsTrigger>
                <TabsTrigger value="logs">Logs</TabsTrigger>
                {location.pathname === '/models' && <TabsTrigger value="models">ML Models</TabsTrigger>}
                {location.pathname === '/users' && <TabsTrigger value="users">Users</TabsTrigger>}
                {location.pathname === '/settings' && <TabsTrigger value="settings">Settings</TabsTrigger>}
              </TabsList>
              
              <TabsContent value="overview" className="space-y-4">
                <ThreatMap className="animate-fade-in" />
                
                <div className="mt-6">
                  <h2 className="text-xl font-semibold mb-4 flex items-center">
                    Recent Activity
                    <Badge className="ml-2 bg-blue-500/20 border-blue-400 text-blue-400">
                      Live
                    </Badge>
                    <Button variant="ghost" size="sm" className="ml-auto h-7 text-xs">
                      View All <ArrowRight className="ml-1" size={12} />
                    </Button>
                  </h2>
                  <ActivityStream activities={mockActivities} />
                </div>
              </TabsContent>
              
              <TabsContent value="threat-intel">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">Threat Intelligence</h2>
                  <p className="mb-4">View and analyze security threats affecting your organization.</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Threat Feed Status</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span>MITRE ATT&CK</span>
                          <Badge variant="outline" className="bg-green-500/10 text-green-500">Active</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span>OSINT Feed</span>
                          <Badge variant="outline" className="bg-green-500/10 text-green-500">Active</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span>Threat Intel</span>
                          <Badge variant="outline" className="bg-amber-500/10 text-amber-500">Warning</Badge>
                        </div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Latest IOCs</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2 text-sm">
                          <div className="p-2 bg-background rounded-md">
                            <div className="font-mono text-xs">c4ff94a99411b0d967dd1c88cd253d7c</div>
                            <div className="text-xs text-muted-foreground">Malware hash - DragonFly APT</div>
                          </div>
                          <div className="p-2 bg-background rounded-md">
                            <div className="font-mono text-xs">103.56.112.8</div>
                            <div className="text-xs text-muted-foreground">C2 server - CosmicRaven</div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="network">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">Network Map</h2>
                  <p className="mb-4">Visualize your network topology and monitor traffic patterns.</p>
                  <div className="h-64 border border-border rounded-lg flex items-center justify-center bg-background/50">
                    <p className="text-muted-foreground">Network visualization will be displayed here</p>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="logs">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">Security Logs</h2>
                  <p className="mb-4">Search, filter, and analyze security event logs.</p>
                  <div className="border border-border rounded-lg bg-background/50 overflow-hidden">
                    <div className="p-4 bg-muted text-sm font-medium border-b border-border">
                      <div className="grid grid-cols-12 gap-4">
                        <div className="col-span-2">Timestamp</div>
                        <div className="col-span-2">Event Type</div>
                        <div className="col-span-2">Source</div>
                        <div className="col-span-6">Message</div>
                      </div>
                    </div>
                    <div className="divide-y divide-border">
                      {[...Array(5)].map((_, i) => (
                        <div key={i} className="p-4 text-sm">
                          <div className="grid grid-cols-12 gap-4">
                            <div className="col-span-2 text-muted-foreground">
                              {new Date(Date.now() - i * 1000 * 60 * 10).toLocaleTimeString()}
                            </div>
                            <div className="col-span-2">
                              <Badge variant="outline" className={
                                i % 3 === 0 ? "bg-red-500/10 text-red-500" : 
                                i % 3 === 1 ? "bg-amber-500/10 text-amber-500" : 
                                "bg-blue-500/10 text-blue-500"
                              }>
                                {i % 3 === 0 ? "ERROR" : i % 3 === 1 ? "WARNING" : "INFO"}
                              </Badge>
                            </div>
                            <div className="col-span-2 font-mono text-xs">
                              10.0.1.{Math.floor(Math.random() * 255)}
                            </div>
                            <div className="col-span-6">
                              {i % 3 === 0 ? "Failed login attempt" : 
                               i % 3 === 1 ? "Suspicious outbound connection" : 
                               "System update completed successfully"}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="models">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">ML & AI Models</h2>
                  <p className="mb-4">View and manage machine learning models for security analysis.</p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Anomaly Detection</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <Badge className="mb-2" variant="outline">Active</Badge>
                        <p className="text-sm text-muted-foreground">Detects unusual patterns in network traffic</p>
                        <div className="mt-4">
                          <div className="text-xs">Accuracy</div>
                          <div className="w-full bg-muted h-2 mt-1 rounded-full">
                            <div className="bg-green-500 h-full rounded-full" style={{ width: "94%" }}></div>
                          </div>
                          <div className="text-xs text-right">94%</div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="users">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">Access Control</h2>
                  <p className="mb-4">Manage users and permissions for system access.</p>
                  <div className="border border-border rounded-lg bg-background/50 overflow-hidden">
                    <div className="p-4 bg-muted text-sm font-medium border-b border-border">
                      <div className="grid grid-cols-12 gap-4">
                        <div className="col-span-3">User</div>
                        <div className="col-span-3">Role</div>
                        <div className="col-span-3">Last Login</div>
                        <div className="col-span-3">Status</div>
                      </div>
                    </div>
                    <div className="divide-y divide-border">
                      {[...Array(5)].map((_, i) => (
                        <div key={i} className="p-4 text-sm">
                          <div className="grid grid-cols-12 gap-4">
                            <div className="col-span-3">
                              <div className="font-medium">User {i+1}</div>
                              <div className="text-xs text-muted-foreground">user{i+1}@example.com</div>
                            </div>
                            <div className="col-span-3">
                              {i === 0 ? "Administrator" : "Standard User"}
                            </div>
                            <div className="col-span-3 text-muted-foreground">
                              {new Date(Date.now() - i * 1000 * 60 * 60 * 24).toLocaleDateString()}
                            </div>
                            <div className="col-span-3">
                              <Badge variant="outline" className="bg-green-500/10 text-green-500">
                                Active
                              </Badge>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="settings">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">System Settings</h2>
                  <p className="mb-4">Configure system settings and preferences.</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div>
                      <h3 className="text-base font-medium mb-2">Notifications</h3>
                      <Card>
                        <CardContent className="pt-6 space-y-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <div className="font-medium">Email Alerts</div>
                              <div className="text-xs text-muted-foreground">Receive critical alerts via email</div>
                            </div>
                            <Button variant="outline" size="sm">Configure</Button>
                          </div>
                          <div className="flex items-center justify-between">
                            <div>
                              <div className="font-medium">Mobile Notifications</div>
                              <div className="text-xs text-muted-foreground">Push notifications to mobile devices</div>
                            </div>
                            <Button variant="outline" size="sm">Configure</Button>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                    <div>
                      <h3 className="text-base font-medium mb-2">System</h3>
                      <Card>
                        <CardContent className="pt-6 space-y-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <div className="font-medium">Update Frequency</div>
                              <div className="text-xs text-muted-foreground">How often to check for updates</div>
                            </div>
                            <Button variant="outline" size="sm">Configure</Button>
                          </div>
                          <div className="flex items-center justify-between">
                            <div>
                              <div className="font-medium">Data Retention</div>
                              <div className="text-xs text-muted-foreground">Configure log retention policies</div>
                            </div>
                            <Button variant="outline" size="sm">Configure</Button>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </div>
        </main>
      </div>
      
      <AIAssistant />
    </div>
  );
};

export default Dashboard;
