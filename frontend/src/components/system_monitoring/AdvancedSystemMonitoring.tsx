import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { 
  Monitor, AlertTriangle, Activity, Cpu, HardDrive, Wifi, Zap, Bell, 
  Maximize, Clock, ChevronUp, ChevronDown, Database, 
  Calendar, Network, Shield, Download, Filter, List, Info,
  Server, FileText, RefreshCw, Power, Sliders, Save
} from 'lucide-react';
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
  Area,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar
} from 'recharts';
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { 
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue
} from "@/components/ui/select";
import { 
  DropdownMenu,
  DropdownMenuContent, 
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

// Types for system metrics
interface SystemMetric {
  timestamp: Date;
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  temperature: number;
}

// Types for system events
interface SystemEvent {
  id: string;
  timestamp: Date;
  type: 'info' | 'warning' | 'critical';
  message: string;
  details?: string;
  source: string;
}

// Types for process data
interface ProcessInfo {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
  disk: number;
  network: number;
  user: string;
  status: 'running' | 'sleeping' | 'stopped' | 'zombie';
  suspicious: boolean;
}

// Types for network connections
interface NetworkConnection {
  id: string;
  localIp: string;
  remoteIp: string;
  port: number;
  protocol: string;
  state: string;
  process: string;
  pid: number;
  country?: string;
  city?: string;
  riskLevel?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  riskScore?: number;
  isBlocked?: boolean;
}

// Types for authentication events
interface AuthEvent {
  id: string;
  timestamp: Date;
  username: string;
  sourceIp: string;
  status: 'success' | 'failure';
  method: string;
  suspicious: boolean;
}

// Types for attached devices
interface AttachedDevice {
  id: string;
  name: string;
  type: string;
  path: string;
  connectedAt: Date;
  isNew: boolean;
  isBlocked: boolean;
}

// System info type
interface SystemInfo {
  hostname: string;
  os: string;
  cpuModel: string;
  totalRam: string;
  uptime: number;
  status: 'healthy' | 'degraded' | 'critical';
  kernelVersion: string;
  lastBoot: Date;
}

// Connection details response type
interface ConnectionDetailsResponse {
  threat_summary: {
    risk_level: string;
    threat_score: number;
    contributing_indicators: string[];
    suggested_actions: string[];
  };
  network_details: {
    timestamp: string;
    source_ip: string;
    destination_ip: string;
    protocol: string;
  };
  security_headers_status: {
    missing_csp: boolean;
    missing_hsts: boolean;
    missing_xfo: boolean;
    missing_xcto: boolean;
    missing_rp: boolean;
    missing_xxp: boolean;
    hsts_short_max_age: boolean;
    insecure_cookies: boolean;
    insecure_csp: boolean;
  };
  behavioral_indicators: {
    beaconing_pattern: boolean;
    rapid_requests: boolean;
    slowloris_indicator: boolean;
  };
  content_analysis: {
    data_exfiltration: boolean;
    path_exfiltration: boolean;
    malicious_payloads: Record<string, any>;
    injection_patterns: string[];
  };
  header_analysis: {
    duplicate_headers: boolean;
    header_injection: boolean;
    invalid_format: boolean;
    malformed_values: boolean;
    obfuscated_headers: boolean;
    unusual_casing: boolean;
  };
}

const timeRangeOptions = ['1m', '5m', '15m', '30m', '1h', '6h', '12h', '24h'];

const AdvancedSystemMonitoring = () => {
  const { toast } = useToast();
  
  // State definitions
  const [metrics, setMetrics] = useState<SystemMetric[]>([]);
  const [events, setEvents] = useState<SystemEvent[]>([]);
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [authEvents, setAuthEvents] = useState<AuthEvent[]>([]);
  const [devices, setDevices] = useState<AttachedDevice[]>([]);
  const [systemInfo, setSystemInfo] = useState<SystemInfo>({
    hostname: 'sys-monitor-01',
    os: 'Linux Ubuntu 24.04 LTS',
    cpuModel: 'Intel Core i7-12700K @ 3.6GHz',
    totalRam: '32GB DDR4',
    uptime: 15.7, // days
    status: 'healthy',
    kernelVersion: '6.4.0-generic',
    lastBoot: new Date(new Date().getTime() - 15.7 * 24 * 60 * 60 * 1000),
  });
  
  // UI state
  const [currentCPU, setCurrentCPU] = useState(0);
  const [currentMemory, setCurrentMemory] = useState(0);
  const [currentDisk, setCurrentDisk] = useState(0);
  const [currentNetwork, setCurrentNetwork] = useState(0);
  const [currentTemperature, setCurrentTemperature] = useState(0);
  const [activeTab, setActiveTab] = useState('overview');
  const [expanded, setExpanded] = useState(true);
  const [timeRange, setTimeRange] = useState('5m');
  const [threatScore, setThreatScore] = useState(12);
  const [realtimeMonitoring, setRealtimeMonitoring] = useState(true);
  const [alertSounds, setAlertSounds] = useState(false);
  const [autoResponse, setAutoResponse] = useState(true);
  const [processFilter, setProcessFilter] = useState('');
  const [eventFilter, setEventFilter] = useState<'all' | 'info' | 'warning' | 'critical'>('all');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [selectedEventDetails, setSelectedEventDetails] = useState<SystemEvent | null>(null);
  const [selectedProcessDetails, setSelectedProcessDetails] = useState<ProcessInfo | null>(null);
  const [selectedConnectionDetails, setSelectedConnectionDetails] = useState<NetworkConnection | null>(null);
  const [selectedDeviceDetails, setSelectedDeviceDetails] = useState<AttachedDevice | null>(null);
  const [selectedAuthEventDetails, setSelectedAuthEventDetails] = useState<AuthEvent | null>(null);
  const [isSniffing, setIsSniffing] = useState(false);
  const [connectionDetailsResponse, setConnectionDetailsResponse] = useState<ConnectionDetailsResponse | null>(null);
  
  // Generate sample metrics
  const generateMetrics = () => {
    const now = new Date();
    let cpu = Math.floor(Math.random() * 40) + 10; // 10-50% CPU usage
    let memory = Math.floor(Math.random() * 30) + 40; // 40-70% memory usage
    const disk = Math.floor(Math.random() * 20) + 30; // 30-50% disk usage
    const network = Math.floor(Math.random() * 60) + 20; // 20-80% network usage
    const temperature = Math.floor(Math.random() * 15) + 45; // 45-60°C
    
    // Occasionally generate spikes
    if (Math.random() > 0.9) {
      cpu += 30; // CPU spike
      if (cpu > 100) cpu = 100;
    }
    
    if (Math.random() > 0.95) {
      memory += 20; // Memory spike
      if (memory > 100) memory = 100;
    }
    
    return {
      timestamp: now,
      cpu,
      memory,
      disk,
      network,
      temperature
    };
  };
  
  // Generate a system event based on metrics
  const generateEvent = (currentMetrics: SystemMetric): SystemEvent | null => {
    // Check for high CPU
    if (currentMetrics.cpu > 80) {
      return {
        id: `event-${Date.now()}-cpu`,
        timestamp: new Date(),
        type: currentMetrics.cpu > 90 ? 'critical' : 'warning',
        message: `High CPU Usage: ${currentMetrics.cpu}%`,
        details: 'System experiencing unusually high CPU load',
        source: 'CPU Monitor'
      };
    }
    
    // Check for high memory
    if (currentMetrics.memory > 85) {
      return {
        id: `event-${Date.now()}-memory`,
        timestamp: new Date(),
        type: currentMetrics.memory > 95 ? 'critical' : 'warning',
        message: `Low Memory: ${100 - currentMetrics.memory}% Free`,
        details: 'System memory resources are running low',
        source: 'Memory Monitor'
      };
    }
    
    // Check for high temperature
    if (currentMetrics.temperature > 58) {
      return {
        id: `event-${Date.now()}-temp`,
        timestamp: new Date(),
        type: currentMetrics.temperature > 65 ? 'critical' : 'warning',
        message: `High CPU Temperature: ${currentMetrics.temperature}°C`,
        details: 'CPU operating above recommended temperature range',
        source: 'Thermal Monitor'
      };
    }
    
    // Random events occasionally
    if (Math.random() > 0.85) {
      const events = [
        {
          type: 'info',
          message: 'System update available',
          details: 'New security patches are available for installation',
          source: 'Update Service'
        },
        {
          type: 'warning',
          message: 'Network anomaly detected',
          details: 'Unusual outbound connection pattern detected',
          source: 'Network Monitor'
        },
        {
          type: 'info',
          message: 'Backup completed',
          details: 'Scheduled system backup completed successfully',
          source: 'Backup Service'
        },
        {
          type: 'info',
          message: 'User login successful',
          details: 'User admin logged in from 192.168.1.5',
          source: 'Authentication Service'
        },
        {
          type: 'warning',
          message: 'Failed login attempt',
          details: 'Multiple failed login attempts for user root from 203.0.113.42',
          source: 'Authentication Service'
        },
        {
          type: 'info',
          message: 'USB device connected',
          details: 'Kingston DataTraveler 32GB connected to /dev/sdb1',
          source: 'Device Manager'
        },
        {
          type: 'warning',
          message: 'File integrity warning',
          details: 'System file /etc/passwd has been modified',
          source: 'File Integrity Monitor'
        }
      ];
      
      const randomEvent = events[Math.floor(Math.random() * events.length)];
      return {
        id: `event-${Date.now()}-random`,
        timestamp: new Date(),
        type: randomEvent.type as 'info' | 'warning' | 'critical',
        message: randomEvent.message,
        details: randomEvent.details,
        source: randomEvent.source
      };
    }
    
    return null;
  };
  
  // Generate sample processes
  const generateProcesses = () => {
    const processList: ProcessInfo[] = [
      {
        pid: 1,
        name: 'systemd',
        cpu: Math.floor(Math.random() * 5),
        memory: Math.floor(Math.random() * 2) + 1,
        disk: 0,
        network: 0,
        user: 'root',
        status: 'running',
        suspicious: false
      },
      {
        pid: 432,
        name: 'sshd',
        cpu: Math.floor(Math.random() * 2),
        memory: Math.floor(Math.random() * 1) + 0.5,
        disk: 0,
        network: Math.floor(Math.random() * 2),
        user: 'root',
        status: 'running',
        suspicious: false
      },
      {
        pid: 845,
        name: 'nginx',
        cpu: Math.floor(Math.random() * 10) + 5,
        memory: Math.floor(Math.random() * 5) + 3,
        disk: Math.floor(Math.random() * 1),
        network: Math.floor(Math.random() * 20) + 10,
        user: 'www-data',
        status: 'running',
        suspicious: false
      },
      {
        pid: 1289,
        name: 'mysql',
        cpu: Math.floor(Math.random() * 15) + 5,
        memory: Math.floor(Math.random() * 20) + 10,
        disk: Math.floor(Math.random() * 10) + 5,
        network: Math.floor(Math.random() * 5),
        user: 'mysql',
        status: 'running',
        suspicious: false
      },
      {
        pid: 2567,
        name: 'java',
        cpu: Math.floor(Math.random() * 25) + 15,
        memory: Math.floor(Math.random() * 30) + 15,
        disk: Math.floor(Math.random() * 5),
        network: Math.floor(Math.random() * 10),
        user: 'tomcat',
        status: 'running',
        suspicious: false
      },
      {
        pid: 3421,
        name: 'python3',
        cpu: Math.floor(Math.random() * 10) + 2,
        memory: Math.floor(Math.random() * 8) + 2,
        disk: Math.floor(Math.random() * 3),
        network: Math.floor(Math.random() * 5),
        user: 'www-data',
        status: 'running',
        suspicious: false
      },
      {
        pid: 4532,
        name: 'node',
        cpu: Math.floor(Math.random() * 12) + 3,
        memory: Math.floor(Math.random() * 15) + 5,
        disk: Math.floor(Math.random() * 2),
        network: Math.floor(Math.random() * 8) + 2,
        user: 'nodejs',
        status: 'running',
        suspicious: false
      },
    ];
    
    // Occasionally add a suspicious process (10% chance)
    if (Math.random() > 0.9) {
      const suspiciousProcesses = [
        {
          name: 'crypto_miner',
          cpu: Math.floor(Math.random() * 40) + 60,
          memory: Math.floor(Math.random() * 10) + 5,
          user: 'unknown'
        },
        {
          name: 'backdoor.sh',
          cpu: Math.floor(Math.random() * 5) + 1,
          memory: Math.floor(Math.random() * 2) + 1,
          user: 'root'
        },
        {
          name: 'data_exfil.py',
          cpu: Math.floor(Math.random() * 10) + 5,
          memory: Math.floor(Math.random() * 5) + 2,
          user: 'www-data'
        }
      ];
      
      const randomSuspicious = suspiciousProcesses[Math.floor(Math.random() * suspiciousProcesses.length)];
      
      processList.push({
        pid: 9000 + Math.floor(Math.random() * 1000),
        name: randomSuspicious.name,
        cpu: randomSuspicious.cpu,
        memory: randomSuspicious.memory,
        disk: Math.floor(Math.random() * 5),
        network: Math.floor(Math.random() * 30) + 10,
        user: randomSuspicious.user,
        status: 'running',
        suspicious: true
      });
      
      // Create an event for the suspicious process
      const newEvent: SystemEvent = {
        id: `event-${Date.now()}-suspicious`,
        timestamp: new Date(),
        type: 'critical',
        message: `Suspicious Process Detected: ${randomSuspicious.name}`,
        details: `Process running as ${randomSuspicious.user} with high resource usage`,
        source: 'Process Monitor'
      };
      
      setEvents(prev => [newEvent, ...prev]);
      
      setThreatScore(prev => Math.min(100, prev + 15));
      
      toast({
        title: "Suspicious Process Detected",
        description: `Process ${randomSuspicious.name} is showing unusual behavior`,
        variant: "destructive"
      });
    }
    
    return processList;
  };

  // Generate network connections
  const generateNetworkConnections = () => {
    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'];
    const states = ['ESTABLISHED', 'TIME_WAIT', 'LISTEN', 'CLOSE_WAIT', 'SYN_SENT'];
    const localIps = ['127.0.0.1', '192.168.1.5', '10.0.0.5', '172.16.0.10'];
    const remoteHosts = [
      { ip: '142.250.180.78', country: 'United States', city: 'Mountain View', risk: 'info', score: 5 }, // Google
      { ip: '157.240.22.35', country: 'United States', city: 'Menlo Park', risk: 'info', score: 5 }, // Facebook
      { ip: '104.18.21.226', country: 'United States', city: 'San Francisco', risk: 'low', score: 12 }, // Cloudflare
      { ip: '18.65.48.72', country: 'United States', city: 'Seattle', risk: 'low', score: 15 }, // AWS
      { ip: '13.107.42.16', country: 'United States', city: 'Redmond', risk: 'info', score: 8 }, // Microsoft
      { ip: '185.199.108.153', country: 'United States', city: 'San Francisco', risk: 'info', score: 5 }, // GitHub
      { ip: '61.149.248.42', country: 'China', city: 'Beijing', risk: 'medium', score: 45 }, // China IP
      { ip: '195.54.160.149', country: 'Russia', city: 'Moscow', risk: 'medium', score: 40 }, // Russia IP
      { ip: '91.108.56.100', country: 'United Arab Emirates', city: 'Dubai', risk: 'low', score: 20 }, // Telegram
    ];
    
    const connections: NetworkConnection[] = [];
    
    // Generate 5-15 connections
    const numConnections = Math.floor(Math.random() * 10) + 5;
    
    for (let i = 0; i < numConnections; i++) {
      const protocol = protocols[Math.floor(Math.random() * protocols.length)];
      const state = states[Math.floor(Math.random() * states.length)];
      const localIp = localIps[Math.floor(Math.random() * localIps.length)];
      const remoteHost = remoteHosts[Math.floor(Math.random() * remoteHosts.length)];
      const port = Math.floor(Math.random() * 60000) + 1024;
      const processIndex = Math.floor(Math.random() * processes.length);
      
      connections.push({
        id: `conn-${Date.now()}-${i}`,
        localIp: localIp,
        remoteIp: remoteHost.ip,
        port: port,
        protocol: protocol,
        state: state,
        process: processes[processIndex].name,
        pid: processes[processIndex].pid,
        country: remoteHost.country,
        city: remoteHost.city,
        riskLevel: remoteHost.risk as 'critical' | 'high' | 'medium' | 'low' | 'info',
        riskScore: remoteHost.score,
        isBlocked: false
      });
    }
    
    // Occasionally add a suspicious connection (10% chance)
    if (Math.random() > 0.9) {
      const suspiciousIps = [
        { ip: '185.176.43.87', country: 'Russia', city: 'Moscow', risk: 'high', score: 75 },
        { ip: '103.41.177.8', country: 'China', city: 'Beijing', risk: 'critical', score: 90 },
        { ip: '94.232.47.163', country: 'Romania', city: 'Bucharest', risk: 'high', score: 65 },
      ];
      
      const randomSuspicious = suspiciousIps[Math.floor(Math.random() * suspiciousIps.length)];
      const isCritical = randomSuspicious.risk === 'critical';
      
      connections.push({
        id: `conn-${Date.now()}-suspicious`,
        localIp: '192.168.1.5',
        remoteIp: randomSuspicious.ip,
        port: 443,
        protocol: 'TCP',
        state: 'ESTABLISHED',
        process: 'unknown',
        pid: 9999,
        country: randomSuspicious.country,
        city: randomSuspicious.city,
        riskLevel: randomSuspicious.risk as 'critical' | 'high' | 'medium' | 'low' | 'info',
        riskScore: randomSuspicious.score,
        isBlocked: isCritical // Auto-block if critical
      });
      
      // Create an event for the suspicious connection
      const newEvent: SystemEvent = {
        id: `event-${Date.now()}-suspicious-conn`,
        timestamp: new Date(),
        type: 'critical',
        message: `${isCritical ? 'Critical' : 'Suspicious'} Connection Detected: ${randomSuspicious.ip}`,
        details: `Connection to suspicious IP in ${randomSuspicious.country} ${isCritical ? 'automatically blocked' : 'established'}`,
        source: 'Network Monitor'
      };
      
      setEvents(prev => [newEvent, ...prev]);
      setThreatScore(prev => Math.min(100, prev + 20));
      
      toast({
        title: `${isCritical ? 'Critical Connection Blocked' : 'Suspicious Connection Detected'}`,
        description: `Connection to ${randomSuspicious.ip} (${randomSuspicious.country}) ${isCritical ? 'has been automatically blocked' : 'detected'}`,
        variant: "destructive"
      });
    }
    
    return connections;
  };

  // Generate authentication events
  const generateAuthEvents = () => {
    const users = ['admin', 'root', 'user', 'www-data', 'guest', 'backup'];
    const methods = ['password', 'ssh-key', 'oauth', 'kerberos'];
    const sourceIps = ['192.168.1.5', '192.168.1.10', '10.0.0.1', '127.0.0.1'];
    
    const events: AuthEvent[] = [];
    
    // Generate 2-4 auth events
    const numEvents = Math.floor(Math.random() * 3) + 2;
    
    for (let i = 0; i < numEvents; i++) {
      const user = users[Math.floor(Math.random() * users.length)];
      const method = methods[Math.floor(Math.random() * methods.length)];
      const sourceIp = sourceIps[Math.floor(Math.random() * sourceIps.length)];
      const status = Math.random() > 0.2 ? 'success' : 'failure';
      
      events.push({
        id: `auth-${Date.now()}-${i}`,
        timestamp: new Date(),
        username: user,
        sourceIp: sourceIp,
        status: status,
        method: method,
        suspicious: false
      });
    }
    
    // Occasionally add a suspicious auth event (8% chance)
    if (Math.random() > 0.92) {
      const suspiciousIp = '203.0.113.42'; // External IP
      const adminUser = Math.random() > 0.5 ? 'root' : 'admin';
      const oddHour = new Date().getHours() >= 1 && new Date().getHours() <= 5;
      
      events.push({
        id: `auth-${Date.now()}-suspicious`,
        timestamp: new Date(),
        username: adminUser,
        sourceIp: suspiciousIp,
        status: Math.random() > 0.7 ? 'success' : 'failure',
        method: 'password',
        suspicious: true
      });
      
      if (oddHour) {
        // Create an event for the suspicious auth at odd hours
        const newEvent: SystemEvent = {
          id: `event-${Date.now()}-suspicious-auth`,
          timestamp: new Date(),
          type: 'critical',
          message: `Unusual Authentication Time: ${adminUser}`,
          details: `${adminUser} account accessed during non-business hours from ${suspiciousIp}`,
          source: 'Authentication Monitor'
        };
        
        setEvents(prev => [newEvent, ...prev]);
        setThreatScore(prev => Math.min(100, prev + 25));
        
        toast({
          title: "Unusual Authentication Detected",
          description: `${adminUser} login at unusual hours from external IP`,
          variant: "destructive"
        });
      }
    }
    
    return events;
  };

  // Generate attached devices
  const generateDevices = () => {
    const deviceList: AttachedDevice[] = [
      {
        id: 'dev-001',
        name: 'Kingston DataTraveler',
        type: 'USB Storage',
        path: '/dev/sdb1',
        connectedAt: new Date(Date.now() - 3 * 60 * 60 * 1000),
        isNew: false,
        isBlocked: false
      },
      {
        id: 'dev-002',
        name: 'DELL USB Keyboard',
        type: 'USB HID',
        path: '/dev/usb4',
        connectedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // 15 days
        isNew: false,
        isBlocked: false
      },
      {
        id: 'dev-003',
        name: 'Logitech Wireless Mouse',
        type: 'USB HID',
        path: '/dev/usb5',
        connectedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // 15 days
        isNew: false,
        isBlocked: false
      },
    ];
    
    // Occasionally add a new device (5% chance)
    if (Math.random() > 0.95) {
      const newDevices = [
        {
          name: 'SanDisk Ultra',
          type: 'USB Storage',
          path: '/dev/sdc1',
        },
        {
          name: 'Unknown USB Device',
          type: 'USB Generic',
          path: '/dev/usb8',
        },
        {
          name: 'ADATA External HDD',
          type: 'USB Storage',
          path: '/dev/sdd1',
        }
      ];
      
      const randomDevice = newDevices[Math.floor(Math.random() * newDevices.length)];
      
      const newDevice: AttachedDevice = {
        id: `dev-${Date.now()}`,
        name: randomDevice.name,
        type: randomDevice.type,
        path: randomDevice.path,
        connectedAt: new Date(),
        isNew: true,
        isBlocked: false
      };
      
      deviceList.push(newDevice);
      
      // Create an event for the new device
      const newEvent: SystemEvent = {
        id: `event-${Date.now()}-new-device`,
        timestamp: new Date(),
        type: 'warning',
        message: `New Device Connected: ${randomDevice.name}`,
        details: `${randomDevice.type} connected at ${randomDevice.path}`,
        source: 'Device Manager'
      };
      
      setEvents(prev => [newEvent, ...prev]);
      
      toast({
        title: "New Device Detected",
        description: `${randomDevice.name} has been connected to the system`,
        variant: "warning"
      });
    }
    
    return deviceList;
  };
  
  // Format metrics for chart display
  const formatMetricsForChart = (metricsData: SystemMetric[]) => {
    return metricsData.map(metric => ({
      time: metric.timestamp.toLocaleTimeString(),
      cpu: metric.cpu,
      memory: metric.memory,
      disk: metric.disk,
      network: metric.network,
      temperature: metric.temperature,
    }));
  };

  // Export data to CSV
  const exportToCSV = (data: any[], filename: string) => {
    const replacer = (_key: string, value: any) => value === null ? '' : value;
    const header = Object.keys(data[0]);
    let csv = data.map(row => header.map(fieldName => JSON.stringify(row[fieldName], replacer)).join(','));
    csv.unshift(header.join(','));
    const csvArray = csv.join('\r\n');

    const blob = new Blob([csvArray], { type: 'text/csv' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${filename}-${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
    
    toast({
      title: "Export Successful",
      description: `${filename} data has been exported to CSV`,
    });
  };

  // Export data to JSON
  const exportToJSON = (data: any[], filename: string) => {
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${filename}-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    
    toast({
      title: "Export Successful",
      description: `${filename} data has been exported to JSON`,
    });
  }
}

export default AdvancedSystemMonitoring