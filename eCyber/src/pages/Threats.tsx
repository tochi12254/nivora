import React from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ArrowRight, AlertOctagon, Shield } from 'lucide-react';
import Header from '../components/layout/Header';
import ThreatVisualization from '../components/threats/ThreatVisualization';
import ThreatFeedsInteractive from '../components/threats/ThreatFeedsInteractive';

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
  },
  {
    id: 4,
    name: "NexusVault Backdoor",
    severity: "critical",
    type: "Backdoor",
    details: "Sophisticated backdoor with kernel-level access",
    affectedSystems: ["Windows", "Linux"],
    timestamp: new Date(Date.now() - 180 * 60 * 1000),
    detectionCount: 5
  },
  {
    id: 5,
    name: "PhantomScript Malware",
    severity: "warning",
    type: "Malware",
    details: "Fileless malware targeting financial institutions",
    affectedSystems: ["Windows Server", "Oracle DB"],
    timestamp: new Date(Date.now() - 340 * 60 * 1000),
    detectionCount: 12
  },
];

// Threat intelligence feeds
const threatFeeds = [
  { name: "MITRE ATT&CK", status: "active", entries: 4231, lastUpdated: "2 hours ago" },
  { name: "OSINT Feed", status: "active", entries: 1872, lastUpdated: "4 hours ago" },
  { name: "Threat Intel", status: "warning", entries: 942, lastUpdated: "3 days ago" },
  { name: "CVE Database", status: "active", entries: 12543, lastUpdated: "1 hour ago" },
];

const Threats = () => {
  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-7xl mx-auto">
          {/* Page header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Threat Intelligence</h1>
              <p className="text-muted-foreground">Track and respond to emerging security threats</p>
            </div>
            
            <div className="mt-4 md:mt-0 text-xs text-muted-foreground">
              Last updated: {new Date().toLocaleTimeString()}
            </div>
          </div>
          
          {/* Emerging threats section */}
          <Card className="mb-6 border-red-500/20 shadow-lg">
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
          
          {/* Threat analysis and feeds section */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="md:col-span-2">
              <ThreatVisualization />
            </div>
            
            <div>
              <ThreatFeedsInteractive />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Threats;
