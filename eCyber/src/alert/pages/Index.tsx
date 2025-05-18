
import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import ThreatLevelIndicator from "../components/ThreatLevelIndicator";
import ThreatsCountCard from "../components/ThreatsCountCard";
import SystemHealthCard from "../components/SystemHealthCard";

import RecentAlertsCard from "../components/RecentAlertsCard";
import ThreatDetectionsTable from "../components/ThreatDetectionsTable";
import PhishingDetectionsTable from "../components/PhishingDetectionsTable";
import FirewallEventsTable from "../components/FirewallEventsTable";
import HttpActivityTable from "../components/HttpActivityTable";
import DnsActivityTable from "../components/DnsActivityTable";
import PacketAnalysisTable from "../components/PacketAnalysisTable";
import IPv6ActivityTable from "../components/IPv6ActivityTable";
import ThreatResponseTable from "../components/ThreatResponseTable";
import QuarantinedFilesTable from "../components/QuarantinedFilesTable";
import SecurityHistoryTimeline from "../components/SecurityHistoryTimeline";
import EventHeatMap from "../components/EventHeatMap";
import { Shield, Download, RefreshCcw, AlertCircle, ChevronUp, ChevronDown } from "lucide-react";
import { Button } from "../components/ui/button";
import { useToast } from "../hooks/use-toast";
import { Separator } from "../components/ui/separator";

// Import mock data
import { 
  threatLevelData,
  activeThreatCounts, 
  systemStatusData, 
  recentCriticalAlerts,
  threatDetections,
  phishingDetections,
  firewallEvents,
  httpActivities,
  dnsActivities,
  packetAnalyses,
  ipv6Activities,
  threatResponses,
  quarantinedFiles
} from "../mockData";

const Index = () => {
  const [activeTab, setActiveTab] = useState("threats");
  const [networkActiveTab, setNetworkActiveTab] = useState("http");
  const [automatedResponsesActiveTab, setAutomatedResponsesActiveTab] = useState("responses");
  const [sectionsExpanded, setSectionsExpanded] = useState({
    threatIntelligence: true,
    networkActivity: true,
    automatedResponses: true,
    history: true
  });
  const { toast } = useToast();

  // Combined timeline data for heatmap
  const allTimelineEvents = [
    ...threatDetections.map(t => ({ timestamp: t.timestamp, type: "threat" })),
    ...phishingDetections.map(p => ({ timestamp: p.timestamp, type: "phishing" })),
    ...firewallEvents.map(f => ({ timestamp: f.timestamp, type: "firewall" })),
    ...httpActivities.map(h => ({ timestamp: h.timestamp, type: "http" })),
    ...dnsActivities.map(d => ({ timestamp: d.timestamp, type: "dns" })),
    ...packetAnalyses.map(p => ({ timestamp: p.timestamp, type: "packet" })),
    ...threatResponses.map(r => ({ timestamp: r.timestamp, type: "response" })),
    ...quarantinedFiles.map(q => ({ timestamp: q.timestamp, type: "quarantine" })),
    ...ipv6Activities.map(i => ({ timestamp: i.timestamp, type: "ipv6" }))
  ];

  const toggleSection = (section: keyof typeof sectionsExpanded) => {
    setSectionsExpanded(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };
  
  const handleRefresh = () => {
    toast({
      title: "Dashboard Refreshed",
      description: "Security data has been updated with latest information.",
    });
  };

  const handleExport = () => {
    toast({
      title: "Report Generated",
      description: "Security report has been prepared for download.",
    });
  };

  // Fix for the type error: Ensure the current threat level is a valid ThreatSeverity
  const currentThreatLevel = threatLevelData.current as "Critical" | "High" | "Medium" | "Low";

  return (
    <div className="min-h-screen bg-background p-2 sm:p-4 md:p-8">
      <header className="mb-4 md:mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center mb-2">
            <Shield className="w-6 h-6 sm:w-8 sm:h-8 mr-2 sm:mr-3 text-primary" />
            <h1 className="text-xl sm:text-2xl md:text-3xl font-bold">Monitor alerts in real time</h1>
          </div>
          <p className="text-sm md:text-base text-muted-foreground max-w-3xl">
            All alerts and warnings appear here!
          </p>
        </div>
        <div className="flex items-center gap-2 sm:gap-3 self-end md:self-auto">
          <Button variant="outline" size="sm" className="text-xs sm:text-sm" onClick={handleRefresh}>
            <RefreshCcw className="w-3 h-3 sm:w-4 sm:h-4 mr-1 sm:mr-2" />
            <span className="hidden xs:inline">Refresh</span>
          </Button>
          <Button variant="outline" size="sm" className="text-xs sm:text-sm" onClick={handleExport}>
            <Download className="w-3 h-3 sm:w-4 sm:h-4 mr-1 sm:mr-2" />
            <span className="hidden xs:inline">Export Report</span>
          </Button>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 md:gap-6 mb-6 md:mb-8">
        <Card className="col-span-1 md:col-span-2 lg:col-span-1 transition-all duration-200 hover:shadow-lg">
          <CardHeader className="pb-2 px-3 sm:px-6">
            <CardTitle className="text-base sm:text-lg font-medium">Threat Level</CardTitle>
          </CardHeader>
          <CardContent className="flex justify-center px-3 sm:px-6">
            <ThreatLevelIndicator
              level={currentThreatLevel}
              description={threatLevelData.description}
            />
          </CardContent>
        </Card>

        <ThreatsCountCard threatCounts={activeThreatCounts} className="transition-all duration-200 hover:shadow-lg" />
        <SystemHealthCard systems={systemStatusData} className="md:col-span-2 lg:col-span-1 transition-all duration-200 hover:shadow-lg" />

      </div>

      <div className="mb-6 md:mb-8">
        <RecentAlertsCard alerts={recentCriticalAlerts} className="transition-all duration-200 hover:shadow-lg" />
      </div>

      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold flex items-center">
            <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5 mr-2 text-threat-medium" />
            Threat Intelligence
          </h2>
          <Button 
            variant="ghost" 
            size="sm" 
            className="p-1 h-6 sm:h-8" 
            onClick={() => toggleSection("threatIntelligence")}
          >
            {sectionsExpanded.threatIntelligence ? <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5" /> : <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />}
          </Button>
        </div>
        
        {sectionsExpanded.threatIntelligence && (
          <Tabs defaultValue="threats" value={activeTab} onValueChange={setActiveTab} className="w-full overflow-x-auto">
            <TabsList className="mb-4 w-full justify-start">
              <TabsTrigger value="threats" className="text-xs sm:text-sm">Threat Detections</TabsTrigger>
              <TabsTrigger value="phishing" className="text-xs sm:text-sm">Phishing & URL Analysis</TabsTrigger>
              <TabsTrigger value="firewall" className="text-xs sm:text-sm">Firewall Events</TabsTrigger>
            </TabsList>
            
            <TabsContent value="threats" className="animate-slide-in">
              <div className="overflow-x-auto">
                <ThreatDetectionsTable threats={threatDetections} />
              </div>
            </TabsContent>
            
            <TabsContent value="phishing" className="animate-slide-in">
              <div className="overflow-x-auto">
                <PhishingDetectionsTable detections={phishingDetections} />
              </div>
            </TabsContent>
            
            <TabsContent value="firewall" className="animate-slide-in">
              <div className="space-y-6 overflow-x-auto">
                <FirewallEventsTable events={firewallEvents} />
              </div>
            </TabsContent>
          </Tabs>
        )}
      </div>

      <Separator className="my-4 sm:my-6" />
      
      {/* Network Monitoring Section */}
      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold flex items-center">
            <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5 mr-2 text-primary" />
            Network Activity Monitoring
          </h2>
          <Button 
            variant="ghost" 
            size="sm" 
            className="p-1 h-6 sm:h-8" 
            onClick={() => toggleSection("networkActivity")}
          >
            {sectionsExpanded.networkActivity ? <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5" /> : <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />}
          </Button>
        </div>
        
        {sectionsExpanded.networkActivity && (
          <Tabs defaultValue="http" value={networkActiveTab} onValueChange={setNetworkActiveTab} className="w-full overflow-x-auto">
            <TabsList className="mb-4 w-full justify-start overflow-x-auto flex-nowrap">
              <TabsTrigger value="http" className="text-xs sm:text-sm">HTTP Activity</TabsTrigger>
              <TabsTrigger value="dns" className="text-xs sm:text-sm">DNS Monitoring</TabsTrigger>
              <TabsTrigger value="packets" className="text-xs sm:text-sm">Packet Analysis</TabsTrigger>
              <TabsTrigger value="ipv6" className="text-xs sm:text-sm">IPv6 Activity</TabsTrigger>
            </TabsList>
            
            <TabsContent value="http" className="animate-slide-in">
              <div className="space-y-6 overflow-x-auto">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">HTTP Activity Monitor</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Monitors HTTP requests, analyzes headers, detects injection attempts, and calculates threat scores based on behavioral analysis.
                    </p>
                    <div className="overflow-x-auto">
                      <HttpActivityTable activities={httpActivities} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="dns" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">DNS Activity Monitor</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Tracks DNS queries, identifies potentially malicious domains, detects unusual TTL values, and correlates with threat intelligence feeds.
                    </p>
                    <div className="overflow-x-auto">
                      <DnsActivityTable activities={dnsActivities} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="packets" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">Network Packet Analysis</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Analyzes packets for suspicious characteristics, monitors protocol distributions, and detects network anomalies like port scans.
                    </p>
                    <div className="overflow-x-auto">
                      <PacketAnalysisTable packets={packetAnalyses} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="ipv6" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">IPv6 Traffic Analysis</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Monitors IPv6 traffic patterns, detects baseline deviations, and identifies potential tunneled traffic for evading security controls.
                    </p>
                    <div className="overflow-x-auto">
                      <IPv6ActivityTable activities={ipv6Activities} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        )}
      </div>
      
      <Separator className="my-4 sm:my-6" />

      {/* Automated Responses Section */}
      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold flex items-center">
            <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5 mr-2 text-threat-low" />
            Automated Responses
          </h2>
          <Button 
            variant="ghost" 
            size="sm" 
            className="p-1 h-6 sm:h-8" 
            onClick={() => toggleSection("automatedResponses")}
          >
            {sectionsExpanded.automatedResponses ? <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5" /> : <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />}
          </Button>
        </div>
        
        {sectionsExpanded.automatedResponses && (
          <Tabs defaultValue="responses" value={automatedResponsesActiveTab} onValueChange={setAutomatedResponsesActiveTab} className="w-full overflow-x-auto">
            <TabsList className="mb-4 w-full justify-start">
              <TabsTrigger value="responses" className="text-xs sm:text-sm">Threat Responses</TabsTrigger>
              <TabsTrigger value="quarantined" className="text-xs sm:text-sm">Quarantined Files</TabsTrigger>
            </TabsList>
            
            <TabsContent value="responses" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">Security Response Actions</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Records of automated security actions taken in response to detected threats, including IP blocks, process termination, and more.
                    </p>
                    <div className="overflow-x-auto">
                      <ThreatResponseTable responses={threatResponses} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="quarantined" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">Quarantined Files</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Files automatically quarantined due to detection of malicious content, suspicious behavior, or unauthorized modifications.
                    </p>
                    <div className="overflow-x-auto">
                      <QuarantinedFilesTable files={quarantinedFiles} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        )}
      </div>
      
      <Separator className="my-4 sm:my-6" />

      {/* Historical & Trends View */}
      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold flex items-center">
            <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5 mr-2 text-primary" />
            Security History & Trends
          </h2>
          <Button 
            variant="ghost" 
            size="sm" 
            className="p-1 h-6 sm:h-8" 
            onClick={() => toggleSection("history")}
          >
            {sectionsExpanded.history ? <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5" /> : <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />}
          </Button>
        </div>
        
        {sectionsExpanded.history && (
          <div className="grid grid-cols-1 gap-4 md:gap-6">
            <SecurityHistoryTimeline 
              threats={threatDetections}
              phishing={phishingDetections}
              firewall={firewallEvents}
              http={httpActivities}
              dns={dnsActivities}
              packets={packetAnalyses}
              responses={threatResponses}
              quarantined={quarantinedFiles}
              ipv6={ipv6Activities}
              className="transition-all duration-200 hover:shadow-lg"
            />
            
            <EventHeatMap data={allTimelineEvents} className="transition-all duration-200 hover:shadow-lg" />
          </div>
        )}
      </div>
      
    </div>
  );
};

export default Index;
