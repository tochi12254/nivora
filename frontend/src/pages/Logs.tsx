
import React, { useState } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FileBarChart, Search, Filter, ArrowRight, RefreshCw } from 'lucide-react';
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import Header from '../components/layout/Header';
import AIAssistant from '../components/common/AIAssistant';

// Sample logs data
const logEntries = [
  {
    id: "1",
    timestamp: new Date(Date.now() - 3 * 60 * 1000),
    level: "error",
    source: "auth-service",
    message: "Failed login attempt",
    details: "Multiple failed login attempts from IP 185.93.2.41"
  },
  {
    id: "2",
    timestamp: new Date(Date.now() - 15 * 60 * 1000),
    level: "warning",
    source: "firewall",
    message: "Suspicious outbound connection",
    details: "Connection to known malicious IP 103.56.112.8 blocked"
  },
  {
    id: "3",
    timestamp: new Date(Date.now() - 35 * 60 * 1000),
    level: "info",
    source: "update-service",
    message: "System update completed",
    details: "All system components updated to latest version"
  },
  {
    id: "4",
    timestamp: new Date(Date.now() - 47 * 60 * 1000),
    level: "error",
    source: "network-monitor",
    message: "Connection timeout",
    details: "Unable to reach database server after 3 attempts"
  },
  {
    id: "5",
    timestamp: new Date(Date.now() - 120 * 60 * 1000),
    level: "warning",
    source: "user-management",
    message: "User password expired",
    details: "Admin user 'jsmith' needs to update credentials"
  },
  {
    id: "6",
    timestamp: new Date(Date.now() - 145 * 60 * 1000),
    level: "info",
    source: "backup-service",
    message: "Backup completed",
    details: "Daily backup completed successfully. Size: 2.3GB"
  },
  {
    id: "7",
    timestamp: new Date(Date.now() - 180 * 60 * 1000),
    level: "error",
    source: "api-gateway",
    message: "Rate limit exceeded",
    details: "Client 10.0.1.23 exceeded API rate limit"
  },
];

const logSources = [
  "All Sources",
  "auth-service",
  "firewall",
  "update-service",
  "network-monitor",
  "user-management",
  "backup-service",
  "api-gateway"
];

const logLevels = ["All Levels", "error", "warning", "info"];

const Logs = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSource, setSelectedSource] = useState("All Sources");
  const [selectedLevel, setSelectedLevel] = useState("All Levels");
  
  // Filter logs based on search, source, and level
  const filteredLogs = logEntries.filter(log => {
    const matchesSearch = searchQuery === "" || 
      log.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.details.toLowerCase().includes(searchQuery.toLowerCase());
      
    const matchesSource = selectedSource === "All Sources" || log.source === selectedSource;
    const matchesLevel = selectedLevel === "All Levels" || log.level === selectedLevel;
    
    return matchesSearch && matchesSource && matchesLevel;
  });
  
  return (
    <div className="flex h-screen bg-background">
      
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        
        <main className="flex-1 overflow-auto p-6">
          <div className="max-w-7xl mx-auto">
            {/* Page header */}
            <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight">Logs & Analysis</h1>
                <p className="text-muted-foreground">Search and analyze security event logs</p>
              </div>
              
              <div className="mt-4 md:mt-0 text-xs text-muted-foreground">
                Last updated: {new Date().toLocaleTimeString()}
              </div>
            </div>
            
            {/* Search and filters */}
            <Card className="mb-6">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center">
                  <Search className="mr-2" size={18} />
                  Search Logs
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col md:flex-row gap-4">
                  <div className="flex-1">
                    <Input
                      placeholder="Search log messages..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full"
                      icon={<Search className="h-4 w-4" />}
                    />
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <Select value={selectedSource} onValueChange={setSelectedSource}>
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Source" />
                      </SelectTrigger>
                      <SelectContent>
                        {logSources.map((source) => (
                          <SelectItem key={source} value={source}>{source}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    
                    <Select value={selectedLevel} onValueChange={setSelectedLevel}>
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Level" />
                      </SelectTrigger>
                      <SelectContent>
                        {logLevels.map((level) => (
                          <SelectItem key={level} value={level}>{level}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    
                    <Button className="w-full md:w-auto">
                      <Filter className="mr-2 h-4 w-4" />
                      Apply Filters
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            {/* Log entries */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-lg font-medium flex items-center justify-between">
                  <div className="flex items-center">
                    <FileBarChart className="mr-2" size={18} />
                    Log Entries
                  </div>
                  <Button variant="outline" size="sm">
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Refresh
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="rounded-md overflow-hidden border border-border">
                  <div className="grid grid-cols-12 gap-4 p-3 bg-muted text-xs font-medium">
                    <div className="col-span-2">Timestamp</div>
                    <div className="col-span-1">Level</div>
                    <div className="col-span-2">Source</div>
                    <div className="col-span-3">Message</div>
                    <div className="col-span-4">Details</div>
                  </div>
                  
                  <div className="divide-y divide-border max-h-[600px] overflow-auto">
                    {filteredLogs.length > 0 ? (
                      filteredLogs.map((log) => (
                        <div key={log.id} className="grid grid-cols-12 gap-4 p-3 text-xs hover:bg-muted/30">
                          <div className="col-span-2 text-muted-foreground">
                            {log.timestamp.toLocaleTimeString()} <span className="ml-1 text-[10px]">{log.timestamp.toLocaleDateString()}</span>
                          </div>
                          <div className="col-span-1">
                            <Badge variant="outline" className={cn(
                              log.level === "error" ? "bg-red-500/10 text-red-500" : 
                              log.level === "warning" ? "bg-amber-500/10 text-amber-500" : 
                              "bg-blue-500/10 text-blue-500"
                            )}>
                              {log.level.toUpperCase()}
                            </Badge>
                          </div>
                          <div className="col-span-2">
                            {log.source}
                          </div>
                          <div className="col-span-3 font-medium">
                            {log.message}
                          </div>
                          <div className="col-span-4 text-muted-foreground">
                            {log.details}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="p-6 text-center text-muted-foreground">
                        No log entries found matching your filters
                      </div>
                    )}
                  </div>
                </div>
                
                <div className="flex items-center justify-between mt-4">
                  <div className="text-sm text-muted-foreground">
                    Showing {filteredLogs.length} of {logEntries.length} log entries
                  </div>
                  <Button variant="ghost" size="sm">
                    Export Logs <ArrowRight className="ml-1" size={12} />
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
      
      <AIAssistant />
    </div>
  );
};

export default Logs;
