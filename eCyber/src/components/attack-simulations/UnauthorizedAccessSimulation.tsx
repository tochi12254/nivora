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
