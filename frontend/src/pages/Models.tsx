
import React from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Cpu, BarChart, PlayCircle, ArrowRight, Zap } from 'lucide-react';
import Header from '../components/layout/Header';
import AIAssistant from '../components/common/AIAssistant';

// Sample models data
const mlModels = [
  {
    id: 1,
    name: "Anomaly Detection",
    status: "active",
    accuracy: 94,
    lastTrained: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
    description: "Detects unusual patterns in network traffic using a neural network",
    type: "Neural Network"
  },
  {
    id: 2,
    name: "Malware Classification",
    status: "active",
    accuracy: 97,
    lastTrained: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
    description: "Classifies potential malware based on behavior patterns",
    type: "Random Forest"
  },
  {
    id: 3,
    name: "User Behavior Analysis",
    status: "training",
    accuracy: 89,
    lastTrained: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000),
    description: "Profiles user behavior to detect account compromises",
    type: "LSTM"
  },
  {
    id: 4,
    name: "Log Anomaly Detection",
    status: "inactive",
    accuracy: 82,
    lastTrained: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    description: "Uses NLP to detect anomalies in log files",
    type: "Transformer"
  },
];

// Sample model insights
const modelInsights = [
  { metric: "Threats detected", value: 28, trend: "up", change: "12%" },
  { metric: "False positives", value: 3, trend: "down", change: "8%" },
  { metric: "Processing time", value: "1.2s", trend: "down", change: "5%" },
  { metric: "Model accuracy", value: "94%", trend: "up", change: "2%" },
];

const Models = () => {
  return (
    <div className="flex h-screen bg-background">
      
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        
        <main className="flex-1 overflow-auto p-6">
          <div className="max-w-7xl mx-auto">
            {/* Page header */}
            <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
              <div>
                <h1 className="text-2xl font-bold tracking-tight">ML & AI Models</h1>
                <p className="text-muted-foreground">Manage and train AI security models</p>
              </div>
              
              <div className="mt-4 md:mt-0 text-xs text-muted-foreground">
                Last updated: {new Date().toLocaleTimeString()}
              </div>
            </div>
            
            {/* Model insights */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              {modelInsights.map((insight, index) => (
                <Card key={index}>
                  <CardContent className="p-6">
                    <div className="text-muted-foreground text-sm">{insight.metric}</div>
                    <div className="text-2xl font-semibold mt-1">{insight.value}</div>
                    <div className={cn(
                      "text-xs flex items-center mt-2",
                      insight.trend === "up" ? "text-green-500" : "text-blue-500"
                    )}>
                      <span className={cn(
                        "mr-1 text-xs",
                        insight.trend === "up" ? "text-green-500" : "text-blue-500"
                      )}>
                        {insight.trend === "up" ? "↑" : "↓"}
                      </span>
                      {insight.change} from last month
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
            
            {/* Models list */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <div className="flex items-center">
                    <Cpu className="mr-2" size={18} />
                    ML Models
                  </div>
                  <Button>
                    <Zap className="mr-2 h-4 w-4" />
                    Train New Model
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="divide-y divide-border">
                  {mlModels.map((model) => (
                    <div key={model.id} className="py-4 first:pt-0 last:pb-0">
                      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
                        <div>
                          <div className="flex items-center">
                            <h3 className="font-medium">{model.name}</h3>
                            <Badge className={cn(
                              "ml-2",
                              model.status === "active" ? "bg-green-500/10 text-green-500" : 
                              model.status === "training" ? "bg-blue-500/10 text-blue-500" :
                              "bg-muted text-muted-foreground"
                            )}>
                              {model.status}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">{model.description}</p>
                          <div className="flex items-center mt-2 text-xs text-muted-foreground">
                            <span className="mr-4">Type: {model.type}</span>
                            <span>Last trained: {model.lastTrained.toLocaleDateString()}</span>
                          </div>
                        </div>
                        
                        <div className="mt-4 md:mt-0">
                          <div className="flex items-center">
                            <div className="text-right mr-4">
                              <div className="text-sm">Accuracy</div>
                              <div className="font-medium">{model.accuracy}%</div>
                            </div>
                            <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                              <div 
                                className={cn(
                                  "h-full rounded-full",
                                  model.accuracy > 95 ? "bg-green-500" :
                                  model.accuracy > 90 ? "bg-blue-500" :
                                  model.accuracy > 85 ? "bg-amber-500" : "bg-red-500"
                                )} 
                                style={{ width: `${model.accuracy}%` }}
                              ></div>
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2 mt-4 md:mt-0">
                          <Button variant="outline" size="sm" disabled={model.status !== "active"}>
                            <BarChart className="mr-1 h-4 w-4" />
                            View Metrics
                          </Button>
                          <Button variant="outline" size="sm" disabled={model.status === "training"}>
                            <PlayCircle className="mr-1 h-4 w-4" />
                            Run
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" size="sm" className="ml-auto">
                  View All Models <ArrowRight className="ml-1" size={12} />
                </Button>
              </CardFooter>
            </Card>
          </div>
        </main>
      </div>
      
      <AIAssistant />
    </div>
  );
};

export default Models;
