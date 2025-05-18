
import React, { useState, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Cpu, BarChart, PlayCircle, ArrowRight, Zap, StopCircle, RefreshCw, Check, AlertCircle } from 'lucide-react';
import Header from '../components/layout/Header';
import ModelTraining from '../components/models/ModelTraining';
import ModelMetrics from '../components/models/ModelMetrics';
import ModelFilters from '../components/models/ModelFilters';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";

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
  const [activeModel, setActiveModel] = useState<typeof mlModels[0] | null>(null);
  const [runningModels, setRunningModels] = useState<Record<number, {progress: number, running: boolean}>>({});
  const [showAllMetrics, setShowAllMetrics] = useState(false);
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>(['active', 'training', 'inactive']);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const { toast } = useToast();
  
  // Filter models based on search term and status
  const filteredModels = mlModels.filter(model => {
    const matchesSearch = 
      model.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      model.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      model.type.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesStatus = selectedStatuses.includes(model.status);
    
    return matchesSearch && matchesStatus;
  });
  
  // Sort models based on selected sort option
  const sortedModels = [...filteredModels].sort((a, b) => {
    switch(sortBy) {
      case 'accuracy-high':
        return b.accuracy - a.accuracy;
      case 'accuracy-low':
        return a.accuracy - b.accuracy;
      case 'name-asc':
        return a.name.localeCompare(b.name);
      case 'name-desc':
        return b.name.localeCompare(a.name);
      case 'recent':
        return new Date(b.lastTrained).getTime() - new Date(a.lastTrained).getTime();
      default:
        return 0;
    }
  });
  
  const handleRunModel = (model: typeof mlModels[0]) => {
    if (model.status === "training") {
      toast({
        title: "Model Unavailable",
        description: "This model is currently training and cannot be run",
        variant: "destructive",
      });
      return;
    }
    
    toast({
      title: "Running Model",
      description: `Executing ${model.name} on current data`,
    });
    
    // Set up running state for this model
    setRunningModels(prev => ({
      ...prev,
      [model.id]: { progress: 0, running: true }
    }));
    
    // Simulate progress
    const intervalId = setInterval(() => {
      setRunningModels(prev => {
        const currentProgress = prev[model.id]?.progress || 0;
        
        if (currentProgress >= 100) {
          clearInterval(intervalId);
          
          // Show completion toast
          toast({
            title: "Model Execution Complete",
            description: `${model.name} analysis completed successfully`,
          });
          
          return {
            ...prev,
            [model.id]: { progress: 100, running: false }
          };
        }
        
        return {
          ...prev,
          [model.id]: { progress: Math.min(currentProgress + 10, 100), running: true }
        };
      });
    }, 300);
  };
  
  const handleStopModel = (model: typeof mlModels[0]) => {
    toast({
      title: "Model Stopped",
      description: `${model.name} execution has been stopped`,
    });
    
    setRunningModels(prev => ({
      ...prev,
      [model.id]: { progress: prev[model.id]?.progress || 0, running: false }
    }));
  };
  
  const handleRefreshModels = () => {
    toast({
      title: "Refreshing Models",
      description: "Updating model status and metrics...",
    });
    
    // Simulate refresh by updating the key to force re-render
    setRefreshKey(prev => prev + 1);
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
    
      
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-7xl mx-auto">
          {/* Page header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">ML & AI Models</h1>
              <p className="text-muted-foreground">Manage and train AI security models</p>
            </div>
            
            <div className="flex items-center gap-2 mt-4 md:mt-0">
              <div className="text-xs text-muted-foreground flex items-center">
                <span className="mr-1">Last updated:</span>
                <span className="bg-muted/50 px-2 py-1 rounded text-xs">{new Date().toLocaleTimeString()}</span>
              </div>
              <Button 
                variant="outline" 
                size="sm"
                onClick={handleRefreshModels}
                className="ml-2 hover:bg-primary/10" 
              >
                <RefreshCw className="mr-1 h-4 w-4" />
                Refresh
              </Button>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={() => setShowAllMetrics(!showAllMetrics)}
                className={cn(
                  "ml-2",
                  showAllMetrics ? "bg-primary/10 text-primary" : ""
                )}
              >
                {showAllMetrics ? "Hide All Metrics" : "Show All Metrics"}
              </Button>
            </div>
          </div>
          
          {/* Model filters */}
          <ModelFilters 
            onSearch={setSearchTerm}
            onFilterChange={setSortBy}
            onStatusChange={setSelectedStatuses}
            selectedStatuses={selectedStatuses}
          />
          
          {/* Model insights */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            {modelInsights.map((insight, index) => (
              <Card 
                key={index} 
                className="bg-card/70 backdrop-blur-sm card-hover-subtle animate-fade-in-up"
                style={{ animationDelay: `${index * 0.1}s` }}
              >
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
          
          {/* Show All Metrics section conditionally */}
          {showAllMetrics && (
            <div className="mb-6 animate-fade-in-up">
              <Card className="bg-card/70 backdrop-blur-sm card-shine">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <BarChart className="mr-2" size={18} />
                    All Model Metrics
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {mlModels.map((model, index) => (
                      <div 
                        key={model.id} 
                        className="border border-border rounded-xl p-6 bg-gradient-to-br from-card to-muted/5 card-hover animate-fade-in-up"
                        style={{ animationDelay: `${index * 0.15}s` }}
                      >
                        <h3 className="font-medium flex items-center">
                          <Cpu className="h-4 w-4 mr-2 text-primary" />
                          {model.name} Metrics
                        </h3>
                        <div className="mt-2 mb-4">
                          <Badge className={cn(
                            "status-badge",
                            model.status === "active" ? "active" : 
                            model.status === "training" ? "training" : 
                            "inactive"
                          )}>
                            {model.status}
                          </Badge>
                          <span className="ml-2 text-xs text-muted-foreground">Type: {model.type}</span>
                        </div>
                        <ModelMetrics modelName={model.name} modelType={model.type} />
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
          
          {/* Model Training */}
          <div className="mb-6">
            <ModelTraining />
          </div>
          
          {/* Models list */}
          <Card className="bg-card/70 backdrop-blur-sm card-shine">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center">
                  <Cpu className="mr-2" size={18} />
                  ML Models
                  <Badge className="ml-2 bg-primary/20 text-primary">{sortedModels.length}</Badge>
                </div>
                <Dialog>
                  <DialogTrigger asChild>
                    <Button className="bg-primary/10 hover:bg-primary/20">
                      <Zap className="mr-2 h-4 w-4" />
                      View All Models
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-3xl">
                    <DialogHeader>
                      <DialogTitle>Available Models</DialogTitle>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                      {mlModels.map((model) => (
                        <div key={model.id} className="flex items-center justify-between p-4 border border-border rounded-md bg-card/70 hover:bg-card/90 transition-all card-hover">
                          <div>
                            <h3 className="font-medium">{model.name}</h3>
                            <p className="text-sm text-muted-foreground">{model.description}</p>
                            <div className="flex items-center mt-2">
                              <Badge className={cn(
                                "status-badge",
                                model.status === "active" ? "active" : 
                                model.status === "training" ? "training" : 
                                "inactive"
                              )}>
                                {model.status}
                              </Badge>
                              <span className="mx-2 text-muted-foreground text-xs">•</span>
                              <span className="text-xs text-muted-foreground">Type: {model.type}</span>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <Button 
                              variant="outline" 
                              size="sm" 
                              disabled={model.status === "training"}
                              onClick={() => handleRunModel(model)}
                            >
                              <PlayCircle className="mr-1 h-4 w-4" />
                              Run
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </DialogContent>
                </Dialog>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {sortedModels.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <AlertCircle className="h-12 w-12 text-muted-foreground mb-3" />
                  <h3 className="font-medium text-lg mb-1">No models match your filters</h3>
                  <p className="text-muted-foreground">Try adjusting your search criteria or filters</p>
                  <Button variant="outline" className="mt-4" onClick={() => {
                    setSearchTerm('');
                    setSelectedStatuses(['active', 'training', 'inactive']);
                    setSortBy('');
                  }}>
                    Reset Filters
                  </Button>
                </div>
              ) : (
                <div className="divide-y divide-border">
                  {sortedModels.map((model, index) => (
                    <div 
                      key={model.id} 
                      className="py-4 first:pt-0 last:pb-0 animate-fade-in-up"
                      style={{ animationDelay: `${index * 0.1}s` }}
                    >
                      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
                        <div>
                          <div className="flex items-center">
                            <h3 className="font-medium">{model.name}</h3>
                            <Badge className={cn(
                              "ml-2",
                              "status-badge",
                              model.status === "active" ? "active" : 
                              model.status === "training" ? "training" : 
                              "inactive"
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
                        
                        <div className="flex flex-col space-y-2 mt-4 md:mt-0 md:flex-row md:space-y-0 md:space-x-2">
                          <Dialog>
                            <DialogTrigger asChild>
                              <Button variant="outline" size="sm" disabled={model.status !== "active"}>
                                <BarChart className="mr-1 h-4 w-4" />
                                View Metrics
                              </Button>
                            </DialogTrigger>
                            <DialogContent className="max-w-3xl">
                              <DialogHeader>
                                <DialogTitle>{model.name} Metrics</DialogTitle>
                              </DialogHeader>
                              <ModelMetrics modelName={model.name} modelType={model.type} />
                            </DialogContent>
                          </Dialog>
                          
                          {runningModels[model.id]?.running ? (
                            <div className="flex items-center gap-2">
                              <div className="flex-1 min-w-[120px]">
                                <Progress 
                                  value={runningModels[model.id]?.progress || 0} 
                                  className="h-2"
                                />
                                <div className="text-xs text-muted-foreground mt-1">
                                  {runningModels[model.id]?.progress || 0}% Complete
                                </div>
                              </div>
                              <Button 
                                variant="destructive" 
                                size="sm"
                                onClick={() => handleStopModel(model)}
                              >
                                <StopCircle className="h-4 w-4" />
                              </Button>
                            </div>
                          ) : (
                            <Button 
                              variant="outline" 
                              size="sm" 
                              disabled={model.status === "training" || (runningModels[model.id]?.progress === 100)}
                              onClick={() => handleRunModel(model)}
                              className={cn(
                                runningModels[model.id]?.progress === 100 ? "bg-green-500/10 text-green-500" : ""
                              )}
                            >
                              {runningModels[model.id]?.progress === 100 ? (
                                <>
                                  <Check className="mr-1 h-4 w-4" />
                                  Complete
                                </>
                              ) : (
                                <>
                                  <PlayCircle className="mr-1 h-4 w-4" />
                                  Run
                                </>
                              )}
                            </Button>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Models;
