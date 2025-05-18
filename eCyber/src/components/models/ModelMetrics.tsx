
import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { BarChart2, LineChart, PieChart, Activity, Download } from 'lucide-react';
import { Button } from "@/components/ui/button";

const ModelMetrics = ({ modelName, modelType }: { modelName: string; modelType: string }) => {
  const [metricView, setMetricView] = useState('performance');

  const renderMetricContent = () => {
    switch(metricView) {
      case 'performance':
        return <PerformanceMetrics />;
      case 'confusion':
        return <ConfusionMatrix />;
      case 'roc':
        return <ROCCurve />;
      case 'feature':
        return <FeatureImportance />;
      default:
        return <PerformanceMetrics />;
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center justify-between">
          <div className="flex items-center">
            <Activity className="mr-2" size={16} />
            {modelName} Metrics
          </div>
          <Button variant="outline" size="sm">
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue={metricView} onValueChange={setMetricView}>
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="performance">Performance</TabsTrigger>
            <TabsTrigger value="confusion">Confusion Matrix</TabsTrigger>
            <TabsTrigger value="roc">ROC Curve</TabsTrigger>
            <TabsTrigger value="feature">Feature Importance</TabsTrigger>
          </TabsList>
          <TabsContent value={metricView} className="mt-4">
            {renderMetricContent()}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

const PerformanceMetrics = () => {
  return (
    <div className="space-y-6">
      {/* Accuracy over time */}
      <div>
        <h3 className="text-sm font-medium mb-2">Accuracy & Loss Over Time</h3>
        <div className="border border-border rounded-md p-4 h-60">
          <div className="h-full relative">
            {/* X axis */}
            <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-border"></div>
            {/* X axis labels */}
            <div className="absolute bottom-[-20px] left-0 right-0 flex justify-between text-xs text-muted-foreground">
              <span>0</span>
              <span>20</span>
              <span>40</span>
              <span>60</span>
              <span>80</span>
              <span>100</span>
            </div>
            {/* Y axis */}
            <div className="absolute top-0 bottom-0 left-0 w-[1px] bg-border"></div>
            {/* Y axis labels */}
            <div className="absolute top-0 bottom-0 left-[-25px] flex flex-col justify-between text-xs text-muted-foreground">
              <span>100%</span>
              <span>75%</span>
              <span>50%</span>
              <span>25%</span>
              <span>0%</span>
            </div>
            
            {/* Accuracy line */}
            <svg className="absolute inset-0 h-full w-full overflow-visible" preserveAspectRatio="none">
              <polyline
                points="0,200 20,150 40,120 60,80 80,60 100,40 120,35 140,30 160,28 180,25 200,20"
                fill="none"
                stroke="#3b82f6"
                strokeWidth="2"
                className="accuracy-line"
                style={{ vectorEffect: 'non-scaling-stroke' }}
              />
            </svg>
            
            {/* Loss line */}
            <svg className="absolute inset-0 h-full w-full overflow-visible" preserveAspectRatio="none">
              <polyline
                points="0,50 20,70 40,90 60,100 80,105 100,110 120,115 140,116 160,118 180,118 200,119"
                fill="none"
                stroke="#ef4444"
                strokeWidth="2"
                className="loss-line"
                style={{ vectorEffect: 'non-scaling-stroke' }}
              />
            </svg>
            
            {/* Legend */}
            <div className="absolute top-2 right-2 flex items-center space-x-4 bg-background/80 backdrop-blur-sm p-1 rounded-md text-xs">
              <div className="flex items-center">
                <div className="w-2 h-2 bg-blue-500 mr-1"></div>
                <span>Accuracy</span>
              </div>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-red-500 mr-1"></div>
                <span>Loss</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {/* Key metrics */}
      <div className="grid grid-cols-2 gap-4">
        <div className="p-4 border border-border rounded-md">
          <div className="text-sm text-muted-foreground mb-1">Accuracy</div>
          <div className="text-2xl font-semibold">94.7%</div>
          <div className="flex items-center text-xs text-green-500 mt-1">
            <span className="mr-1">↑</span>
            2.3% from previous version
          </div>
        </div>
        
        <div className="p-4 border border-border rounded-md">
          <div className="text-sm text-muted-foreground mb-1">F1 Score</div>
          <div className="text-2xl font-semibold">0.923</div>
          <div className="flex items-center text-xs text-green-500 mt-1">
            <span className="mr-1">↑</span>
            0.05 from previous version
          </div>
        </div>
        
        <div className="p-4 border border-border rounded-md">
          <div className="text-sm text-muted-foreground mb-1">Precision</div>
          <div className="text-2xl font-semibold">0.918</div>
          <div className="flex items-center text-xs text-amber-500 mt-1">
            <span className="mr-1">↓</span>
            0.02 from previous version
          </div>
        </div>
        
        <div className="p-4 border border-border rounded-md">
          <div className="text-sm text-muted-foreground mb-1">Recall</div>
          <div className="text-2xl font-semibold">0.932</div>
          <div className="flex items-center text-xs text-green-500 mt-1">
            <span className="mr-1">↑</span>
            0.08 from previous version
          </div>
        </div>
      </div>
    </div>
  );
};

const ConfusionMatrix = () => {
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium">Confusion Matrix</h3>
      
      <div className="border border-border rounded-md p-4 flex justify-center">
        <div className="relative">
          {/* Matrix */}
          <div className="grid grid-cols-4 gap-1">
            {/* Header row */}
            <div className="h-10"></div> {/* Empty top-left cell */}
            <div className="h-10 bg-muted flex items-center justify-center font-medium">Normal</div>
            <div className="h-10 bg-muted flex items-center justify-center font-medium">Suspicious</div>
            <div className="h-10 bg-muted flex items-center justify-center font-medium">Malicious</div>
            
            {/* Normal row */}
            <div className="h-16 bg-muted flex items-center justify-center font-medium">Normal</div>
            <div className="h-16 bg-green-500/20 flex items-center justify-center text-lg font-bold">243</div>
            <div className="h-16 bg-red-500/10 flex items-center justify-center text-lg font-bold">12</div>
            <div className="h-16 bg-red-500/10 flex items-center justify-center text-lg font-bold">3</div>
            
            {/* Suspicious row */}
            <div className="h-16 bg-muted flex items-center justify-center font-medium">Suspicious</div>
            <div className="h-16 bg-red-500/10 flex items-center justify-center text-lg font-bold">8</div>
            <div className="h-16 bg-green-500/20 flex items-center justify-center text-lg font-bold">87</div>
            <div className="h-16 bg-red-500/10 flex items-center justify-center text-lg font-bold">5</div>
            
            {/* Malicious row */}
            <div className="h-16 bg-muted flex items-center justify-center font-medium">Malicious</div>
            <div className="h-16 bg-red-500/10 flex items-center justify-center text-lg font-bold">2</div>
            <div className="h-16 bg-red-500/10 flex items-center justify-center text-lg font-bold">7</div>
            <div className="h-16 bg-green-500/20 flex items-center justify-center text-lg font-bold">65</div>
          </div>
          
          {/* Axis labels */}
          <div className="absolute -left-12 top-1/2 transform -translate-y-1/2 -rotate-90 text-sm text-muted-foreground">
            Actual
          </div>
          <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-6 text-sm text-muted-foreground">
            Predicted
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div className="p-3 border border-green-500/20 rounded-md bg-green-500/5">
          <div className="font-medium">True Positives</div>
          <div className="text-muted-foreground">Correctly identified as positive: 243 + 87 + 65 = 395</div>
        </div>
        
        <div className="p-3 border border-red-500/20 rounded-md bg-red-500/5">
          <div className="font-medium">False Positives</div>
          <div className="text-muted-foreground">Incorrectly identified as positive: 12 + 3 + 8 + 5 + 2 + 7 = 37</div>
        </div>
      </div>
    </div>
  );
};

const ROCCurve = () => {
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium">ROC Curve</h3>
      
      <div className="border border-border rounded-md p-4 h-60 relative">
        {/* Axes */}
        <div className="absolute top-0 bottom-0 left-10 w-[1px] bg-border"></div>
        <div className="absolute bottom-10 left-0 right-0 h-[1px] bg-border"></div>
        
        {/* Axes labels */}
        <div className="absolute top-0 bottom-0 left-2 flex flex-col justify-between text-xs text-muted-foreground">
          <span>1.0</span>
          <span>0.8</span>
          <span>0.6</span>
          <span>0.4</span>
          <span>0.2</span>
          <span>0.0</span>
        </div>
        <div className="absolute bottom-2 left-10 right-0 flex justify-between text-xs text-muted-foreground">
          <span>0.0</span>
          <span>0.2</span>
          <span>0.4</span>
          <span>0.6</span>
          <span>0.8</span>
          <span>1.0</span>
        </div>
        
        {/* Axis titles */}
        <div className="absolute -left-8 top-1/2 transform -translate-y-1/2 -rotate-90 text-xs text-muted-foreground">
          True Positive Rate
        </div>
        <div className="absolute bottom-4 left-1/2 transform -translate-x-1/2 text-xs text-muted-foreground">
          False Positive Rate
        </div>
        
        {/* Diagonal line (random classifier) */}
        <svg className="absolute top-0 left-10 bottom-10 right-0">
          <line 
            x1="0%" y1="100%" 
            x2="100%" y2="0%" 
            stroke="#d4d4d8" 
            strokeWidth="1" 
            strokeDasharray="4,4"
          />
        </svg>
        
        {/* ROC curve */}
        <svg className="absolute top-0 left-10 bottom-10 right-0">
          <path 
            d="M0,190 C20,170 40,100 80,70 C120,40 180,20 220,10" 
            fill="none" 
            stroke="#3b82f6" 
            strokeWidth="2"
          />
        </svg>
        
        {/* AUC value */}
        <div className="absolute top-4 right-4 bg-background/80 backdrop-blur-sm p-2 rounded-md border border-border text-xs">
          <div className="font-medium">AUC</div>
          <div className="text-lg font-bold text-blue-500">0.928</div>
        </div>
      </div>
      
      {/* AUC explanation */}
      <div className="p-3 border border-border rounded-md bg-muted/10 text-sm">
        <div className="font-medium mb-1">Area Under Curve (AUC)</div>
        <p className="text-muted-foreground">
          The AUC value of 0.928 indicates excellent model discrimination. 
          The model's ability to distinguish between classes is significantly better than random chance (0.5).
        </p>
      </div>
    </div>
  );
};

const FeatureImportance = () => {
  const features = [
    { name: "Connection Duration", importance: 0.24 },
    { name: "Protocol Type", importance: 0.18 },
    { name: "Bytes Transferred", importance: 0.15 },
    { name: "Source Port", importance: 0.12 },
    { name: "Destination Port", importance: 0.09 },
    { name: "Time of Day", importance: 0.08 },
    { name: "Packet Size", importance: 0.06 },
    { name: "TCP Flags", importance: 0.05 },
    { name: "Service", importance: 0.03 }
  ];
  
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium">Feature Importance</h3>
      
      <div className="border border-border rounded-md p-4">
        {features.map((feature, i) => (
          <div key={i} className="mb-4 last:mb-0">
            <div className="flex justify-between mb-1">
              <span className="text-sm">{feature.name}</span>
              <span className="text-sm font-medium">{(feature.importance * 100).toFixed(1)}%</span>
            </div>
            <div className="w-full h-2 bg-muted rounded-full">
              <div 
                className="h-full bg-blue-500 rounded-full" 
                style={{ width: `${feature.importance * 100}%` }}
              ></div>
            </div>
          </div>
        ))}
      </div>
      
      {/* Recommendation */}
      <div className="p-3 border border-blue-500/20 rounded-md bg-blue-500/5 text-sm">
        <div className="font-medium mb-1">Analysis</div>
        <p className="text-muted-foreground">
          Connection Duration and Protocol Type are the most influential features in this model.
          Consider collecting more granular data for these features to potentially improve model accuracy.
        </p>
      </div>
    </div>
  );
};

export default ModelMetrics;
