
import React, { useEffect, useRef } from 'react';
import { 
  Area, 
  AreaChart, 
  ResponsiveContainer, 
  Tooltip, 
  XAxis, 
  YAxis 
} from 'recharts';
import { Settings } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

// Simulated data - in a real app, this would come from an API
const generateData = () => {
  const now = new Date();
  return Array.from({ length: 24 }, (_, i) => {
    const time = new Date(now);
    time.setHours(time.getHours() - 23 + i);
    
    return {
      time: `${time.getHours()}:00`,
      threats: Math.floor(Math.random() * 15),
      traffic: Math.floor(Math.random() * 100) + 20,
    };
  });
};

// Simulated threat locations
const threatLocations = [
  { id: 1, latitude: 40.7128, longitude: -74.0060, country: "United States", severity: "critical", count: 27 },
  { id: 2, latitude: 51.5074, longitude: -0.1278, country: "United Kingdom", severity: "warning", count: 15 },
  { id: 3, latitude: 35.6762, longitude: 139.6503, country: "Japan", severity: "info", count: 8 },
  { id: 4, latitude: -33.8688, longitude: 151.2093, country: "Australia", severity: "blocked", count: 42 },
  { id: 5, latitude: 55.7558, longitude: 37.6173, country: "Russia", severity: "critical", count: 31 },
];

interface ThreatMapProps {
  className?: string;
}

const ThreatMap: React.FC<ThreatMapProps> = ({ className }) => {
  const [data, setData] = React.useState(generateData());
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  // Redraw canvas when component mounts
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // Set canvas dimensions
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw world map outline (simplified for this example)
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.beginPath();
    ctx.arc(canvas.width / 2, canvas.height / 2, canvas.height / 3, 0, Math.PI * 2);
    ctx.stroke();
    
    // Draw grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    for (let i = 0; i < 360; i += 20) {
      const angle = (i * Math.PI) / 180;
      const radius = canvas.height / 3;
      
      ctx.beginPath();
      ctx.moveTo(canvas.width / 2, canvas.height / 2);
      ctx.lineTo(
        canvas.width / 2 + Math.cos(angle) * radius,
        canvas.height / 2 + Math.sin(angle) * radius
      );
      ctx.stroke();
    }
    
    // Draw animated pulse circles
    const drawPulses = () => {
      threatLocations.forEach((threat) => {
        // Convert lat/long to x,y (simplified)
        const x = canvas.width / 2 + (threat.longitude / 180) * (canvas.width / 3);
        const y = canvas.height / 2 - (threat.latitude / 90) * (canvas.height / 4);
        
        // Draw threat point
        let color = 'rgba(14, 165, 233, 0.8)'; // info blue
        if (threat.severity === 'warning') color = 'rgba(245, 158, 11, 0.8)';
        if (threat.severity === 'critical') color = 'rgba(239, 68, 68, 0.8)';
        if (threat.severity === 'blocked') color = 'rgba(16, 185, 129, 0.8)';
        
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fill();
        
        // Draw pulse animation
        const time = Date.now() / 1000;
        const pulseSize = 8 + (Math.sin(time * 2 + threat.id) + 1) * 8;
        
        ctx.strokeStyle = color.replace('0.8', '0.3');
        ctx.beginPath();
        ctx.arc(x, y, pulseSize, 0, Math.PI * 2);
        ctx.stroke();
      });
      
      requestAnimationFrame(drawPulses);
    };
    
    drawPulses();
    
    // Update data every 15 seconds
    const interval = setInterval(() => {
      setData(generateData());
    }, 15000);
    
    return () => clearInterval(interval);
  }, []);
  
  return (
    <Card className={`${className} shadow-lg border-border relative overflow-hidden`}>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium">Global Threat Map</CardTitle>
        <Button variant="ghost" size="sm">
          <Settings size={16} />
        </Button>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Threat map visualization */}
          <div className="glass-card p-4 lg:col-span-2">
            <div className="aspect-[16/9] relative">
              <canvas 
                ref={canvasRef} 
                className="absolute inset-0 w-full h-full"
              ></canvas>
            </div>
            <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
              <div className="flex items-center space-x-4">
                <div className="flex items-center">
                  <span className="inline-block w-3 h-3 rounded-full bg-blue-500 mr-1"></span>
                  <span>Info</span>
                </div>
                <div className="flex items-center">
                  <span className="inline-block w-3 h-3 rounded-full bg-amber-500 mr-1"></span>
                  <span>Warning</span>
                </div>
                <div className="flex items-center">
                  <span className="inline-block w-3 h-3 rounded-full bg-red-500 mr-1"></span>
                  <span>Critical</span>
                </div>
                <div className="flex items-center">
                  <span className="inline-block w-3 h-3 rounded-full bg-green-500 mr-1"></span>
                  <span>Blocked</span>
                </div>
              </div>
              <span>Updated just now</span>
            </div>
          </div>
          
          {/* Threat metrics */}
          <div className="space-y-4">
            <div className="glass-card p-4">
              <h3 className="text-xs font-medium text-muted-foreground mb-2">Threat Activity (24h)</h3>
              <ResponsiveContainer width="100%" height={120}>
                <AreaChart data={data}>
                  <defs>
                    <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#9b87f5" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#9b87f5" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis 
                    dataKey="time"
                    tick={{ fontSize: 10, fill: '#64748b' }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis 
                    hide={true}
                  />
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'rgba(26, 31, 44, 0.9)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                      boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
                    }}
                    itemStyle={{ color: '#f8fafc' }}
                    formatter={(value) => [`${value} threats`, 'Detected']}
                    labelFormatter={(label) => `Time: ${label}`}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="threats" 
                    stroke="#9b87f5" 
                    fill="url(#threatGradient)" 
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            
            <div className="glass-card p-4">
              <h3 className="text-xs font-medium text-muted-foreground mb-3">Top Threat Locations</h3>
              <ul className="space-y-3">
                {threatLocations.slice(0, 3).map((location) => (
                  <li key={location.id} className="flex items-center justify-between">
                    <div className="flex items-center">
                      <div 
                        className={`w-2 h-2 rounded-full mr-2 ${
                          location.severity === 'critical' ? 'bg-red-500' : 
                          location.severity === 'warning' ? 'bg-amber-500' : 
                          location.severity === 'blocked' ? 'bg-green-500' :
                          'bg-blue-500'
                        }`}
                      ></div>
                      <span className="text-sm">{location.country}</span>
                    </div>
                    <span className="text-sm font-medium data-highlight">
                      {location.count}
                    </span>
                  </li>
                ))}
              </ul>
              <div className="mt-3 pt-3 border-t border-border">
                <Button variant="ghost" size="sm" className="w-full text-xs text-muted-foreground hover:text-primary">
                  View All Locations
                </Button>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ThreatMap;
