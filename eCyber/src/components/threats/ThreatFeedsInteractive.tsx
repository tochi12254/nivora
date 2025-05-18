
import React, { useState } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Shield, Globe, AlertOctagon, Activity, Eye, RefreshCw, Bell } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";

// Threat feed data with expanded information
const initialThreatFeeds = [
  { 
    id: 1, 
    name: 'MITRE ATT&CK', 
    status: 'active', 
    icon: Shield,
    description: 'Globally-accessible knowledge base of adversary tactics and techniques',
    lastUpdated: new Date(Date.now() - 2 * 60 * 60 * 1000),
    entries: 4231,
    isExpanded: false,
    isSubscribed: true
  },
  { 
    id: 2, 
    name: 'OSINT Feed', 
    status: 'active', 
    icon: Globe,
    description: 'Open-source intelligence on emerging threats and vulnerabilities',
    lastUpdated: new Date(Date.now() - 4 * 60 * 60 * 1000),
    entries: 1872,
    isExpanded: false,
    isSubscribed: true
  },
  { 
    id: 3, 
    name: 'Threat Intel', 
    status: 'warning', 
    icon: AlertOctagon,
    description: 'Curated intelligence on active threats and malicious actors',
    lastUpdated: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000), 
    entries: 942,
    isExpanded: false,
    isSubscribed: true
  },
  { 
    id: 4, 
    name: 'CVE Database', 
    status: 'active', 
    icon: Activity,
    description: 'Comprehensive database of Common Vulnerabilities and Exposures',
    lastUpdated: new Date(Date.now() - 1 * 60 * 60 * 1000),
    entries: 12543, 
    isExpanded: false,
    isSubscribed: true
  },
];

const ThreatFeedsInteractive = () => {
  const [threatFeeds, setThreatFeeds] = useState(initialThreatFeeds);
  const { toast } = useToast();
  
  const toggleExpand = (id: number) => {
    setThreatFeeds(feeds => 
      feeds.map(feed => 
        feed.id === id ? { ...feed, isExpanded: !feed.isExpanded } : feed
      )
    );
  };
  
  const toggleSubscription = (id: number) => {
    setThreatFeeds(feeds => 
      feeds.map(feed => {
        if (feed.id === id) {
          const newStatus = !feed.isSubscribed;
          // Show toast notification
          toast({
            title: newStatus ? "Subscription Activated" : "Subscription Deactivated",
            description: `You have ${newStatus ? 'subscribed to' : 'unsubscribed from'} ${feed.name}`,
            variant: newStatus ? "default" : "destructive",
          });
          return { ...feed, isSubscribed: newStatus };
        }
        return feed;
      })
    );
  };
  
  const refreshFeed = (id: number) => {
    // Simulate a refresh
    toast({
      title: "Refreshing Feed",
      description: "Fetching the latest threat intelligence...",
    });
    
    setTimeout(() => {
      setThreatFeeds(feeds => 
        feeds.map(feed => {
          if (feed.id === id) {
            return { 
              ...feed, 
              lastUpdated: new Date(),
              entries: feed.entries + Math.floor(Math.random() * 20),
              status: 'active'
            };
          }
          return feed;
        })
      );
      
      toast({
        title: "Feed Updated",
        description: "The latest threat intelligence has been loaded",
        variant: "default",
      });
    }, 2000);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center">
          <Bell className="mr-2" size={18} />
          Threat Intelligence Feeds
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {threatFeeds.map((feed) => (
            <div 
              key={feed.id} 
              className={cn(
                "border border-border rounded-lg transition-all",
                feed.isExpanded ? "bg-muted/30" : ""
              )}
            >
              <div 
                className="flex items-center justify-between p-4 cursor-pointer"
                onClick={() => toggleExpand(feed.id)}
              >
                <div className="flex items-center">
                  <div className={cn(
                    "w-10 h-10 rounded-full flex items-center justify-center mr-3",
                    feed.status === 'active' ? "bg-green-500/10 text-green-500" : "bg-amber-500/10 text-amber-500"
                  )}>
                    <feed.icon size={20} />
                  </div>
                  <div>
                    <div className="font-medium">{feed.name}</div>
                    <div className="text-xs text-muted-foreground">{feed.entries} entries</div>
                  </div>
                </div>
                <div className="text-right">
                  <Badge 
                    variant="outline" 
                    className={cn(
                      feed.status === 'active' ? "bg-green-500/10 text-green-500" : "bg-amber-500/10 text-amber-500"
                    )}
                  >
                    {feed.status === 'active' ? 'Active' : 'Warning'}
                  </Badge>
                  <div className="text-xs text-muted-foreground mt-1">
                    Updated {feed.lastUpdated.toLocaleTimeString()} {feed.lastUpdated.toLocaleDateString()}
                  </div>
                </div>
              </div>
              
              {feed.isExpanded && (
                <div className="p-4 pt-0 border-t border-border mt-2">
                  <p className="text-sm mb-3">{feed.description}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={(e) => {
                          e.stopPropagation();
                          refreshFeed(feed.id);
                        }}
                      >
                        <RefreshCw className="mr-2 h-3.5 w-3.5" />
                        Refresh Feed
                      </Button>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={(e) => {
                          e.stopPropagation();
                          // View details functionality
                          toast({
                            title: "Viewing Feed Details",
                            description: `Detailed view of ${feed.name}`,
                          });
                        }}
                      >
                        <Eye className="mr-2 h-3.5 w-3.5" />
                        View Details
                      </Button>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm">Subscribed</span>
                      <Switch 
                        checked={feed.isSubscribed}
                        onCheckedChange={() => toggleSubscription(feed.id)}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default ThreatFeedsInteractive;
