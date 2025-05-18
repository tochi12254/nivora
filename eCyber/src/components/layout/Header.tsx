
import React, { useState } from 'react';
import { Bell, Search, User, Settings, LogOut } from 'lucide-react';
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuLabel, 
  DropdownMenuSeparator, 
  DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { Input } from "@/components/ui/input";
import { cn } from '@/lib/utils';
import { Link } from 'react-router-dom';
const notifications = [
  { id: 1, title: "Critical alert detected", description: "Unusual login from Philippines", time: "2m ago", read: false },
  { id: 2, title: "Threat blocked", description: "Malware attempt stopped", time: "10m ago", read: false },
  { id: 3, title: "Daily scan completed", description: "No issues found", time: "1h ago", read: true },
];

const Header = () => {
  const [isSearchActive, setIsSearchActive] = useState(false);
  
  return (
    <header className="h-16 bg-background/50 backdrop-blur-lg border-b border-border flex items-center justify-between px-6 z-10">
      {/* Left side - Search */}
      <div className={cn(
        "relative transition-all duration-300",
        isSearchActive ? "w-full md:w-2/3" : "w-64"
      )}>
        <Input
          placeholder="Search threats, logs, IPs..."
          className="pl-10 bg-secondary/50 border-secondary hover:border-isimbi-purple/50 focus:border-isimbi-purple"
          onFocus={() => setIsSearchActive(true)}
          onBlur={() => setIsSearchActive(false)}
        />
        <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
      </div>
      
      {/* Right side - Actions */}
      <div className="flex items-center space-x-4">
        {/* System status */}
        
        
        {/* Notifications */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="relative p-2 rounded-full hover:bg-secondary/80 transition-colors">
              <Bell size={20} />
              <span className="absolute top-1 right-1 w-2 h-2 bg-isimbi-purple rounded-full"></span>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80">
            <DropdownMenuLabel className="flex items-center justify-between">
              <span>Notifications</span>
              <span className="text-xs text-muted-foreground">Mark all as read</span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {notifications.map((notification) => (
              <DropdownMenuItem key={notification.id} className="flex flex-col items-start p-3 cursor-pointer">
                <div className="flex items-start justify-between w-full">
                  <div className="font-medium">{notification.title}</div>
                  <div className="text-xs text-muted-foreground">{notification.time}</div>
                </div>
                <div className="text-sm text-muted-foreground mt-1">{notification.description}</div>
                {!notification.read && <div className="w-1.5 h-1.5 bg-isimbi-purple rounded-full mt-1"></div>}
              </DropdownMenuItem>
            ))}
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-center text-sm text-muted-foreground hover:text-foreground cursor-pointer">
              View all notifications
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <div>
          <ThemeToggle/>
        </div>
        {/* User menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="flex items-center space-x-2">
              <Avatar className="h-8 w-8 border border-border">
                <AvatarImage src="https://github.com/shadcn.png" />
                <AvatarFallback>JD</AvatarFallback>
              </Avatar>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>My Account</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="cursor-pointer">
              <User className="mr-2" size={16} />
              <span>Profile</span>
            </DropdownMenuItem>
            <DropdownMenuItem className="cursor-pointer">
              <Settings className="mr-2" size={16} />
              <span>Settings</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="cursor-pointer text-destructive">
              <LogOut className="mr-2" size={16} />
              <Link to={"/"}>
              <span>Log out</span>
              </Link>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
};

export default Header;
