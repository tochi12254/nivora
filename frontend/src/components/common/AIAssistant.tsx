
import React, { useState } from 'react';
import { Bot, X, Maximize2, Minimize2, Send } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

interface AIAssistantProps {
  className?: string;
}

interface Message {
  id: number;
  text: string;
  sender: 'user' | 'ai';
  timestamp: Date;
}

const initialMessages: Message[] = [
  {
    id: 1,
    text: "Hello! I'm ISIMBI's AI Assistant. How can I help you with security monitoring today?",
    sender: 'ai',
    timestamp: new Date(),
  }
];

const AIAssistant: React.FC<AIAssistantProps> = ({ className }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [messages, setMessages] = useState<Message[]>(initialMessages);
  const [input, setInput] = useState('');

  // Function to handle sending a new message
  const handleSendMessage = () => {
    if (!input.trim()) return;

    // Add user message
    const userMessage: Message = {
      id: messages.length + 1,
      text: input,
      sender: 'user',
      timestamp: new Date(),
    };
    
    setMessages([...messages, userMessage]);
    setInput('');

    // Simulate AI response
    setTimeout(() => {
      const aiResponses = [
        "I've analyzed your request and found relevant security information.",
        "Based on recent scans, there are no critical threats matching that pattern.",
        "Let me check our logs for that activity pattern...",
        "I've identified several similar events in the last 24 hours that you should review.",
        "The network traffic patterns appear normal based on historical baselines."
      ];
      
      const aiMessage: Message = {
        id: messages.length + 2,
        text: aiResponses[Math.floor(Math.random() * aiResponses.length)],
        sender: 'ai',
        timestamp: new Date(),
      };
      
      setMessages(prevMessages => [...prevMessages, aiMessage]);
    }, 1000);
  };

  return (
    <>
      {/* Chat button */}
      {!isOpen && (
        <Button 
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 h-14 w-14 rounded-full shadow-lg bg-isimbi-purple hover:bg-isimbi-purple/90 flex items-center justify-center"
        >
          <Bot size={24} />
        </Button>
      )}
      
      {/* Chat panel */}
      {isOpen && (
        <div 
          className={cn(
            "fixed bottom-6 right-6 glass-card border border-white/10 shadow-xl flex flex-col",
            "transition-all duration-300 z-50",
            isExpanded ? "w-[80vw] h-[80vh] max-w-4xl translate-x-0" : "w-96 h-[500px] max-w-[90vw]",
            className
          )}
        >
          {/* Header */}
          <div className="p-4 border-b border-border flex items-center justify-between">
            <div className="flex items-center">
              <Bot className="h-5 w-5 text-isimbi-purple mr-2" />
              <h3 className="font-medium">ISIMBI AI Assistant</h3>
            </div>
            <div className="flex items-center space-x-2">
              <Button 
                variant="ghost" 
                size="sm" 
                className="h-8 w-8 p-0" 
                onClick={() => setIsExpanded(!isExpanded)}
              >
                {isExpanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
              </Button>
              <Button 
                variant="ghost" 
                size="sm" 
                className="h-8 w-8 p-0" 
                onClick={() => setIsOpen(false)}
              >
                <X size={16} />
              </Button>
            </div>
          </div>
          
          {/* Messages */}
          <div className="flex-1 p-4 overflow-y-auto space-y-4">
            {messages.map((message) => (
              <div 
                key={message.id} 
                className={cn(
                  "max-w-[80%] rounded-lg p-3",
                  message.sender === 'user' 
                    ? "bg-isimbi-purple/20 ml-auto" 
                    : "bg-secondary/50"
                )}
              >
                <div className="text-sm">{message.text}</div>
                <div className="text-xs text-muted-foreground mt-1">
                  {message.timestamp.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                </div>
              </div>
            ))}
          </div>
          
          {/* Input */}
          <div className="p-4 border-t border-border">
            <form 
              className="flex items-center space-x-2" 
              onSubmit={(e) => {
                e.preventDefault();
                handleSendMessage();
              }}
            >
              <Input
                placeholder="Ask about security events, alerts, or data..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="flex-1"
              />
              <Button type="submit" size="icon">
                <Send size={16} />
              </Button>
            </form>
          </div>
        </div>
      )}
    </>
  );
};

export default AIAssistant;
