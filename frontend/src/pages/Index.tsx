
import React, { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Link } from 'react-router-dom';
import { ChevronRight, Shield, Cpu, Database, Lock, Globe } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';
import axios from 'axios';
import { RootState } from '@/app/store';
import { setIsLoginShown } from '@/features/display/displaySlice';
import Login from './Login';

const Index = () => {

  const [data, setData] = useState<any[]>();
  const dispatch = useDispatch();
  const isLoginShown: boolean = useSelector((state: RootState) => state.display.isLoginShown);

  useEffect(() => {
    async () => {
        try {
          const response = await axios.get("http://127.0.0.1:8000/test-create-user");
          if (response.data) {
            setData(response.data);
            console.log("Received data: ", response.data)
          }
        } catch (error: any) {
          console.error("error: ", error)
        }
  }
  },[data])
  
  return (
    <div className="min-h-screen relative bg-gradient-to-b from-isimbi-navy via-isimbi-navy to-isimbi-dark-charcoal">
      {/* Header */}
      <header className="container mx-auto px-4 py-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <div className="h-8 w-8 rounded-md bg-isimbi-purple flex items-center justify-center">
              <span className="text-white font-bold">CW</span>
            </div>
            <span className="text-xl font-semibold text-white ml-2 tracking-wider">CYBER WATCH</span>
          </div>
          <nav className="hidden md:flex space-x-8 text-sm">
            <a href="#features" className="text-gray-300 hover:text-white transition-colors">Features</a>
            <a href="#about" className="text-gray-300 hover:text-white transition-colors">About</a>
            <a href="#security" className="text-gray-300 hover:text-white transition-colors">Security</a>
            <a href="#contact" className="text-gray-300 hover:text-white transition-colors">Contact</a>
          </nav>
          <div className="flex items-center space-x-4">
            <Button variant="ghost" className="text-gray-300 hover:text-white"  onClick={() => dispatch(setIsLoginShown(!isLoginShown))}>
              Sign In
            </Button>
            <Button className="bg-isimbi-purple hover:bg-isimbi-purple/90">
              Request Demo
            </Button>
          </div>
        </div>
        
      </header>
      <Login/>
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 md:py-32 flex flex-col items-center justify-center text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="max-w-4xl mx-auto"
        >
          <h1 className="text-4xl md:text-6xl font-bold text-white leading-tight mb-6">
            CYBER WATCH — <span className="text-isimbi-purple">Intelligent Security</span>, Built for the New Era
          </h1>
          <p className="text-xl text-gray-300 mb-10 max-w-2xl mx-auto">
            Advanced network monitoring, threat detection, and AI-powered incident response for the modern enterprise.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-4">
            <Link to="/dashboard">
              <Button size="lg" className="bg-isimbi-bright-blue hover:bg-isimbi-bright-blue/90 text-white px-8 shadow-lg shadow-isimbi-bright-blue/20">
                Explore Dashboard
                <ChevronRight className="ml-2 h-5 w-5" />
              </Button>
            </Link>
            <Button variant="outline" size="lg" className="border-gray-600 text-white hover:bg-white/5">
              Watch Video Demo
            </Button>
          </div>
        </motion.div>

        {/* Animated visualization */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5, duration: 1.5 }}
          className="mt-16 relative w-full max-w-4xl h-64 sm:h-80 md:h-96"
        >
          {/* Simplified 3D network visualization */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="relative w-64 h-64 sm:w-80 sm:h-80 animate-rotate-globe">
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-40 h-40 sm:w-52 sm:h-52 rounded-full border border-isimbi-purple/20"></div>
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-60 h-60 sm:w-72 sm:h-72 rounded-full border border-isimbi-purple/15 rotate-45"></div>
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-full h-full rounded-full border border-isimbi-purple/10 -rotate-12"></div>
              
              {/* Nodes */}
              {[...Array(12)].map((_, i) => {
                const angle = (i / 12) * Math.PI * 2;
                const radius = 120;
                const x = Math.cos(angle) * radius;
                const y = Math.sin(angle) * radius;
                return (
                  <motion.div
                    key={i}
                    className={`absolute top-1/2 left-1/2 w-3 h-3 rounded-full bg-isimbi-purple/80`}
                    style={{ 
                      left: `calc(50% + ${x}px)`, 
                      top: `calc(50% + ${y}px)` 
                    }}
                    animate={{
                      scale: [1, 1.2, 1],
                      opacity: [0.7, 1, 0.7]
                    }}
                    transition={{
                      repeat: Infinity,
                      duration: 2,
                      delay: i * 0.2
                    }}
                  />
                );
              })}
              
              {/* Connecting lines - simulated with absolutely positioned divs */}
              <div className="absolute top-1/2 left-1/2 w-3/4 h-0.5 bg-gradient-to-r from-transparent via-isimbi-bright-blue/30 to-transparent transform -translate-x-1/2 -translate-y-1/2"></div>
              <div className="absolute top-1/2 left-1/2 w-3/4 h-0.5 bg-gradient-to-r from-transparent via-isimbi-bright-blue/30 to-transparent transform -translate-x-1/2 -translate-y-1/2 rotate-45"></div>
              <div className="absolute top-1/2 left-1/2 w-3/4 h-0.5 bg-gradient-to-r from-transparent via-isimbi-bright-blue/30 to-transparent transform -translate-x-1/2 -translate-y-1/2 rotate-90"></div>
              <div className="absolute top-1/2 left-1/2 w-3/4 h-0.5 bg-gradient-to-r from-transparent via-isimbi-bright-blue/30 to-transparent transform -translate-x-1/2 -translate-y-1/2 rotate-135"></div>
              
              {/* Center globe */}
              <motion.div 
                className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-16 h-16 rounded-full bg-gradient-to-r from-isimbi-purple to-isimbi-bright-blue blur-sm animate-float"
                animate={{ 
                  boxShadow: ["0 0 10px rgba(155, 135, 245, 0.5)", "0 0 30px rgba(155, 135, 245, 0.8)", "0 0 10px rgba(155, 135, 245, 0.5)"] 
                }}
                transition={{ duration: 3, repeat: Infinity }}
              />
            </div>
          </div>
          
          {/* Packets/data visualization */}
          {[...Array(7)].map((_, i) => (
            <motion.div
              key={i}
              className="absolute h-2 w-2 rounded-full bg-isimbi-bright-blue"
              style={{ 
                left: Math.random() * 100 + '%',
                top: Math.random() * 100 + '%',
                opacity: 0,
              }}
              animate={{ 
                opacity: [0, 0.8, 0],
                scale: [0, 1, 0],
                x: Math.random() * 200 - 100,
                y: Math.random() * 200 - 100,
              }}
              transition={{ 
                repeat: Infinity, 
                duration: 3,
                delay: i * 0.7,
                ease: "easeInOut" 
              }}
            />
          ))}
        </motion.div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 bg-gradient-to-b from-isimbi-dark-charcoal to-isimbi-navy">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-white mb-4">Enterprise-Grade Security Features</h2>
            <p className="text-gray-300 max-w-2xl mx-auto">
              Comprehensive cybersecurity platform combining AI, machine learning, and expert systems for advanced threat detection and response.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {/* Feature 1 */}
            <div className="glass-card p-6 relative overflow-hidden group">
              <div className="mb-4 text-isimbi-bright-blue">
                <Shield size={28} />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Real-Time Threat Detection</h3>
              <p className="text-gray-300 text-sm">
                Advanced algorithms constantly monitor for anomalies and potential security breaches.
              </p>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </div>

            {/* Feature 2 */}
            <div className="glass-card p-6 relative overflow-hidden group">
              <div className="mb-4 text-isimbi-bright-blue">
                <Cpu size={28} />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">AI-Powered Analysis</h3>
              <p className="text-gray-300 text-sm">
                Machine learning models that adapt to your organization's network patterns and behaviors.
              </p>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </div>

            {/* Feature 3 */}
            <div className="glass-card p-6 relative overflow-hidden group">
              <div className="mb-4 text-isimbi-bright-blue">
                <Database size={28} />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Comprehensive Logging</h3>
              <p className="text-gray-300 text-sm">
                Full-spectrum data collection and storage with intelligent searching and filtering.
              </p>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </div>

            {/* Feature 4 */}
            <div className="glass-card p-6 relative overflow-hidden group">
              <div className="mb-4 text-isimbi-bright-blue">
                <Globe size={28} />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Global Threat Intelligence</h3>
              <p className="text-gray-300 text-sm">
                Up-to-date information on emerging threats and attack vectors from around the world.
              </p>
              <div className="absolute -bottom-10 -right-10 w-32 h-32 bg-isimbi-purple/10 rounded-full blur-2xl transition-all group-hover:w-40 group-hover:h-40 group-hover:bg-isimbi-purple/15"></div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-isimbi-navy relative overflow-hidden">
        <div className="container mx-auto px-4 relative z-10">
          <div className="max-w-3xl mx-auto text-center">
            <h2 className="text-3xl font-bold text-white mb-6">Ready to Strengthen Your Security Posture?</h2>
            <p className="text-gray-300 mb-10">
              Join industry leaders who trust CYBER WATCH for their most critical security operations.
            </p>
            <Link to="/dashboard">
              <Button size="lg" className="bg-isimbi-purple hover:bg-isimbi-purple/90 text-white px-8 shadow-lg shadow-isimbi-purple/20">
                Experience the Dashboard
              </Button>
            </Link>
          </div>
        </div>
        
        {/* Background decorative elements */}
        <div className="absolute top-0 left-0 w-full h-full">
          <div className="absolute top-10 left-10 w-72 h-72 bg-isimbi-purple/5 rounded-full blur-3xl"></div>
          <div className="absolute bottom-10 right-10 w-80 h-80 bg-isimbi-bright-blue/5 rounded-full blur-3xl"></div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-isimbi-dark-charcoal py-10 border-t border-white/10">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="flex items-center mb-6 md:mb-0">
              <div className="h-8 w-8 rounded-md bg-isimbi-purple flex items-center justify-center">
                <span className="text-white font-bold">IS</span>
              </div>
              <span className="text-xl font-semibold text-white ml-2 tracking-wider">CYBER WATCH</span>
            </div>
            <div className="text-sm text-gray-400">
              &copy; {new Date().getFullYear()} CYBER WATCH Security. All rights reserved.
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
