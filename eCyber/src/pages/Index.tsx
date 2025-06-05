import React, { useEffect, useState, useRef } from 'react';
import { Shield, Terminal, AlertTriangle, Activity, Zap, Eye, Lock, Cpu, Globe, Server, Wifi, Target, Crosshair, Radar, Satellite, Skull, Brain, Binary, CircuitBoard, Usb, FileX, Flame, Bug, Database, Network, Radio, Signal, Camera, Headphones } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { RootState } from "@/app/store";
import { setAuthModalState } from "@/app/slices/displaySlice"
import { useSelector, useDispatch } from "react-redux"
import AuthModal from './AuthModal';

const Index = () => {

  const dispatch = useDispatch();
  const isAuthModalOpen = useSelector((state: RootState) => state.display.isAuthModalOpen);

  const [text, setText] = useState('');
  const [matrixChars, setMatrixChars] = useState([]);
  const [threatCount, setThreatCount] = useState(847291);
  const [systemStatus, setSystemStatus] = useState('SCANNING');
  const [activeThreats, setActiveThreats] = useState([]);
  const [glitchText, setGlitchText] = useState('CYBER WARFARE DEFENSE');
  const [networkNodes, setNetworkNodes] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [scanProgress, setScanProgress] = useState(0);
  const canvasRef = useRef(null);


  
  const fullText = 'Quantum-encrypted neural threat analysis engine initialized... Scanning 847,291 endpoints across 195 countries... Advanced AI threat detection ACTIVE... Zero-day exploit prevention ENABLED... Real-time cyber warfare countermeasures DEPLOYED...';

  const threatTypes = [
    'APT29 COZY BEAR', 'LAZARUS GROUP', 'EQUATION GROUP', 'CARBANAK', 'FANCY BEAR',
    'DARK HALO', 'MAZE RANSOMWARE', 'RYUK VARIANT', 'EMOTET TROJAN', 'TRICKBOT',
    'COBALT STRIKE', 'MIMIKATZ', 'POWERSHELL EMPIRE', 'METASPLOIT', 'BLOODHOUND'
  ];

  const countries = ['RUSSIA', 'CHINA', 'NORTH KOREA', 'IRAN', 'UKRAINE', 'USA', 'UK', 'ISRAEL', 'GERMANY', 'FRANCE'];

  // Matrix rain effect - more intense
  useEffect(() => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ@#$%^&*()_+-=[]{}|;:,.<>?¡™£¢∞§¶•ªº–≠œ∑´®†¥¨ˆøπ"'.split('');
    const matrix = [];
    for (let i = 0; i < 150; i++) {
      matrix.push({
        id: i,
        x: Math.random() * 100,
        char: chars[Math.floor(Math.random() * chars.length)],
        delay: Math.random() * 3,
        speed: 0.5 + Math.random() * 2
      });
    }
    setMatrixChars(matrix);
  }, []);

  // Network visualization
  useEffect(() => {
    const nodes = [];
    for (let i = 0; i < 30; i++) {
      nodes.push({
        id: i,
        x: Math.random() * 100,
        y: Math.random() * 100,
        connections: Math.floor(Math.random() * 4) + 1,
        status: Math.random() > 0.8 ? 'threat' : Math.random() > 0.9 ? 'warning' : 'secure'
      });
    }
    setNetworkNodes(nodes);
  }, []);

  // Typing effect with glitch
  useEffect(() => {
    let i = 0;
    const typingInterval = setInterval(() => {
      if (i < fullText.length) {
        setText(fullText.substring(0, i + 1));
        i++;
      } else {
        clearInterval(typingInterval);
        setSystemStatus('OPERATIONAL');
      }
    }, 30);

    return () => clearInterval(typingInterval);
  }, []);

  // Real-time threat simulation
  useEffect(() => {
    const threatInterval = setInterval(() => {
      setThreatCount(prev => prev + Math.floor(Math.random() * 47) + 1);
      
      // Generate new threats
      const newThreat = {
        id: Date.now(),
        type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
        country: countries[Math.floor(Math.random() * countries.length)],
        severity: Math.random() > 0.7 ? 'CRITICAL' : Math.random() > 0.4 ? 'HIGH' : 'MEDIUM',
        ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
      };
      
      setActiveThreats(prev => [newThreat, ...prev.slice(0, 4)]);
    }, 1500);

    return () => clearInterval(threatInterval);
  }, []);

  // Glitch effect for main title
  useEffect(() => {
    const glitchInterval = setInterval(() => {
      const glitchChars = '!@#$%^&*()_+-=[]{}|;:,.<>?1234567890';
      const originalText = 'CYBER WARFARE DEFENSE';
      let glitched = originalText;
      
      if (Math.random() > 0.85) {
        glitched = originalText.split('').map(char => 
          Math.random() > 0.8 ? glitchChars[Math.floor(Math.random() * glitchChars.length)] : char
        ).join('');
        
        setTimeout(() => setGlitchText(originalText), 100);
      }
      
      setGlitchText(glitched);
    }, 200);

    return () => clearInterval(glitchInterval);
  }, []);

  // Scan progress simulation
  useEffect(() => {
    const scanInterval = setInterval(() => {
      setScanProgress(prev => {
        const newProgress = prev + Math.random() * 5;
        return newProgress > 100 ? 0 : newProgress;
      });
    }, 100);

    return () => clearInterval(scanInterval);
  }, []);

  // Alert system
  useEffect(() => {
    const alertInterval = setInterval(() => {
      const alertTypes = [
        'DDOS ATTACK DETECTED',
        'MALWARE SIGNATURE FOUND',
        'UNAUTHORIZED ACCESS ATTEMPT',
        'SUSPICIOUS NETWORK TRAFFIC',
        'PHISHING CAMPAIGN IDENTIFIED',
        'ZERO-DAY EXPLOIT BLOCKED',
        'RANSOMWARE VARIANT DETECTED',
        'ADVANCED PERSISTENT THREAT'
      ];
      
      const newAlert = {
        id: Date.now(),
        message: alertTypes[Math.floor(Math.random() * alertTypes.length)],
        severity: Math.random() > 0.5 ? 'CRITICAL' : 'WARNING',
        timestamp: new Date().toLocaleTimeString()
      };
      
      setAlerts(prev => [newAlert, ...prev.slice(0, 2)]);
    }, 3000);

    return () => clearInterval(alertInterval);
  }, []);

  // Canvas network visualization
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const width = canvas.width = window.innerWidth;
    const height = canvas.height = window.innerHeight;
    
    let animationId;
    
    const animate = () => {
      ctx.clearRect(0, 0, width, height);
      
      // Draw connections
      networkNodes.forEach((node, i) => {
        networkNodes.slice(i + 1).forEach(otherNode => {
          const distance = Math.sqrt(
            Math.pow((node.x - otherNode.x) * width / 100, 2) + 
            Math.pow((node.y - otherNode.y) * height / 100, 2)
          );
          
          if (distance < 200) {
            ctx.beginPath();
            ctx.moveTo(node.x * width / 100, node.y * height / 100);
            ctx.lineTo(otherNode.x * width / 100, otherNode.y * height / 100);
            ctx.strokeStyle = node.status === 'threat' || otherNode.status === 'threat' 
              ? 'rgba(239, 68, 68, 0.3)' 
              : 'rgba(34, 211, 238, 0.1)';
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        });
      });
      
      animationId = requestAnimationFrame(animate);
    };
    
    animate();
    
    return () => {
      if (animationId) cancelAnimationFrame(animationId);
    };
  }, [networkNodes]);

  const stats = [
    { label: 'THREATS NEUTRALIZED', value: threatCount.toLocaleString(), icon: Shield, color: 'text-red-400' },
    { label: 'GLOBAL ENDPOINTS', value: '847,291', icon: Globe, color: 'text-blue-400' },
    { label: 'RESPONSE TIME', value: '0.0003s', icon: Zap, color: 'text-yellow-400' },
    { label: 'AI ACCURACY', value: '99.97%', icon: Brain, color: 'text-purple-400' },
    { label: 'QUANTUM ENCRYPTION', value: '2048-BIT', icon: Lock, color: 'text-green-400' },
    { label: 'ZERO-DAY BLOCKS', value: '4,829', icon: Bug, color: 'text-orange-400' }
  ];

  return (

    <>
    <div className="min-h-screen bg-black text-cyan-400 font-mono overflow-hidden relative">
      {/* Canvas Background */}
      <canvas 
        ref={canvasRef}
        className="absolute inset-0 opacity-20 pointer-events-none"
        style={{ zIndex: 1 }}
      />
      
      {/* Intense Matrix Background */}
      <div className="absolute inset-0 opacity-15" style={{ zIndex: 2 }}>
        {matrixChars.map((char) => (
          <motion.div
            key={char.id}
            className="absolute text-green-400 text-xs font-bold"
            style={{ left: `${char.x}%` }}
            animate={{
              y: ['0vh', '110vh'],
              opacity: [0, 1, 1, 0],
              scale: [0.5, 1, 1, 0.5]
            }}
            transition={{
              duration: 8 / char.speed,
              repeat: Infinity,
              delay: char.delay,
              ease: 'linear'
            }}
          >
            {char.char}
          </motion.div>
        ))}
      </div>

      {/* Multiple Grid Overlays */}
      <div className="absolute inset-0 opacity-10" style={{ zIndex: 3 }}>
        <div className="w-full h-full bg-gradient-to-br from-red-500/20 via-transparent to-cyan-500/20"></div>
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(34,211,238,0.1),transparent_50%)]"></div>
        <div className="absolute inset-0 bg-grid-pattern opacity-30"></div>
        <div className="absolute inset-0 bg-circuit-pattern opacity-20"></div>
      </div>

      {/* Floating Alerts */}
      <AnimatePresence>
        {alerts.map((alert, index) => (
          <motion.div
            key={alert.id}
            initial={{ x: '100vw', opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: '-100vw', opacity: 0 }}
            className={`fixed top-20 right-4 z-50 p-4 border-l-4 backdrop-blur-md ${
              alert.severity === 'CRITICAL' 
                ? 'bg-red-900/50 border-red-400 text-red-100' 
                : 'bg-yellow-900/50 border-yellow-400 text-yellow-100'
            }`}
            style={{ top: `${80 + index * 80}px` }}
          >
            <div className="flex items-center space-x-2">
              <AlertTriangle className="animate-pulse" size={16} />
              <span className="text-xs font-bold">{alert.severity}</span>
            </div>
            <div className="text-xs mt-1">{alert.message}</div>
            <div className="text-xs opacity-60">{alert.timestamp}</div>
          </motion.div>
        ))}
      </AnimatePresence>

      {/* Header */}
      <motion.header 
        initial={{ y: -100, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.8 }}
        className="relative z-40 flex justify-between items-center px-8 py-4 border-b border-cyan-500/50 backdrop-blur-xl bg-black/60"
        style={{ boxShadow: '0 0 50px rgba(34,211,238,0.3)' }}
      >
        <motion.div 
          className="flex items-center space-x-4"
          whileHover={{ scale: 1.05 }}
        >
          <motion.div
            animate={{ 
              rotate: 360,
              boxShadow: ['0 0 20px rgba(34,211,238,0.5)', '0 0 40px rgba(239,68,68,0.5)', '0 0 20px rgba(34,211,238,0.5)']
            }}
            transition={{ 
              rotate: { duration: 4, repeat: Infinity, ease: 'linear' },
              boxShadow: { duration: 2, repeat: Infinity }
            }}
            className="relative"
          >
            <Shield className="text-cyan-400 drop-shadow-[0_0_20px_rgba(34,211,238,0.8)]" size={40} />
            <div className="absolute inset-0 border-2 border-red-500 animate-ping opacity-50"></div>
          </motion.div>
          <div>
            <span className="text-3xl font-bold tracking-[0.5em] text-transparent bg-gradient-to-r from-cyan-400 via-red-500 to-purple-600 bg-clip-text">
              eCyber
            </span>
            <div className="text-xs text-green-400 animate-pulse flex items-center">
              <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
              [{systemStatus}] - DEFCON 2
            </div>
          </div>
        </motion.div>

        <nav className="space-x-8 hidden md:flex text-sm">
          {['THREAT-INTEL', 'NEURAL-NET', 'QUANTUM-SHIELD', 'WAR-ROOM'].map((item, i) => (
            <motion.a
              key={item}
              href={`#${item.toLowerCase()}`}
              className="relative group cursor-pointer"
              whileHover={{ scale: 1.2, textShadow: '0 0 10px rgba(34,211,238,0.8)' }}
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
            >
              <span className="text-cyan-300 hover:text-red-400 transition-colors font-bold">
                {item}
              </span>
              <div className="absolute -bottom-1 left-0 w-0 h-1 bg-gradient-to-r from-cyan-400 via-red-500 to-purple-600 group-hover:w-full transition-all duration-300"></div>
            </motion.a>
          ))}
        </nav>

        <div className="space-x-4 flex items-center">
          <motion.button
            onClick={() => dispatch(setAuthModalState(!isAuthModalOpen))}
            whileHover={{ 
              scale: 1.1, 
              boxShadow: '0 0 30px rgba(239,68,68,0.8)',
              textShadow: '0 0 10px rgba(255,255,255,1)'
            }}
            whileTap={{ scale: 0.9 }}
            className="px-8 py-3 border-2 border-red-500 text-red-400 hover:bg-red-500/20 transition-all duration-300 backdrop-blur-sm font-bold tracking-widest"
          >
            GET IN
          </motion.button>
          <motion.button
            whileHover={{ 
              scale: 1.1, 
              boxShadow: '0 0 50px rgba(34,211,238,1)',
              textShadow: '0 0 10px rgba(0,0,0,1)'
            }}
            whileTap={{ scale: 0.9 }}
            className="px-8 py-3 bg-gradient-to-r from-cyan-500 via-blue-600 to-purple-700 text-black font-bold hover:from-cyan-400 hover:to-purple-600 transition-all duration-300 tracking-widest"
          >
            Get A Demo👍
          </motion.button>
        </div>
      </motion.header>

      {/* Hero Section */}
      <main className="relative z-30 flex flex-col items-center justify-center text-center py-8 px-4">
        <motion.div
          initial={{ scale: 0.3, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 1.5, delay: 0.2 }}
          className="mb-6"
        >
          <h1 className="text-4xl md:text-7xl lg:text-9xl font-bold tracking-wider mb-6 relative">
            <motion.span 
              className="text-transparent bg-gradient-to-r from-red-500 via-cyan-400 to-purple-600 bg-clip-text drop-shadow-[0_0_30px_rgba(34,211,238,0.8)]"
              animate={{ 
                textShadow: ['0 0 20px rgba(239,68,68,0.8)', '0 0 40px rgba(34,211,238,0.8)', '0 0 20px rgba(147,51,234,0.8)', '0 0 20px rgba(239,68,68,0.8)'],
                filter: ['hue-rotate(0deg)', 'hue-rotate(360deg)']
              }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              REAL-TIME
            </motion.span>
            <br />
            <motion.span 
              className="text-transparent bg-gradient-to-r from-purple-600 via-pink-500 to-red-500 bg-clip-text"
              style={{ 
                filter: 'drop-shadow(0 0 30px rgba(239,68,68,0.8))',
                textShadow: '0 0 50px rgba(239,68,68,1)'
              }}
            >
              {glitchText}
            </motion.span>
            <br />
            <motion.span 
              className="text-transparent bg-gradient-to-r from-green-400 via-cyan-400 to-blue-500 bg-clip-text"
              animate={{ 
                textShadow: ['0 0 30px rgba(34,211,238,0.8)', '0 0 60px rgba(34,211,238,1)', '0 0 30px rgba(34,211,238,0.8)']
              }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              NEURAL GRID
            </motion.span>
            
            {/* Glitch overlay */}
            <motion.div
              className="absolute inset-0 bg-gradient-to-r from-red-500/20 to-cyan-500/20"
              animate={{ opacity: [0, 0.3, 0] }}
              transition={{ duration: 0.1, repeat: Infinity, repeatDelay: 2 }}
            />
          </h1>
        </motion.div>

        {/* Live Scan Progress */}
        <motion.div
          initial={{ opacity: 0, width: 0 }}
          animate={{ opacity: 1, width: '100%' }}
          transition={{ delay: 1 }}
          className="w-full max-w-4xl mb-8"
        >
          <div className="flex justify-between text-xs mb-2">
            <span className="text-cyan-400">GLOBAL THREAT SCAN PROGRESS</span>
            <span className="text-green-400">{Math.floor(scanProgress)}%</span>
          </div>
          <div className="w-full bg-gray-800 h-2 relative overflow-hidden">
            <motion.div
              className="h-full bg-gradient-to-r from-red-500 via-yellow-500 to-green-500"
              style={{ width: `${scanProgress}%` }}
              animate={{ 
                boxShadow: ['0 0 10px rgba(34,211,238,0.5)', '0 0 30px rgba(239,68,68,0.8)', '0 0 10px rgba(34,211,238,0.5)']
              }}
              transition={{ duration: 1, repeat: Infinity }}
            />
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-pulse" />
          </div>
        </motion.div>

        {/* Terminal Output */}
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          className="mb-8 w-full max-w-6xl"
        >
          <div className="text-lg text-cyan-300 h-12 flex items-center justify-center">
            <Terminal className="mr-3 text-green-400 animate-pulse" size={24} />
            <span className="text-center">{text}</span>
            <span className="animate-pulse text-red-400 ml-2 text-2xl">█</span>
          </div>
        </motion.div>

        {/* Active Threats */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 1.2 }}
          className="mb-8 w-full max-w-6xl"
        >
          <div className="text-red-400 text-xl font-bold mb-4 flex items-center justify-center">
            <AlertTriangle className="mr-2 animate-pulse" />
            LIVE THREAT FEED
            <AlertTriangle className="ml-2 animate-pulse" />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {activeThreats.map((threat) => (
              <motion.div
                key={threat.id}
                initial={{ opacity: 0, x: -100 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 100 }}
                className={`bg-black/60 backdrop-blur-md border-l-4 p-4 ${
                  threat.severity === 'CRITICAL' 
                    ? 'border-red-500 bg-red-900/20' 
                    : threat.severity === 'HIGH'
                    ? 'border-orange-500 bg-orange-900/20'
                    : 'border-yellow-500 bg-yellow-900/20'
                }`}
              >
                <div className="flex justify-between items-start">
                  <div>
                    <div className={`text-sm font-bold ${
                      threat.severity === 'CRITICAL' ? 'text-red-400' : 
                      threat.severity === 'HIGH' ? 'text-orange-400' : 'text-yellow-400'
                    }`}>
                      {threat.severity} - {threat.type}
                    </div>
                    <div className="text-xs text-cyan-300">Origin: {threat.country}</div>
                    <div className="text-xs text-gray-400">IP: {threat.ip}</div>
                  </div>
                  <Skull className={`${
                    threat.severity === 'CRITICAL' ? 'text-red-400' : 
                    threat.severity === 'HIGH' ? 'text-orange-400' : 'text-yellow-400'
                  } animate-pulse`} size={20} />
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Stats Grid - Enhanced */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 1.4 }}
          className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-12 w-full max-w-7xl"
        >
          {stats.map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 50 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.6 + i * 0.1 }}
              whileHover={{ 
                scale: 1.1, 
                boxShadow: '0 0 50px rgba(34,211,238,0.5)',
                borderColor: 'rgb(239,68,68)',
                rotateY: 10
              }}
              className="bg-black/60 backdrop-blur-xl border border-cyan-500/30 p-6 text-center hover:border-red-400 transition-all duration-300 relative overflow-hidden group"
            >
              <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/10 to-purple-500/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
              >
                <stat.icon className={`mx-auto mb-3 ${stat.color} drop-shadow-lg`} size={28} />
              </motion.div>
              <div className="text-3xl font-bold text-white mb-2 relative z-10">{stat.value}</div>
              <div className="text-xs text-cyan-300 tracking-widest relative z-10">{stat.label}</div>
              
              {/* Animated border */}
              <div className="absolute inset-0 border-2 border-transparent group-hover:border-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            </motion.div>
          ))}
        </motion.div>

        {/* Action Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 2 }}
          className="flex flex-col sm:flex-row gap-8 mb-12"
        >
          <motion.div
            whileHover={{ 
              scale: 1.2, 
              boxShadow: '0 0 80px rgba(239,68,68,1)',
              rotateX: 5
            }}
            whileTap={{ scale: 0.9 }}
          >
            <button className="px-16 py-6 bg-gradient-to-r from-red-600 via-red-500 to-orange-500 text-white font-bold text-xl hover:from-red-500 hover:to-orange-400 transition-all duration-300 shadow-[0_0_50px_rgba(239,68,68,0.8)] tracking-[0.2em] relative overflow-hidden group">
              <span className="relative z-10">INITIATE CYBER WARFARE</span>
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
            </button>
          </motion.div>
          <motion.button
            whileHover={{ 
              scale: 1.2, 
              boxShadow: '0 0 80px rgba(34,211,238,1)',
              rotateX: -5
            }}
            whileTap={{ scale: 0.9 }}
            className="px-16 py-6 border-4 border-cyan-400 text-cyan-400 font-bold text-xl hover:bg-cyan-400/20 transition-all duration-300 tracking-[0.2em] relative overflow-hidden group"
          >
            <span className="relative z-10">NEURAL NETWORK DEMO</span>
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
          </motion.button>
        </motion.div>

        {/* Enhanced Terminal Window */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 2.5 }}
          className="w-full max-w-7xl bg-black/90 backdrop-blur-xl border-2 border-green-500/50 shadow-[0_0_100px_rgba(34,211,238,0.5)] overflow-hidden relative"
        >
          {/* Enhanced Terminal Header */}
          <div className="flex items-center justify-between px-8 py-4 bg-gradient-to-r from-gray-900 via-black to-red-900/50 border-b-2 border-green-500/30 relative">
            <div className="flex items-center space-x-4">
              <div className="flex space-x-3">
                <motion.div 
                  className="w-4 h-4 bg-red-500 rounded-full"
                  animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
                  transition={{ duration: 1, repeat: Infinity }}
                />
                <motion.div 
                  className="w-4 h-4 bg-yellow-500 rounded-full"
                  animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
                  transition={{ duration: 1, repeat: Infinity, delay: 0.3 }}
                />
                <motion.div 
                  className="w-4 h-4 bg-green-500 rounded-full"
                  animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
                  transition={{ duration: 1, repeat: Infinity, delay: 0.6 }}
                />
              </div>
              <span className="text-green-400 font-mono text-lg font-bold tracking-wider">QUANTUM-THREAT-ANALYZER-v9.7.3</span>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              >
                <Cpu className="text-cyan-400" size={20} />
              </motion.div>
            </div>
            <div className="flex items-center space-x-6 text-sm">
              <span className="text-red-400 font-bold">CPU: 98.7%</span>
              <span className="text-yellow-400 font-bold">RAM: 47.2GB</span>
              <span className="text-cyan-400 font-bold">NET: 10.4 Gbps</span>
              <span className="text-purple-400 font-bold">GPU: 99.1%</span>
              <motion.div
                animate={{ opacity: [1, 0.3, 1] }}
                transition={{ duration: 0.5, repeat: Infinity }}
                className="flex items-center space-x-1"
              >
                <div className="w-3 h-3 bg-green-400 rounded-full"></div>
                <span className="text-green-400 font-bold">OPERATIONAL</span>
              </motion.div>
            </div>
            
            {/* Scanning line effect */}
            <motion.div
              className="absolute bottom-0 left-0 h-1 bg-gradient-to-r from-cyan-400 to-red-500"
              animate={{ width: ['0%', '100%', '0%'] }}
              transition={{ duration: 3, repeat: Infinity }}
            />
          </div>
          
          {/* Enhanced Terminal Content */}
          <div className="p-8 text-left text-sm h-96 overflow-y-auto space-y-2 font-mono relative">
            {/* Background scanning effect */}
            <div className="absolute inset-0 opacity-5">
              <motion.div
                className="w-full h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent"
                animate={{ y: [0, 384, 0] }}
                transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
              />
            </div>
            
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 2.7}} className="text-cyan-400 font-bold">
              [QUANTUM] █████████████████████████ 100% Neural network initialized...
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 2.9}} className="text-green-400">
              [AI-CORE] Advanced ML model loaded: quantum-threat-neural-net-v9.7
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.1}} className="text-blue-400">
              [GLOBAL] Monitoring 847,291 endpoints across 195 countries in real-time
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.3}} className="text-purple-400">
              [INTEL] Real-time threat intelligence pipeline: MAXIMUM OVERDRIVE
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.5}} className="text-green-400">
              [DEFENSE] Zero-day exploit detection: QUANTUM-ENABLED
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.7}} className="text-red-400 animate-pulse font-bold">
              [CRITICAL] 247 APT attacks detected and neutralized in last 60 seconds
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 3.9}} className="text-yellow-400 animate-pulse">
              [WARNING] Lazarus Group attempting blockchain infiltration - BLOCKED
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 4.1}} className="text-green-400">
              [SUCCESS] Quantum signature database synced (2,847,291 signatures)
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 4.3}} className="text-cyan-400">
              [BLOCKCHAIN] Quantum-encrypted verification: AUTHENTICATED
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 4.5}} className="text-orange-400 animate-pulse">
              [ALERT] Maze ransomware variant detected - Auto-countermeasures deployed
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 4.7}} className="text-purple-400">
              [NEURAL] Deep learning threat prediction accuracy: 99.97%
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 4.9}} className="text-green-400">
              [STATUS] All quantum defense grids operational - DEFCON 2 ACTIVE
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 5.1}} className="text-red-400 animate-pulse font-bold">
              [BREAKING] Nation-state actor detected - Initiating quantum counterstrike...
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 5.3}} className="text-cyan-400">
              [SYSTEM] Threat response time: 0.0003 milliseconds - NEW RECORD
            </motion.p>
            <motion.p initial={{opacity: 0}} animate={{opacity: 1}} transition={{delay: 5.5}} className="text-green-400 font-bold">
              [VICTORY] All hostile activities neutralized - Network secured
            </motion.p>
          </div>
          
          {/* Terminal scan line */}
          <motion.div
            className="absolute bottom-0 left-0 w-full h-0.5 bg-gradient-to-r from-cyan-400 via-green-400 to-red-400"
            animate={{ 
              boxShadow: ['0 0 10px rgba(34,211,238,0.5)', '0 0 30px rgba(34,211,238,1)', '0 0 10px rgba(34,211,238,0.5)']
            }}
            transition={{ duration: 1, repeat: Infinity }}
          />
        </motion.div>
      </main>

      {/* Enhanced Floating Particles and Effects */}
      <div className="absolute inset-0 pointer-events-none" style={{ zIndex: 5 }}>
        {[...Array(50)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute w-2 h-2 rounded-full"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              backgroundColor: ['#22d3ee', '#ef4444', '#a855f7', '#10b981'][Math.floor(Math.random() * 4)]
            }}
            animate={{
              scale: [0, 2, 0],
              opacity: [0, 1, 0],
              rotate: [0, 360]
            }}
            transition={{
              duration: 4,
              repeat: Infinity,
              delay: Math.random() * 4,
            }}
          />
        ))}
      </div>

      {/* Laser scanning effects */}
      <motion.div
        className="absolute inset-0 pointer-events-none"
        style={{ zIndex: 4 }}
      >
        <motion.div
          className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-red-500 to-transparent opacity-30"
          animate={{ y: ['0vh', '100vh'] }}
          transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
        />
        <motion.div
          className="absolute h-full w-0.5 bg-gradient-to-b from-transparent via-cyan-500 to-transparent opacity-30"
          animate={{ x: ['0vw', '100vw'] }}
          transition={{ duration: 10, repeat: Infinity, ease: 'linear', delay: 2 }}
        />
      </motion.div>

      {/* Enhanced Footer */}
      <motion.footer
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 6 }}
        className="relative z-30 mt-auto py-8 px-8 text-sm border-t-2 border-cyan-500/50 text-center backdrop-blur-xl bg-black/60"
        style={{ boxShadow: '0 0 50px rgba(34,211,238,0.3)' }}
      >
        <div className="flex justify-between items-center">
          <span className="text-cyan-400">
            &copy; {new Date().getFullYear()} eCyber Security Operations Center. 
            <span className="text-red-400 font-bold"> CLASSIFIED - TOP SECRET</span>
          </span>
          <div className="flex items-center space-x-6">
            <motion.div
              animate={{ scale: [1, 1.2, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
              className="flex items-center space-x-2"
            >
              <span className="text-green-400 font-bold">QUANTUM ENCRYPTION ACTIVE</span>
              <motion.div 
                className="w-3 h-3 bg-green-400 rounded-full"
                animate={{ opacity: [1, 0.3, 1] }}
                transition={{ duration: 1, repeat: Infinity }}
              />
            </motion.div>
            <div className="flex items-center space-x-2">
              <span className="text-red-400 font-bold">THREAT LEVEL:</span>
              <span className="text-red-400 font-bold animate-pulse">MAXIMUM</span>
            </div>
          </div>
        </div>
      </motion.footer>

     
      </div>
      <AuthModal/>
      </>
  );
};

export default Index;