
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Terminal, 
  Code, 
  List, 
  Play, 
  Square,
  Globe,
  Database,
  Search,
  Settings,
  ChevronRight,
  Wifi
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Packet, Threat, Stats, ThreatSeverity } from './types';
import { BLACKLISTED_IPS, PYTHON_CODE, REQUIREMENTS_TXT } from './constants';

// --- Sub-components ---

const SeverityBadge: React.FC<{ severity: ThreatSeverity }> = ({ severity }) => {
  const colors = {
    [ThreatSeverity.LOW]: 'bg-blue-900/40 text-blue-400 border-blue-500/50',
    [ThreatSeverity.MEDIUM]: 'bg-yellow-900/40 text-yellow-400 border-yellow-500/50',
    [ThreatSeverity.HIGH]: 'bg-orange-900/40 text-orange-400 border-orange-500/50',
    [ThreatSeverity.CRITICAL]: 'bg-red-900/40 text-red-400 border-red-500/50',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-bold border ${colors[severity]}`}>
      {severity}
    </span>
  );
};

const Header: React.FC<{ isMonitoring: boolean; toggleMonitoring: () => void }> = ({ isMonitoring, toggleMonitoring }) => (
  <header className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
    <div className="flex items-center gap-3">
      <div className="p-2 bg-indigo-600 rounded-lg shadow-lg shadow-indigo-500/20">
        <Shield className="w-6 h-6 text-white" />
      </div>
      <div>
        <h1 className="text-xl font-bold tracking-tight text-white">GuardiaNIDS</h1>
        <p className="text-xs text-slate-400 font-mono">v1.0.2 / Enterprise Security</p>
      </div>
    </div>
    <div className="flex items-center gap-4">
      <div className="hidden md:flex items-center gap-6 px-4 mr-4 border-r border-slate-700">
        <div className="flex flex-col items-end">
          <span className="text-[10px] uppercase text-slate-500 font-bold">Status</span>
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${isMonitoring ? 'bg-emerald-500 animate-pulse' : 'bg-slate-500'}`} />
            <span className={`text-sm font-medium ${isMonitoring ? 'text-emerald-400' : 'text-slate-400'}`}>
              {isMonitoring ? 'System Active' : 'Suspended'}
            </span>
          </div>
        </div>
      </div>
      <button 
        onClick={toggleMonitoring}
        className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-bold text-sm transition-all duration-300 ${
          isMonitoring 
            ? 'bg-red-500/10 text-red-400 border border-red-500/50 hover:bg-red-500/20' 
            : 'bg-indigo-600 text-white hover:bg-indigo-500 shadow-lg shadow-indigo-500/30'
        }`}
      >
        {isMonitoring ? <><Square className="w-4 h-4 fill-current" /> Stop Capture</> : <><Play className="w-4 h-4 fill-current" /> Start Monitor</>}
      </button>
    </div>
  </header>
);

const Sidebar: React.FC<{ activeTab: string; setActiveTab: (tab: string) => void }> = ({ activeTab, setActiveTab }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'live', label: 'Packet Stream', icon: Wifi },
    { id: 'threats', label: 'Threat Log', icon: AlertTriangle },
    { id: 'code', label: 'Python Source', icon: Code },
    { id: 'settings', label: 'Configuration', icon: Settings },
  ];

  return (
    <nav className="w-64 border-r border-slate-800 hidden lg:block h-[calc(100vh-73px)] sticky top-[73px] bg-slate-900/30 p-4">
      <div className="space-y-1">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-colors ${
                isActive 
                  ? 'bg-indigo-600/10 text-indigo-400' 
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <Icon className={`w-5 h-5 ${isActive ? 'text-indigo-400' : 'text-slate-500'}`} />
              {item.label}
            </button>
          );
        })}
      </div>
      <div className="absolute bottom-8 left-4 right-4">
        <div className="p-4 rounded-2xl bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700/50">
          <p className="text-xs font-bold text-slate-300 mb-2 flex items-center gap-2">
            <Globe className="w-3 h-3" /> Network Health
          </p>
          <div className="w-full bg-slate-700 h-1.5 rounded-full overflow-hidden">
            <div className="bg-emerald-500 h-full w-[88%] shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
          </div>
          <p className="text-[10px] text-slate-500 mt-2">Optimal coverage across 4 nodes</p>
        </div>
      </div>
    </nav>
  );
};

// --- Main App ---

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [chartData, setChartData] = useState<{ time: string; count: number }[]>([]);
  const [stats, setStats] = useState<Stats>({
    packetsProcessed: 0,
    threatsDetected: 0,
    activeConnections: 0,
    bandwidthMbps: 0,
  });

  const packetIntervalRef = useRef<number | null>(null);

  // Simulation Logic
  const generatePacket = useCallback(() => {
    const protocols: any[] = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP'];
    const ips = ['192.168.1.1', '192.168.1.50', '10.0.0.15', '172.16.0.4', ...BLACKLISTED_IPS];
    const ports = [80, 443, 22, 21, 3306, 5432, 8080, 12345, 6667];
    
    const srcIp = ips[Math.floor(Math.random() * ips.length)];
    const dstIp = '192.168.1.100'; // Target server
    const destPort = ports[Math.floor(Math.random() * ports.length)];
    const protocol = protocols[Math.floor(Math.random() * protocols.length)];

    const newPacket: Packet = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toLocaleTimeString(),
      sourceIp: srcIp,
      destIp: dstIp,
      sourcePort: Math.floor(Math.random() * 65535),
      destPort: destPort,
      protocol: protocol,
      size: Math.floor(Math.random() * 1500),
    };

    setPackets(prev => [newPacket, ...prev].slice(0, 50));
    setStats(prev => ({
      ...prev,
      packetsProcessed: prev.packetsProcessed + 1,
      bandwidthMbps: parseFloat((Math.random() * 25 + 5).toFixed(2)),
      activeConnections: Math.floor(Math.random() * 50 + 10)
    }));

    // Threat Detection Simulation
    if (BLACKLISTED_IPS.includes(srcIp)) {
      triggerThreat({
        type: 'Blacklisted IP',
        sourceIp: srcIp,
        severity: ThreatSeverity.CRITICAL,
        description: `Traffic detected from known malicious source ${srcIp}`
      });
    }

    // Small chance for Port Scan
    if (Math.random() > 0.98) {
      triggerThreat({
        type: 'Port Scan',
        sourceIp: srcIp,
        severity: ThreatSeverity.HIGH,
        description: `Multiple sequential port connections detected from ${srcIp}`
      });
    }

    // Small chance for Failed Login
    if (destPort === 22 && Math.random() > 0.95) {
      triggerThreat({
        type: 'Failed Login',
        sourceIp: srcIp,
        severity: ThreatSeverity.MEDIUM,
        description: `Burst of connection attempts to SSH port (22)`
      });
    }
  }, []);

  const triggerThreat = (threatData: Omit<Threat, 'id' | 'timestamp'>) => {
    const newThreat: Threat = {
      ...threatData,
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toLocaleTimeString(),
    };
    setThreats(prev => [newThreat, ...prev].slice(0, 20));
    setStats(prev => ({ ...prev, threatsDetected: prev.threatsDetected + 1 }));
  };

  useEffect(() => {
    if (isMonitoring) {
      packetIntervalRef.current = window.setInterval(generatePacket, 800);
    } else {
      if (packetIntervalRef.current) clearInterval(packetIntervalRef.current);
    }
    return () => {
      if (packetIntervalRef.current) clearInterval(packetIntervalRef.current);
    };
  }, [isMonitoring, generatePacket]);

  useEffect(() => {
    const interval = setInterval(() => {
      setChartData(prev => {
        const newData = [...prev, { time: new Date().toLocaleTimeString(), count: Math.floor(Math.random() * 100) }];
        return newData.slice(-15);
      });
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const toggleMonitoring = () => setIsMonitoring(!isMonitoring);

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
              <StatCard label="Packets Analyzed" value={stats.packetsProcessed.toLocaleString()} icon={Wifi} color="text-blue-400" />
              <StatCard label="Threats Blocked" value={stats.threatsDetected} icon={AlertTriangle} color="text-red-400" />
              <StatCard label="Active Sessions" value={stats.activeConnections} icon={Database} color="text-emerald-400" />
              <StatCard label="Throughput" value={`${stats.bandwidthMbps} Mbps`} icon={Activity} color="text-amber-400" />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Traffic Chart */}
              <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="font-bold text-slate-200">Traffic Velocity</h3>
                  <div className="flex gap-2">
                    <span className="flex items-center gap-1.5 text-xs text-indigo-400 font-medium">
                      <div className="w-2 h-2 rounded-full bg-indigo-500"></div> Real-time
                    </span>
                  </div>
                </div>
                <div className="h-[300px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                      <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} hide />
                      <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                        itemStyle={{ color: '#818cf8', fontWeight: 'bold' }}
                      />
                      <Area type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={3} fillOpacity={1} fill="url(#colorCount)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Critical Threats List */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
                <h3 className="font-bold text-slate-200 mb-4 flex items-center justify-between">
                  Active Threats
                  <span className="text-xs font-normal text-slate-500">Last 10 detected</span>
                </h3>
                <div className="space-y-4 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                  {threats.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center text-slate-500 py-12">
                      <Shield className="w-12 h-12 mb-3 opacity-20" />
                      <p className="text-sm">No threats detected</p>
                    </div>
                  ) : (
                    threats.map((threat) => (
                      <div key={threat.id} className="p-3 bg-slate-800/40 rounded-xl border border-slate-700/50 hover:border-indigo-500/30 transition-colors">
                        <div className="flex justify-between items-start mb-2">
                          <SeverityBadge severity={threat.severity} />
                          <span className="text-[10px] text-slate-500 font-mono">{threat.timestamp}</span>
                        </div>
                        <p className="text-sm font-bold text-slate-300">{threat.type}</p>
                        <p className="text-xs text-slate-500 mt-1">{threat.sourceIp}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        );
      case 'live':
        return (
          <div className="bg-slate-900/50 border border-slate-800 rounded-2xl overflow-hidden flex flex-col h-[70vh]">
            <div className="p-4 border-b border-slate-800 bg-slate-900/80 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-indigo-400" />
                <h3 className="font-bold text-slate-200 text-sm">Real-time Packet Capture</h3>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 px-2 py-1 bg-slate-800 rounded text-[10px] font-mono text-slate-400">
                  <div className="w-1.5 h-1.5 rounded-full bg-emerald-500"></div> SNIFFING ETH0
                </div>
              </div>
            </div>
            <div className="flex-1 overflow-auto p-4 custom-scrollbar bg-slate-950 font-mono text-xs">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-slate-950 text-slate-500 uppercase text-[10px] tracking-wider font-bold">
                  <tr>
                    <th className="pb-3 px-2">Timestamp</th>
                    <th className="pb-3 px-2">Source</th>
                    <th className="pb-3 px-2">Destination</th>
                    <th className="pb-3 px-2">Proto</th>
                    <th className="pb-3 px-2">Port</th>
                    <th className="pb-3 px-2">Size</th>
                  </tr>
                </thead>
                <tbody className="text-slate-300">
                  {packets.map((pkt) => (
                    <tr key={pkt.id} className="border-b border-slate-900/50 hover:bg-slate-900 transition-colors">
                      <td className="py-2 px-2 text-slate-500">{pkt.timestamp}</td>
                      <td className={`py-2 px-2 ${BLACKLISTED_IPS.includes(pkt.sourceIp) ? 'text-red-400 font-bold' : 'text-indigo-400'}`}>{pkt.sourceIp}</td>
                      <td className="py-2 px-2">{pkt.destIp}</td>
                      <td className="py-2 px-2 text-emerald-400">{pkt.protocol}</td>
                      <td className="py-2 px-2 text-amber-400">{pkt.destPort}</td>
                      <td className="py-2 px-2 text-slate-500">{pkt.size}B</td>
                    </tr>
                  ))}
                  {packets.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-20 text-center text-slate-600 italic">Waiting for traffic...</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        );
      case 'threats':
        return (
          <div className="bg-slate-900/50 border border-slate-800 rounded-2xl overflow-hidden">
             <div className="p-6 border-b border-slate-800">
                <h3 className="text-lg font-bold text-slate-200">Incident Report Log</h3>
                <p className="text-sm text-slate-500">Review all detected suspicious activities and network breaches.</p>
             </div>
             <div className="overflow-x-auto">
               <table className="w-full text-left border-collapse">
                 <thead className="bg-slate-950/50 text-slate-500 uppercase text-[10px] tracking-wider font-bold">
                   <tr>
                     <th className="p-4">Time</th>
                     <th className="p-4">Severity</th>
                     <th className="p-4">Type</th>
                     <th className="p-4">Attacker IP</th>
                     <th className="p-4">Description</th>
                   </tr>
                 </thead>
                 <tbody className="divide-y divide-slate-800">
                   {threats.map((threat) => (
                     <tr key={threat.id} className="hover:bg-slate-800/30 transition-colors">
                       <td className="p-4 text-xs font-mono text-slate-500">{threat.timestamp}</td>
                       <td className="p-4"><SeverityBadge severity={threat.severity} /></td>
                       <td className="p-4 text-sm font-bold text-slate-300">{threat.type}</td>
                       <td className="p-4 text-sm font-mono text-indigo-400">{threat.sourceIp}</td>
                       <td className="p-4 text-xs text-slate-400 max-w-xs">{threat.description}</td>
                     </tr>
                   ))}
                   {threats.length === 0 && (
                     <tr>
                       <td colSpan={5} className="p-12 text-center text-slate-600">No security incidents on record.</td>
                     </tr>
                   )}
                 </tbody>
               </table>
             </div>
          </div>
        );
      case 'code':
        return (
          <div className="space-y-6">
            <div className="bg-indigo-600/10 border border-indigo-500/20 p-6 rounded-2xl">
              <h3 className="text-indigo-400 font-bold mb-2 flex items-center gap-2">
                <Code className="w-5 h-5" /> Local Implementation Guide
              </h3>
              <p className="text-sm text-slate-300 mb-4">
                To run GuardiaNIDS on your machine, you need Python installed with root/administrator privileges to access raw network sockets.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-900 p-4 rounded-xl border border-slate-800">
                   <h4 className="text-xs font-bold text-slate-500 uppercase mb-2">Step 1: Install Dependencies</h4>
                   <pre className="text-xs text-indigo-300 font-mono">pip install -r requirements.txt</pre>
                </div>
                <div className="bg-slate-900 p-4 rounded-xl border border-slate-800">
                   <h4 className="text-xs font-bold text-slate-500 uppercase mb-2">Step 2: Run Detector</h4>
                   <pre className="text-xs text-indigo-300 font-mono">sudo python nids_core.py</pre>
                </div>
              </div>
            </div>

            <div className="bg-slate-900/50 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="flex items-center justify-between p-4 bg-slate-900 border-b border-slate-800">
                <div className="flex items-center gap-4">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-500/50"></div>
                    <div className="w-3 h-3 rounded-full bg-yellow-500/50"></div>
                    <div className="w-3 h-3 rounded-full bg-emerald-500/50"></div>
                  </div>
                  <span className="text-xs font-mono text-slate-500">nids_core.py</span>
                </div>
                <button 
                  onClick={() => navigator.clipboard.writeText(PYTHON_CODE)}
                  className="text-xs font-bold text-indigo-400 hover:text-indigo-300 transition-colors"
                >
                  Copy Code
                </button>
              </div>
              <div className="p-6 bg-slate-950 overflow-x-auto max-h-[500px] custom-scrollbar">
                <pre className="text-xs font-mono text-slate-400 leading-relaxed whitespace-pre">
                  {PYTHON_CODE}
                </pre>
              </div>
            </div>

            <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6">
              <h4 className="text-sm font-bold text-slate-200 mb-3">requirements.txt</h4>
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                <pre className="text-xs font-mono text-slate-500">{REQUIREMENTS_TXT}</pre>
              </div>
            </div>
          </div>
        );
      default:
        return (
          <div className="flex flex-col items-center justify-center py-32 text-slate-500">
             <Settings className="w-16 h-16 mb-4 opacity-10 animate-spin-slow" />
             <p>Component under development...</p>
          </div>
        );
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col">
      <Header isMonitoring={isMonitoring} toggleMonitoring={toggleMonitoring} />
      
      <div className="flex flex-1 relative">
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
        
        <main className="flex-1 p-6 lg:p-10 max-w-7xl mx-auto w-full">
          <div className="mb-8">
            <h2 className="text-3xl font-extrabold text-white mb-2">
              {activeTab.charAt(0).toUpperCase() + activeTab.slice(1)} View
            </h2>
            <div className="flex items-center gap-2 text-sm text-slate-500">
              <span className="hover:text-slate-300 cursor-pointer">Security Center</span>
              <ChevronRight className="w-4 h-4" />
              <span className="text-indigo-400 capitalize">{activeTab}</span>
            </div>
          </div>

          {renderContent()}
        </main>
      </div>

      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #475569; }
        @keyframes spin-slow {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .animate-spin-slow { animation: spin-slow 8s linear infinite; }
      `}</style>
    </div>
  );
}

// Helper Card Component
const StatCard: React.FC<{ label: string; value: string | number; icon: any; color: string }> = ({ label, value, icon: Icon, color }) => (
  <div className="bg-slate-900/50 border border-slate-800 p-5 rounded-2xl hover:border-slate-700 transition-all hover:translate-y-[-2px]">
    <div className="flex items-center gap-3 mb-3">
      <div className={`p-2 rounded-lg bg-slate-800 ${color}`}>
        <Icon className="w-5 h-5" />
      </div>
      <span className="text-xs font-bold uppercase tracking-wider text-slate-500">{label}</span>
    </div>
    <div className="text-2xl font-bold text-slate-100">{value}</div>
  </div>
);
