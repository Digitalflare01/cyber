import React, { useState } from 'react';
import { Shield, Smartphone, Globe, Router, Database, Code, Activity, Menu, X, CheckCircle, AlertTriangle, Info } from 'lucide-react';
import axios from 'axios';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}

export default function App() {
  const [activeTab, setActiveTab] = useState('web');
  const [isSidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="min-h-screen bg-brand-black text-brand-white flex overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className={cn(
        "fixed inset-y-0 left-0 z-50 w-64 bg-brand-dark border-r border-brand-gray transform transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0",
        isSidebarOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="h-full flex flex-col">
          <div className="flex items-center justify-between p-6 border-b border-brand-gray">
            <div className="flex items-center gap-3 text-brand-white">
              <Shield className="w-8 h-8 opacity-90" />
              <span className="text-xl font-bold tracking-wider uppercase text-shadow-sm">Orchestrator</span>
            </div>
            <button onClick={() => setSidebarOpen(false)} className="lg:hidden text-gray-400 hover:text-white">
              <X className="w-6 h-6" />
            </button>
          </div>
          
          <nav className="flex-1 overflow-y-auto py-6 px-4 space-y-2">
            <div className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-4 px-2">Engines</div>
            
            <SidebarItem 
              icon={<Globe />} label="Web App Scanner" 
              active={activeTab === 'web'} onClick={() => setActiveTab('web')} 
            />
            <SidebarItem 
              icon={<Smartphone />} label="Mobile Analyzer" 
              active={activeTab === 'mobile'} onClick={() => setActiveTab('mobile')} 
            />
            <SidebarItem 
              icon={<Router />} label="IoT / Network Scan" 
              active={activeTab === 'iot'} onClick={() => setActiveTab('iot')} 
            />
            <SidebarItem 
              icon={<Code />} label="Software Analysis" 
              active={activeTab === 'software'} onClick={() => setActiveTab('software')} 
            />
            
            <div className="mt-8 mb-4 border-t border-brand-gray pt-6 px-2 text-xs font-semibold text-gray-500 uppercase tracking-widest">Dashboard</div>
            <SidebarItem 
              icon={<Database />} label="Scan History" 
              active={activeTab === 'history'} onClick={() => setActiveTab('history')} 
            />
          </nav>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden relative">
        <header className="h-20 bg-brand-black/90 backdrop-blur-md border-b border-brand-gray flex items-center px-6 lg:px-10 justify-between sticky top-0 z-40">
          <div className="flex items-center gap-4">
            <button onClick={() => setSidebarOpen(true)} className="lg:hidden text-gray-400 hover:text-white">
              <Menu className="w-6 h-6" />
            </button>
            <h1 className="text-2xl font-light tracking-wide flex items-center gap-3">
              <Activity className="w-5 h-5 text-gray-400" />
              Dynamic Application Security Testing
            </h1>
          </div>
          <div className="flex items-center gap-4">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse hidden sm:block"></div>
            <span className="text-sm text-gray-400 hidden sm:block">Engines Online</span>
            <div className="h-10 w-10 bg-brand-white text-brand-black rounded-full flex items-center justify-center font-bold ml-4">
              AD
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-6 lg:p-10 relative">
          {/* Ambient Glow */}
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-brand-white/5 rounded-full blur-[100px] pointer-events-none"></div>
          
          <div className="max-w-6xl mx-auto relative z-10 glass-panel p-8">
            {activeTab !== 'history' ? (
              <ScannerModule type={activeTab} />
            ) : (
              <HistoryModule />
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

function SidebarItem({ icon, label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 group text-left",
        active 
          ? "bg-brand-white text-brand-black shadow-lg" 
          : "text-gray-400 hover:bg-brand-gray hover:text-brand-white"
      )}
    >
      <span className={cn(
        "transition-colors duration-200",
        active ? "text-brand-black" : "text-gray-500 group-hover:text-brand-white"
      )}>
        {React.cloneElement(icon, { size: 18 })}
      </span>
      {label}
    </button>
  );
}

function ScannerModule({ type }) {
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState(null);

  const config = {
    web: { title: 'Web App Scanner', icon: <Globe className="w-6 h-6"/>, placeholder: 'https://example.com', desc: 'DAST via ZAP / Nuclei Engine' },
    mobile: { title: 'Mobile Analyzer', icon: <Smartphone className="w-6 h-6"/>, placeholder: 'example_app.apk', desc: 'SAST via MobSF Architecture' },
    iot: { title: 'IoT & Network Scan', icon: <Router className="w-6 h-6"/>, placeholder: '192.168.1.100', desc: 'Port mapping via Nmap / OpenVAS' },
    software: { title: 'Software Analysis', icon: <Code className="w-6 h-6"/>, placeholder: 'apache:http_server:2.4.49', desc: 'CVE Matching via NVD API' }
  }[type];

  const handleScan = async (e) => {
    e.preventDefault();
    if (!target) return;
    
    setIsScanning(true);
    setResults(null);
    
    try {
      // Assuming PHP API is running on localhost/cyber/backend/api
      const apiBase = window.location.hostname === 'localhost' ? 'http://localhost/cyber/backend/api' : '/cyber/backend/api';
      
      const res = await axios.post(`${apiBase}/scan/start`, {
        type: type,
        identifier: target,
        name: `${config.title} - ${target}`
      });
      
      if (res.data.scan_id) {
        // Fetch results generated
        const resData = await axios.get(`${apiBase}/scan/results?id=${res.data.scan_id}`);
        setResults(resData.data);
      }
    } catch (error) {
      console.error(error);
      alert('Error triggering scan: ' + (error.response?.data?.error || error.message));
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center gap-4 mb-8 border-b border-brand-gray pb-6">
        <div className="p-3 bg-brand-gray rounded-xl border border-gray-700">
          {config.icon}
        </div>
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">{config.title}</h2>
          <p className="text-gray-400 mt-1">{config.desc}</p>
        </div>
      </div>

      <form onSubmit={handleScan} className="flex flex-col gap-6 max-w-2xl">
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-2">Target Identifier</label>
          <div className="flex gap-4">
            <input 
              type="text" 
              className="input-field shadow-inner" 
              placeholder={config.placeholder}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={isScanning}
            />
            <button type="submit" className="btn-primary whitespace-nowrap flex items-center gap-2 group" disabled={isScanning || !target}>
              {isScanning ? (
                <>
                  <div className="w-4 h-4 rounded-full border-2 border-brand-black border-t-transparent animate-spin"></div>
                  Analyzing...
                </>
              ) : (
                <>Launch Engine</>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Results View */}
      {results && (
        <div className="mt-12 pt-8 border-t border-brand-gray animate-in fade-in duration-500">
          <h3 className="text-xl font-medium mb-6">Orchestrator Output</h3>
          
          <div className="grid gap-6">
            {results.findings?.length > 0 ? results.findings.map((vuln, idx) => (
              <VulnerabilityCard key={idx} vuln={vuln} />
            )) : (
              <div className="p-8 border border-brand-gray rounded-xl bg-brand-dark/50 text-center flex flex-col items-center justify-center">
                <CheckCircle className="w-12 h-12 text-gray-600 mb-4" />
                <h4 className="text-lg font-medium text-gray-300">No vulnerabilities detected.</h4>
                <p className="text-gray-500 mt-2">The engine completed analysis with zero critical findings.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function VulnerabilityCard({ vuln }) {
  const isCritical = vuln.severity === 'critical' || vuln.severity === 'high';
  return (
    <div className="bg-brand-black border border-brand-gray rounded-xl overflow-hidden hover:border-gray-500 transition-colors duration-300">
      <div className="px-6 py-4 flex items-center justify-between border-b border-brand-gray bg-brand-dark/50">
        <div className="flex items-center gap-3">
          {isCritical ? (
            <AlertTriangle className="w-5 h-5 text-gray-300" />
          ) : (
             <Info className="w-5 h-5 text-gray-400" />
          )}
          <h4 className="font-semibold text-lg">{vuln.title}</h4>
        </div>
        <div className="flex gap-3 items-center">
          {vuln.cve_id && (
            <span className="px-3 py-1 bg-brand-black border border-brand-gray rounded-full text-xs font-mono text-gray-300">
              {vuln.cve_id}
            </span>
          )}
          <span className={cn(
            "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider text-brand-black",
            vuln.severity === 'critical' ? 'bg-brand-white' : 
            vuln.severity === 'high' ? 'bg-gray-300' : 'bg-gray-500 text-white'
          )}>
            {vuln.severity}
          </span>
        </div>
      </div>
      
      <div className="p-6">
        <p className="text-gray-300 text-sm leading-relaxed mb-6">
          {vuln.description}
        </p>
        
        {vuln.remediation_snippet && (
          <div className="bg-brand-dark border border-brand-gray rounded-lg p-5">
            <div className="text-sm font-semibold tracking-wider text-gray-400 uppercase mb-3 flex items-center gap-2">
              <Code className="w-4 h-4" />
              Remediation / Patch Code
            </div>
            <pre className="text-sm font-mono text-gray-200 whitespace-pre-wrap leading-relaxed">
              {vuln.remediation_snippet}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

function HistoryModule() {
  const [history, setHistory] = useState([]);
  
  React.useEffect(() => {
    const fetchHistory = async () => {
      try {
        const apiBase = window.location.hostname === 'localhost' ? 'http://localhost/cyber/backend/api' : '/cyber/backend/api';
        const res = await axios.get(`${apiBase}/history`);
        setHistory(res.data.history || []);
      } catch(e) { console.error('History fetch failed', e); }
    };
    fetchHistory();
  }, []);

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
       <div className="flex items-center gap-4 mb-8 border-b border-brand-gray pb-6">
        <div className="p-3 bg-brand-gray rounded-xl border border-gray-700">
          <Database className="w-6 h-6"/>
        </div>
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">Scan History</h2>
          <p className="text-gray-400 mt-1">Global audit logs of all triggered engine actions</p>
        </div>
      </div>

      <div className="w-full overflow-x-auto">
        <table className="w-full text-sm text-left text-gray-300 border-collapse">
          <thead className="text-xs uppercase bg-brand-dark text-gray-500 border-b border-brand-gray">
            <tr>
              <th className="px-6 py-4 font-semibold">ID</th>
              <th className="px-6 py-4 font-semibold">Target</th>
              <th className="px-6 py-4 font-semibold">Engine</th>
              <th className="px-6 py-4 font-semibold">Findings</th>
              <th className="px-6 py-4 font-semibold">Date</th>
            </tr>
          </thead>
          <tbody>
            {history.map((h, i) => (
               <tr key={i} className="border-b border-brand-gray/50 hover:bg-brand-dark/30 transition-colors">
                  <td className="px-6 py-4 font-mono">#{h.id}</td>
                  <td className="px-6 py-4 font-medium">{h.identifier}</td>
                  <td className="px-6 py-4">
                    <span className="px-2.5 py-1 bg-brand-gray rounded-md text-xs font-mono">{h.type.toUpperCase()}</span>
                  </td>
                  <td className="px-6 py-4">
                    {h.finding_count > 0 ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-brand-white text-brand-black rounded-full text-xs font-bold">
                        <AlertTriangle className="w-3 h-3"/> {h.finding_count} Found
                      </span>
                    ) : (
                      <span className="text-gray-500">Clean</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-gray-500">{new Date(h.start_time).toLocaleString()}</td>
               </tr>
            ))}
            {history.length === 0 && (
              <tr>
                <td colSpan="5" className="px-6 py-12 text-center text-gray-500 bg-brand-dark/20">
                  No scanning history available.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
