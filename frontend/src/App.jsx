import React, { useState, useEffect } from 'react';
import { Mail, Shield, Network, FileText, Settings, Activity } from 'lucide-react';
import FileUploader from './components/FileUploader';
import AnalysisResults from './components/AnalysisResults';
import AttributionGraphView from './components/AttributionGraphView';
import QueryConsole from './components/QueryConsole';

export default function App() {
  const [activeTab, setActiveTab] = useState('analyze');
  const [apiStatus, setApiStatus] = useState(false);
  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [caughtCount, setCaughtCount] = useState(18);

  // Check API health status
  const checkHealth = async () => {
    try {
      const resp = await fetch('http://127.0.0.1:8000/health');
      if (resp.ok) {
        setApiStatus(true);
      } else {
        setApiStatus(false);
      }
    } catch (err) {
      setApiStatus(false);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleAnalyzeFile = async (file) => {
    setLoading(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const resp = await fetch('http://127.0.0.1:8000/analyze?offline=true&lightweight=true', {
        method: 'POST',
        body: formData,
      });

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || `Server error HTTP ${resp.status}`);
      }

      const result = await resp.json();
      setAnalysisData(result);
      // Increment caught count if threat
      if (result.verdict?.threat_score >= 50) {
        setCaughtCount(prev => prev + 1);
      }
    } catch (err) {
      console.error('Analysis error:', err);
      setError(err.message || 'Failed to analyze email payload. Ensure API server is online.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#FBF7F1] text-[#3A362F] flex font-sans selection:bg-[#C97B4A]/10 selection:text-[#C97B4A]">
      
      {/* 1. Left Sidebar */}
      <aside className="w-[190px] bg-[#F3ECE0] border-r border-[#EDE6DA] flex flex-col justify-between p-4 flex-shrink-0">
        <div className="space-y-6">
          
          {/* Logo Mark & Wordmark */}
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 bg-[#C97B4A] rounded-lg flex items-center justify-center text-white flex-shrink-0">
              <Shield className="w-4.5 h-4.5 stroke-[1.5]" />
            </div>
            <div>
              <span className="font-serif text-[15px] font-normal tracking-tight text-[#3A362F]">
                SentinelMail
              </span>
              
              {/* API Status Dot */}
              <div className="flex items-center space-x-1 mt-0.5">
                <span className={`w-1.5 h-1.5 rounded-full ${apiStatus ? 'bg-[#7A8B6F]' : 'bg-[#C1654F]'}`} />
                <span className="text-[10px] text-[#8A8378] font-mono leading-none">
                  {apiStatus ? 'connected' : 'offline'}
                </span>
              </div>
            </div>
          </div>

          {/* Navigation Items */}
          <nav className="flex flex-col space-y-1">
            {[
              { id: 'analyze', label: 'Analyze', icon: <Mail className="w-4 h-4" /> },
              { id: 'campaigns', label: 'Campaigns', icon: <Network className="w-4 h-4" /> },
              { id: 'reports', label: 'Reports', icon: <FileText className="w-4 h-4" /> },
              { id: 'settings', label: 'Settings', icon: <Settings className="w-4 h-4" />, inactive: true },
            ].map((item) => {
              const isActive = activeTab === item.id;
              if (item.inactive) {
                return (
                  <div
                    key={item.id}
                    className="flex items-center space-x-2.5 px-3 py-2 text-[12.5px] text-[#8A8378] cursor-not-allowed opacity-60"
                  >
                    <span className="flex-shrink-0">{item.icon}</span>
                    <span>{item.label}</span>
                  </div>
                );
              }
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center space-x-2.5 px-3 py-2 text-[12.5px] rounded-lg transition-all text-left ${
                    isActive
                      ? 'bg-white border border-[#EDE6DA] text-[#C97B4A] font-medium shadow-none'
                      : 'text-[#8A8378] hover:text-[#3A362F] hover:bg-white/40'
                  }`}
                >
                  <span className={`flex-shrink-0 ${isActive ? 'text-[#C97B4A]' : 'text-[#8A8378]'}`}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Bottom Pinned Stat Card */}
        <div
          className="bg-white border border-[#EDE6DA] p-3 rounded-lg text-center select-none"
          style={{ transform: 'rotate(-0.3deg)' }}
        >
          <span className="text-[11px] text-[#8A8378] block font-mono">This week</span>
          <span className="text-[13px] font-serif text-[#3A362F] mt-0.5 block">
            {caughtCount} threats caught
          </span>
        </div>
      </aside>

      {/* Main Workspace */}
      <div className="flex-1 flex flex-col min-w-0">
        <div className="flex-1 flex p-8 gap-8">
          
          {/* 2. Main Content Area */}
          <main className="flex-1 min-w-0 space-y-6">
            
            {activeTab === 'analyze' && (
              <div className="space-y-6">
                
                {/* Conversational Heading */}
                <div className="text-left">
                  <h2 className="font-serif text-[21px] text-[#3A362F] leading-tight">
                    {analysisData
                      ? `Analysis complete for ${analysisData.filename || 'uploaded file'}`
                      : 'Good morning — let\'s review security status today'}
                  </h2>
                  <p className="text-[13px] text-[#8A8378] mt-1">
                    Upload raw EML message files for deep header parsing, NLP sentiment checks, and quishing detection.
                  </p>
                </div>

                {/* Upload Card component */}
                <FileUploader onAnalyze={handleAnalyzeFile} isLoading={loading} error={error} />
                
                {/* Analysis Results */}
                <AnalysisResults data={analysisData} />
              </div>
            )}

            {activeTab === 'campaigns' && (
              <div className="space-y-6">
                <div className="text-left">
                  <h2 className="font-serif text-[21px] text-[#3A362F] leading-tight">
                    Threat Infrastructure Graph
                  </h2>
                  <p className="text-[13px] text-[#8A8378] mt-1">
                    Visualise campaign clusters, linked sender domains, dynamic hop paths, and historical actor matches.
                  </p>
                </div>
                <AttributionGraphView />
              </div>
            )}

            {activeTab === 'reports' && (
              <div className="space-y-6">
                <div className="text-left">
                  <h2 className="font-serif text-[21px] text-[#3A362F] leading-tight">
                    Forensic Query Console
                  </h2>
                  <p className="text-[13px] text-[#8A8378] mt-1">
                    Query the local forensic archive using natural language or extract specific campaign indicators.
                  </p>
                </div>
                <QueryConsole />
              </div>
            )}

          </main>

          {/* 3. Right Sidebar Panel */}
          <aside className="w-[230px] flex-shrink-0 hidden xl:block space-y-6">
            
            {/* Campaign map Card */}
            <div
              className="bg-white border border-[#EDE6DA] p-4 rounded-xl text-left"
              style={{ transform: 'rotate(0.3deg)' }}
            >
              <h3 className="font-serif text-[14px] text-[#3A362F] mb-3">
                Campaign Map
              </h3>
              
              {/* Simplified scatter plot scatter */}
              <div className="h-32 bg-[#F3ECE0]/40 rounded-lg border border-[#EDE6DA] relative overflow-hidden flex items-center justify-center">
                {/* Threat cluster (brick red) */}
                <div className="absolute w-2 h-2 rounded-full bg-[#C1654F] top-12 left-10 opacity-80" />
                <div className="absolute w-2.5 h-2.5 rounded-full bg-[#C1654F] top-16 left-16 opacity-90" />
                <div className="absolute w-2 h-2 rounded-full bg-[#C1654F] top-10 left-20 opacity-70" />
                <div className="absolute w-1.5 h-1.5 rounded-full bg-[#C1654F] top-20 left-12 opacity-80" />
                <div className="absolute w-2 h-2 rounded-full bg-[#C1654F] top-8 left-14 opacity-75" />
                
                {/* Outlier (sage green) */}
                <div className="absolute w-2.5 h-2.5 rounded-full bg-[#7A8B6F] top-24 left-36 animate-pulse" />
                
                {/* Connecting delicate lines */}
                <svg className="absolute inset-0 w-full h-full pointer-events-none" xmlns="http://www.w3.org/2000/svg">
                  <line x1="40" y1="48" x2="64" y2="64" stroke="#EDE6DA" strokeWidth="0.75" />
                  <line x1="80" y1="40" x2="64" y2="64" stroke="#EDE6DA" strokeWidth="0.75" />
                  <line x1="48" y1="80" x2="64" y2="64" stroke="#EDE6DA" strokeWidth="0.75" />
                  <line x1="56" y1="32" x2="64" y2="64" stroke="#EDE6DA" strokeWidth="0.75" />
                  {/* Outlier dotted connection */}
                  <line x1="64" y1="64" x2="144" y2="96" stroke="#EDE6DA" strokeWidth="0.75" strokeDasharray="3,3" />
                </svg>
              </div>
              
              <p className="text-[11.5px] text-[#8A8378] mt-3 leading-normal">
                Linked email scatter showing 5 elements belonging to a single campaign, with 1 safe outlier.
              </p>
            </div>
            
            {/* Quick Helper Note */}
            <div className="bg-white/40 border border-[#EDE6DA]/60 p-4 rounded-xl text-left">
              <span className="text-[10px] text-[#8A8378] font-mono uppercase tracking-wider block">Diagnostics</span>
              <p className="text-[11.5px] text-[#8A8378] mt-1.5 leading-normal">
                SentinelMail runs offline heuristics, OCR/QR-decoding, and Dempster-Shafer combinations locally.
              </p>
            </div>
          </aside>

        </div>
      </div>

    </div>
  );
}
