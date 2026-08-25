import React from 'react';
import { Shield, Network, Search, FileCode, Activity } from 'lucide-react';

export default function Header({ activeTab, setActiveTab, apiStatus }) {
  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col md:flex-row justify-between items-center gap-4">
        
        {/* Brand Logo */}
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-gradient-to-tr from-cyan-600 to-blue-600 rounded-xl shadow-lg shadow-cyan-500/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-extrabold tracking-tight text-white">
                SENTINEL<span className="text-cyan-400">MAIL</span>
              </h1>
              <span className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                v0.2.0 Pipeline
              </span>
            </div>
            <p className="text-xs text-slate-400">AI-Powered Forensic Email Threat Detection & Campaign Graph</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center space-x-1 bg-slate-900/80 p-1.5 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab('analysis')}
            className={`flex items-center space-x-2 px-4 py-2 text-xs font-semibold rounded-lg transition-all ${
              activeTab === 'analysis'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/25'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>EML Analysis</span>
          </button>

          <button
            onClick={() => setActiveTab('campaigns')}
            className={`flex items-center space-x-2 px-4 py-2 text-xs font-semibold rounded-lg transition-all ${
              activeTab === 'campaigns'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/25'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Network className="w-4 h-4" />
            <span>Attribution Graph</span>
          </button>

          <button
            onClick={() => setActiveTab('query')}
            className={`flex items-center space-x-2 px-4 py-2 text-xs font-semibold rounded-lg transition-all ${
              activeTab === 'query'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/25'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Search className="w-4 h-4" />
            <span>AI Query Console</span>
          </button>
        </nav>

        {/* API Status Indicator */}
        <div className="flex items-center space-x-2 text-xs text-slate-400 bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800">
          <Activity className={`w-3.5 h-3.5 ${apiStatus ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
          <span>API: <strong className={apiStatus ? 'text-emerald-400' : 'text-amber-400'}>{apiStatus ? 'ONLINE' : 'CONNECTING...'}</strong></span>
        </div>

      </div>
    </header>
  );
}
