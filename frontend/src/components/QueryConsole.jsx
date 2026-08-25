import React, { useState, useEffect } from 'react';
import { Search, Sparkles, Download, CornerDownLeft } from 'lucide-react';

export default function QueryConsole() {
  const [query, setQuery] = useState('show me all emails from this campaign');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const sampleQueries = [
    'Show me all emails from this campaign',
    'Show phishing threat emails with QR codes',
    'Show confidential wire transfer requests',
    'Show safe legitimate emails',
  ];

  const handleQuery = async (queryText = query) => {
    if (!queryText.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('http://127.0.0.1:8000/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: queryText }),
      });
      if (!resp.ok) throw new Error(`HTTP error ${resp.status}`);
      const data = await resp.json();
      setResults(data);
    } catch (err) {
      console.error('Error executing query:', err);
      setError('Query request failed. Ensure API server is online.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    handleQuery('show me all emails from this campaign');
  }, []);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      handleQuery();
    }
  };

  return (
    <div className="space-y-6 text-[#3A362F] text-[12.5px]">

      {/* Query Search Bar Card */}
      <div className="craft-card p-6 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-medium text-[#3A362F] uppercase tracking-wider">
          <Sparkles className="w-4 h-4 text-[#C97B4A]" />
          <span>Forensic Search Archive</span>
        </div>

        <div className="relative flex items-center">
          <Search className="w-4.5 h-4.5 text-[#8A8378] absolute left-4 pointer-events-none" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search forensic data... e.g. 'show phishing threat emails with QR codes'"
            className="w-full bg-[#FBF7F1]/80 text-[#3A362F] placeholder-[#8A8378]/70 text-sm font-sans pl-11 pr-28 py-3 rounded-xl border border-[#EDE6DA] focus:border-[#C97B4A] focus:outline-none transition-all"
          />
          <button
            onClick={() => handleQuery()}
            disabled={loading}
            className="absolute right-2 craft-button px-4 py-2 text-xs font-medium flex items-center space-x-1"
          >
            <span>Search</span>
            <CornerDownLeft className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Sample Query Chips */}
        <div className="flex flex-wrap gap-2 pt-1 text-left">
          <span className="text-[12px] text-[#8A8378] self-center">Try querying:</span>
          {sampleQueries.map((sq, idx) => (
            <button
              key={idx}
              onClick={() => {
                setQuery(sq);
                handleQuery(sq);
              }}
              className="text-[11.5px] bg-[#F3ECE0]/30 hover:bg-[#F3ECE0]/60 text-[#3A362F] px-3 py-1 rounded-full border border-[#EDE6DA] hover:border-[#C97B4A] transition-all font-mono"
            >
              "{sq}"
            </button>
          ))}
        </div>
      </div>

      {/* Results Section */}
      {results && (
        <div className="craft-card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-serif text-[14px] text-[#3A362F]">
              Matches Found ({results.results_count})
            </h3>
            <span className="text-[11px] font-mono text-[#8A8378]">{results.message}</span>
          </div>

          <div className="space-y-3">
            {results.matches?.map((m, idx) => {
              const isPhish = m.threat_score >= 50;
              return (
                <div key={idx} className="bg-[#F3ECE0]/10 p-4 rounded-xl border border-[#EDE6DA] flex flex-col md:flex-row items-start md:items-center justify-between gap-4 text-left">
                  <div className="flex items-start space-x-3.5 min-w-0">
                    {/* Score badge */}
                    <div className={`px-2.5 py-1 text-xs font-bold font-mono rounded-lg border flex-shrink-0 ${
                      isPhish ? 'bg-[#F7E8E3] text-[#C1654F] border-[#EDE6DA]' : 'bg-[#EAEFE6] text-[#7A8B6F] border-[#EDE6DA]'
                    }`}>
                      {m.threat_score}/100
                    </div>
                    <div className="min-w-0">
                      <h4 className="text-[13px] font-serif text-[#3A362F] truncate">{m.subject || 'No Subject'}</h4>
                      <p className="text-[11.5px] text-[#8A8378] font-mono truncate mt-0.5">From: {m.sender || 'Unknown'} | File: {m.file_name}</p>
                      {m.sha256 && <p className="text-[10px] text-[#8A8378] font-mono mt-1">SHA-256: {m.sha256.slice(0, 32)}...</p>}
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <button
                      onClick={() => window.open(`http://127.0.0.1:8000/reports/${m.file_name.replace('_report.json', '').replace('.json', '')}?format=pdf`, '_blank')}
                      className="flex items-center space-x-1.5 px-3 py-1.5 bg-white hover:bg-[#F3ECE0]/20 text-[#3A362F] text-xs font-medium rounded-lg border border-[#EDE6DA] transition-all"
                    >
                      <Download className="w-3.5 h-3.5 text-[#C97B4A]" />
                      <span>PDF</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {error && (
        <div className="flex items-center space-x-2.5 p-3.5 bg-[#F7E8E3] border border-[#EDE6DA] rounded-lg text-[#C1654F]">
          <span>{error}</span>
        </div>
      )}

    </div>
  );
}
