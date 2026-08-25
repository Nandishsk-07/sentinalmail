import React, { useState } from 'react';
import { Upload, AlertTriangle, QrCode, ShieldCheck, Sparkles, CheckCircle2 } from 'lucide-react';

export default function FileUploader({ onAnalyze, isLoading, error }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  const sampleFiles = [
    { 
      name: 'phish_qr_mfa.eml', 
      label: 'Action Required: Scan QR Code to Update MFA', 
      type: 'phish', 
      iconType: 'qrcode',
      meta: 'company-1t-support.net | Decoded QR code MFA phishing',
      badge: 'High Risk',
      rotate: 'rotate(-0.2deg)'
    },
    { 
      name: 'phish_ceo_wire_fraud.eml', 
      label: 'URGENT: Confidential Wire Transfer Request', 
      type: 'phish', 
      iconType: 'alert',
      meta: 'deltahold1ngs.com | Lookalike domain & financial request',
      badge: 'High Risk',
      rotate: 'rotate(0deg)'
    },
    { 
      name: 'phish_microsoft_security.eml', 
      label: '⚠️ URGENT: Unusual Sign-in Activity — Verify Your Identity Now', 
      type: 'phish', 
      iconType: 'alert',
      meta: 'm1cr0soft-secure.xyz | Display name spoofing',
      badge: 'High Risk',
      rotate: 'rotate(0.2deg)'
    },
    { 
      name: 'legit_meeting_followup.eml', 
      label: 'Follow-up: Supply Chain Sync - Action Items from Aug 20 Call', 
      type: 'legit', 
      iconType: 'check',
      meta: 'globallogistics.io | Verified SPF, DKIM, and DMARC passing',
      badge: 'Verified',
      rotate: 'rotate(0deg)'
    },
  ];

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.eml')) {
        setSelectedFile(file);
        onAnalyze(file);
      } else {
        alert('Please upload a valid .eml email file.');
      }
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.name.endsWith('.eml')) {
        setSelectedFile(file);
        onAnalyze(file);
      } else {
        alert('Please upload a valid .eml email file.');
      }
    }
  };

  const loadSampleFile = async (sampleName) => {
    try {
      const resp = await fetch(`/samples/${sampleName}`);
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      }
      const blob = await resp.blob();
      const file = new File([blob], sampleName, { type: 'message/rfc822' });
      setSelectedFile(file);
      onAnalyze(file);
    } catch (err) {
      console.error('Error fetching sample EML file:', err);
      alert(`Could not load static sample EML file. Please drag & drop a local EML file.`);
    }
  };

  const renderIcon = (iconType) => {
    switch (iconType) {
      case 'qrcode':
        return <QrCode className="w-4 h-4 text-[#C1654F]" />;
      case 'alert':
        return <AlertTriangle className="w-4 h-4 text-[#C1654F]" />;
      case 'check':
        return <ShieldCheck className="w-4 h-4 text-[#7A8B6F]" />;
      default:
        return <Upload className="w-4 h-4 text-[#C97B4A]" />;
    }
  };

  return (
    <div className="space-y-6">
      
      {/* A single wide upload/drop card row */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`relative craft-card p-5 flex items-center justify-between gap-4 transition-colors duration-200 ${
          dragActive ? 'border-[#C97B4A] bg-[#F3ECE0]/20' : 'bg-white hover:border-[#C97B4A]/50'
        }`}
      >
        <input
          type="file"
          accept=".eml"
          onChange={handleFileChange}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
          disabled={isLoading}
        />

        <div className="flex items-center space-x-4">
          {/* Soft terracotta-tinted square icon box */}
          <div className="w-11 h-11 bg-[#F7E8E3] rounded-lg flex items-center justify-center text-[#C97B4A] flex-shrink-0">
            <Upload className={`w-5.5 h-5.5 stroke-[1.5] ${isLoading ? 'animate-bounce' : ''}`} />
          </div>

          <div className="text-left">
            <h3 className="font-serif text-[14.5px] text-[#3A362F]">
              {isLoading ? 'Running forensic check...' : 'Upload email payload'}
            </h3>
            <p className="text-[12px] text-[#8A8378] mt-0.5">
              Drag & drop a <span className="font-mono text-[#C97B4A]">.eml</span> message file, or click to choose local file.
            </p>
          </div>
        </div>

        <button className="craft-button px-5 py-2 text-[12.5px] font-medium pointer-events-none flex-shrink-0">
          {isLoading ? 'Analyzing...' : 'Analyze'}
        </button>
      </div>

      {/* File status notifications */}
      {selectedFile && !isLoading && (
        <div className="flex items-center space-x-2 text-[12px] text-[#7A8B6F] bg-[#EAEFE6] border border-[#EDE6DA] px-3.5 py-2 rounded-lg">
          <CheckCircle2 className="w-4 h-4 text-[#7A8B6F]" />
          <span>Active payload: <strong className="font-mono">{selectedFile.name}</strong></span>
        </div>
      )}

      {error && (
        <div className="flex items-center space-x-2.5 p-3.5 bg-[#F7E8E3] border border-[#EDE6DA] rounded-lg text-[#C1654F] text-[12.5px]">
          <AlertTriangle className="w-4.5 h-4.5 text-[#C1654F] flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Recent analysis section (Demo Presets list) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-[13.5px] font-serif text-[#3A362F]">
            Recent Analysis & Presets
          </h4>
          <span className="text-[11px] text-[#8A8378]">Select a demo preset to run the threat pipeline</span>
        </div>

        <div className="flex flex-col space-y-2.5">
          {sampleFiles.map((s) => {
            const isPhish = s.type === 'phish';
            return (
              <button
                key={s.name}
                onClick={() => loadSampleFile(s.name)}
                disabled={isLoading}
                style={{ transform: s.rotate }}
                className="w-full text-left bg-white border border-[#EDE6DA] rounded-xl p-4 flex items-center justify-between gap-4 transition-colors hover:border-[#C97B4A] hover:bg-[#F3ECE0]/10"
              >
                <div className="flex items-center space-x-3.5 min-w-0">
                  {/* Icon container */}
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${
                    isPhish ? 'bg-[#F7E8E3]' : 'bg-[#EAEFE6]'
                  }`}>
                    {renderIcon(s.iconType)}
                  </div>

                  <div className="min-w-0">
                    <h5 className="text-[12.5px] font-serif text-[#3A362F] truncate">
                      {s.label}
                    </h5>
                    <p className="text-[11.5px] text-[#8A8378] mt-0.5 truncate font-mono">
                      {s.meta}
                    </p>
                  </div>
                </div>

                {/* Status Badge */}
                <span className={`px-2.5 py-1 text-[11px] rounded-full border flex-shrink-0 ${
                  isPhish 
                    ? 'bg-[#F7E8E3] border-[#EDE6DA] text-[#C1654F]' 
                    : 'bg-[#EAEFE6] border-[#EDE6DA] text-[#7A8B6F]'
                }`}>
                  {s.badge}
                </span>
              </button>
            );
          })}
        </div>
      </div>

    </div>
  );
}
