import React from 'react';
import { Download, ShieldAlert, ShieldCheck, AlertTriangle, KeyRound, MapPin, Hash, QrCode, FileText, CheckCircle2, XCircle } from 'lucide-react';

export default function AnalysisResults({ data }) {
  if (!data) return null;

  const { verdict, chain_of_custody, engine_results, report_urls, report_id } = data;
  const score = verdict?.threat_score || 0;
  const tier = verdict?.tier || 'UNKNOWN';

  const headerRes = engine_results?.HeaderParser || {};
  const nlpRes = engine_results?.NLPEngine || {};
  const visualRes = engine_results?.VisualEngine || {};
  const attrRes = engine_results?.AttributionGraph || {};

  const custody = chain_of_custody || {};
  const auth = headerRes?.auth_results?.header || {};

  // Handcrafted Tier Styling Helper (using our exact color tokens)
  const getTierStyle = (tierStr) => {
    const isThreat = tierStr === 'CONFIRMED_THREAT' || tierStr === 'LIKELY_PHISH' || tierStr === 'SUSPICIOUS';
    
    if (isThreat) {
      return {
        badgeBg: 'bg-[#F7E8E3] text-[#C1654F] border-[#EDE6DA]',
        bannerBg: 'bg-white border-[#EDE6DA]',
        scoreBg: 'bg-[#C1654F]',
        icon: <ShieldAlert className="w-6 h-6 text-[#C1654F]" />,
        textColor: 'text-[#C1654F]',
      };
    } else {
      return {
        badgeBg: 'bg-[#EAEFE6] text-[#7A8B6F] border-[#EDE6DA]',
        bannerBg: 'bg-white border-[#EDE6DA]',
        scoreBg: 'bg-[#7A8B6F]',
        icon: <ShieldCheck className="w-6 h-6 text-[#7A8B6F]" />,
        textColor: 'text-[#7A8B6F]',
      };
    }
  };

  const style = getTierStyle(tier);

  const handleDownloadPDF = () => {
    const pdfUrl = report_urls?.pdf || `http://127.0.0.1:8000/reports/${report_id}?format=pdf`;
    window.open(pdfUrl, '_blank');
  };

  return (
    <div className="space-y-6 text-[#3A362F] text-[12.5px]">

      {/* Executive Verdict Banner (Large card, border-radius 14px, no shadow) */}
      <div className={`craft-card p-6 flex flex-col md:flex-row items-center justify-between gap-6`}>
        <div className="flex items-start space-x-4 text-left">
          {/* Terracotta/Muted icon container */}
          <div className="w-11 h-11 bg-[#F3ECE0] rounded-lg flex items-center justify-center flex-shrink-0">
            {style.icon}
          </div>
          <div>
            <div className="flex items-center space-x-2.5 mb-1.5">
              <span className={`text-[10px] font-bold font-mono px-2.5 py-0.5 rounded-full border uppercase ${style.badgeBg}`}>
                {tier.replace('_', ' ')}
              </span>
              <span className="text-[11px] text-[#8A8378]">
                File: <strong className="text-[#3A362F] font-mono font-medium">{custody.file_name || headerRes.file}</strong>
              </span>
            </div>
            <h2 className="font-serif text-[18px] text-[#3A362F] leading-snug">{headerRes.subject || 'No Subject'}</h2>
            <p className="text-[11.5px] text-[#8A8378] mt-1">From: <span className="font-mono text-[#3A362F]">{headerRes.from || 'Unknown'}</span></p>
          </div>
        </div>

        {/* Score Gauge & PDF Download Action */}
        <div className="flex flex-col sm:flex-row items-center gap-4 flex-shrink-0">
          <div className={`flex flex-col items-center justify-center w-20 h-20 rounded-xl text-white ${style.scoreBg}`}>
            <span className="text-3xl font-serif font-normal">{score}</span>
            <span className="text-[9px] uppercase tracking-wider font-sans font-medium mt-0.5">Threat Score</span>
          </div>

          <button
            onClick={handleDownloadPDF}
            className="craft-button px-4 py-2.5 text-xs flex items-center space-x-2"
          >
            <Download className="w-4 h-4 text-white" />
            <span>Forensic Report</span>
          </button>
        </div>
      </div>

      {/* Chain-of-Custody & Timestamps Box */}
      <div className="craft-card p-4 font-mono text-[11.5px] text-[#8A8378] text-left">
        <div className="flex items-center space-x-2 text-[#3A362F] font-sans font-medium mb-2 text-xs">
          <Hash className="w-4 h-4 text-[#C97B4A]" />
          <span>CHAIN-OF-CUSTODY METADATA</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <div>SHA-256: <span className="text-[#C97B4A] font-bold break-all">{custody.sha256 || 'N/A'}</span></div>
          <div>Analyzed: <span className="text-[#3A362F]">{custody.analyzed_at_utc || new Date().toISOString()}</span></div>
        </div>
      </div>

      {/* Grid: Authentication & Signal Contributions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

        {/* Email Authentication Status */}
        <div className="craft-card p-5 space-y-4 text-left">
          <div className="flex items-center space-x-2 text-xs font-medium text-[#3A362F] uppercase tracking-wider">
            <KeyRound className="w-4 h-4 text-[#C97B4A]" />
            <span>Authentication Checks</span>
          </div>

          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'SPF', item: auth.spf },
              { label: 'DKIM', item: auth.dkim },
              { label: 'DMARC', item: auth.dmarc },
            ].map(({ label, item }) => {
              const verdictStr = (item?.verdict || 'none').toLowerCase();
              const isPass = verdictStr === 'pass';
              return (
                <div key={label} className="bg-[#F3ECE0]/30 p-3 rounded-lg border border-[#EDE6DA] text-center">
                  <span className="text-[11px] font-medium text-[#8A8378] block mb-1">{label}</span>
                  <span className={`inline-flex items-center space-x-1 text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                    isPass ? 'bg-[#EAEFE6] text-[#7A8B6F]' : 'bg-[#F7E8E3] text-[#C1654F]'
                  }`}>
                    <span>{verdictStr.toUpperCase()}</span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Dempster-Shafer Signal Breakdown */}
        <div className="craft-card p-5 space-y-4 text-left">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#3A362F] uppercase tracking-wider">Belief Contributions</span>
            <span className="text-[10px] text-[#8A8378] font-mono">Dempster-Shafer</span>
          </div>

          <div className="space-y-3">
            {verdict.signal_contributions?.map((c) => (
              <div key={c.engine} className="space-y-1">
                <div className="flex justify-between text-[11.5px] text-[#3A362F]">
                  <span>{c.engine}</span>
                  <span className="font-mono text-[#C97B4A]">{(c.threat_belief * 100).toFixed(0)}% threat</span>
                </div>
                <div className="h-1.5 w-full bg-[#EDE6DA] rounded-full overflow-hidden flex">
                  <div style={{ width: `${c.threat_belief * 100}%` }} className="bg-[#C1654F] h-full" />
                  <div style={{ width: `${c.safe_belief * 100}%` }} className="bg-[#7A8B6F] h-full" />
                  <div style={{ width: `${c.uncertainty * 100}%` }} className="bg-[#8A8378]/30 h-full" />
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Relay Path Hops */}
      <div className="craft-card p-5 text-left">
        <div className="flex items-center space-x-2 text-xs font-medium text-[#3A362F] uppercase tracking-wider mb-4">
          <MapPin className="w-4 h-4 text-[#C97B4A]" />
          <span>Relay Hop Routing Chain ({headerRes.relay_path?.length || 0} hops)</span>
        </div>

        <div className="space-y-2.5">
          {headerRes.relay_path?.map((hop) => (
            <div key={hop.hop} className="flex items-start space-x-4 bg-[#F3ECE0]/20 p-3 rounded-lg border border-[#EDE6DA] text-[11.5px]">
              <div className="px-2 py-0.5 bg-white text-[#C97B4A] font-mono font-bold rounded border border-[#EDE6DA] flex-shrink-0">
                Hop {hop.hop}
              </div>
              <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-2">
                <div>
                  <span className="text-[#8A8378] block">From Host / IP:</span>
                  <strong className="text-[#3A362F] font-mono font-medium">{hop.from_host || '—'}</strong>
                  {hop.from_ip && <span className="text-[#C97B4A] block font-mono">[{hop.from_ip}]</span>}
                </div>
                <div>
                  <span className="text-[#8A8378] block">By Host:</span>
                  <span className="text-[#3A362F] font-mono">{hop.by_host || '—'}</span>
                </div>
                <div>
                  <span className="text-[#8A8378] block">Protocol & Delay:</span>
                  <span className="text-[#3A362F]">{hop.protocol || 'ESMTP'}</span>
                  {hop.delay_seconds !== null && <span className="text-[#C97B4A] font-mono ml-2">(+{hop.delay_seconds}s)</span>}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* NLP & Flagged Phrases */}
      <div className="craft-card p-5 space-y-4 text-left">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-medium text-[#3A362F] uppercase tracking-wider">
            <FileText className="w-4 h-4 text-[#C97B4A]" />
            <span>NLP Intent & Suspicious Phrase Flagger</span>
          </div>
          <span className="text-[12px] font-serif text-[#C97B4A]">Phishing Intent Score: {(nlpRes.phishing_score?.score * 100 || 0).toFixed(0)}%</span>
        </div>

        {nlpRes.flagged_phrases?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-[#EDE6DA] text-[#8A8378] font-serif font-normal">
                  <th className="pb-2 font-normal">Severity</th>
                  <th className="pb-2 font-normal">Flagged Phrase</th>
                  <th className="pb-2 font-normal">Category</th>
                  <th className="pb-2 font-normal">Observed Context</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EDE6DA]/40">
                {nlpRes.flagged_phrases.map((p, idx) => (
                  <tr key={idx} className="hover:bg-[#F3ECE0]/10">
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 text-[9px] font-bold rounded uppercase ${
                        p.severity === 'critical' || p.severity === 'high' ? 'bg-[#F7E8E3] text-[#C1654F]' : 'bg-[#F3ECE0] text-[#8A8378]'
                      }`}>
                        {p.severity}
                      </span>
                    </td>
                    <td className="py-2.5 font-mono text-[#3A362F]">"{p.phrase}"</td>
                    <td className="py-2.5 text-[#8A8378] uppercase font-mono">{p.category}</td>
                    <td className="py-2.5 text-[#8A8378] italic">{p.context}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-[#8A8378] italic">No suspicious phrases flagged in email body.</p>
        )}
      </div>

      {/* Visual Scan & QR Code Findings */}
      <div className="craft-card p-5 space-y-4 text-left">
        <div className="flex items-center space-x-2 text-xs font-medium text-[#3A362F] uppercase tracking-wider">
          <QrCode className="w-4 h-4 text-[#C97B4A]" />
          <span>Visual & QR Code Findings</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#F3ECE0]/20 p-4 rounded-lg border border-[#EDE6DA]">
            <span className="text-[#8A8378] block mb-1">Images Scanned: <strong className="text-[#3A362F]">{visualRes.images_scanned || 0}</strong></span>
            <span className="text-[#8A8378] block mb-1">QR Codes Found: <strong className="text-[#C1654F]">{visualRes.qr_codes_found || 0}</strong></span>
            {visualRes.decoded_urls?.map((url, idx) => (
              <div key={idx} className="mt-2 p-2 bg-[#F7E8E3] border border-[#EDE6DA] rounded text-[#C1654F] font-mono break-all text-[11px]">
                ⚠️ Decoded QR URL: {url}
              </div>
            ))}
          </div>

          <div className="bg-[#F3ECE0]/20 p-4 rounded-lg border border-[#EDE6DA]">
            <span className="text-[#8A8378] block mb-2 font-semibold font-serif">Attachments Inventory</span>
            {visualRes.attachments?.length > 0 ? (
              <ul className="space-y-1 text-[#3A362F] font-mono">
                {visualRes.attachments.map((att, idx) => (
                  <li key={idx} className="flex justify-between text-[11.5px]">
                    <span>{att.filename}</span>
                    <span className="text-[#8A8378]">({att.size_bytes} B)</span>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-[#8A8378] italic text-[11.5px]">No file attachments in this email payload.</span>
            )}
          </div>
        </div>
      </div>

    </div>
  );
}
