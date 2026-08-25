import React, { useEffect, useRef, useState } from 'react';
import { Network as VisNetwork } from 'vis-network';
import { DataSet } from 'vis-data';
import { Network, ShieldAlert, RefreshCw, Layers } from 'lucide-react';

export default function AttributionGraphView() {
  const containerRef = useRef(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  const fetchCampaigns = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('http://127.0.0.1:8000/campaigns');
      if (!resp.ok) throw new Error(`HTTP error ${resp.status}`);
      const json = await resp.json();
      setData(json);
    } catch (err) {
      console.error('Error fetching campaigns:', err);
      setError('Failed to load campaigns and attribution graph from API server.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCampaigns();
  }, []);

  useEffect(() => {
    if (!data || !containerRef.current) return;

    const graphData = data.node_link_graph || {};
    const rawNodes = graphData.nodes || [];
    const rawLinks = graphData.links || graphData.edges || [];

    // Node style mapping matching the warm linen design tokens
    const getNodeStyle = (type) => {
      switch (type) {
        case 'email':
          return { color: { background: '#F3ECE0', border: '#EDE6DA', highlight: { background: '#FFFFFF', border: '#C97B4A' } }, shape: 'diamond', size: 24 };
        case 'actor':
          return { color: { background: '#C1654F', border: '#EDE6DA', highlight: { background: '#C1654F', border: '#C97B4A' } }, shape: 'star', size: 34 };
        case 'ip':
          return { color: { background: '#C97B4A', border: '#EDE6DA', highlight: { background: '#C97B4A', border: '#3A362F' } }, shape: 'dot', size: 18 };
        case 'domain':
          return { color: { background: '#FFFFFF', border: '#EDE6DA', highlight: { background: '#FFFFFF', border: '#C97B4A' } }, shape: 'box', size: 16 };
        case 'url':
          return { color: { background: '#C1654F', border: '#EDE6DA', highlight: { background: '#C1654F', border: '#3A362F' } }, shape: 'triangle', size: 16 };
        case 'relay_host':
          return { color: { background: '#7A8B6F', border: '#EDE6DA', highlight: { background: '#7A8B6F', border: '#3A362F' } }, shape: 'dot', size: 15 };
        default:
          return { color: { background: '#EDE6DA', border: '#EDE6DA', highlight: { background: '#EDE6DA', border: '#8A8378' } }, shape: 'ellipse', size: 14 };
      }
    };

    const nodes = new DataSet(
      rawNodes.map((n) => {
        const style = getNodeStyle(n.type);
        const label = n.label || n.id;
        return {
          id: n.id,
          label: label.length > 25 ? label.slice(0, 22) + '...' : label,
          title: `<b>${n.type?.toUpperCase()}</b><br/>${n.id}`,
          // Light theme labels with white outline for excellent contrast
          font: { color: '#3A362F', size: 11, strokeWidth: 3, strokeColor: '#FFFFFF', face: 'system-ui' },
          ...style,
          data: n,
        };
      })
    );

    const edges = new DataSet(
      rawLinks.map((l, idx) => ({
        id: `e_${idx}`,
        from: l.source || l.from,
        to: l.target || l.to,
        label: l.relation || '',
        font: { color: '#8A8378', size: 9, align: 'top', strokeWidth: 2, strokeColor: '#FFFFFF', face: 'system-ui' },
        color: { color: '#EDE6DA', highlight: '#C97B4A' },
        arrows: 'to',
        smooth: { type: 'continuous' },
      }))
    );

    const options = {
      physics: {
        barnesHut: {
          gravitationalConstant: -2000,
          centralGravity: 0.35,
          springLength: 95,
        },
      },
      interaction: {
        hover: true,
        tooltipDelay: 100,
        zoomView: true,
      },
    };

    const network = new VisNetwork(containerRef.current, { nodes, edges }, options);

    network.on('selectNode', (params) => {
      if (params.nodes.length > 0) {
        const nodeObj = nodes.get(params.nodes[0]);
        setSelectedNode(nodeObj?.data || null);
      }
    });

    network.on('deselectNode', () => {
      setSelectedNode(null);
    });

    return () => {
      network.destroy();
    };
  }, [data]);

  return (
    <div className="space-y-6 text-[#3A362F] text-[12.5px]">

      {/* Header & Refresh Action */}
      <div className="craft-card p-6 flex items-center justify-between">
        <div className="flex items-center space-x-3 text-left">
          <div className="w-11 h-11 bg-[#F7E8E3] text-[#C97B4A] rounded-lg flex items-center justify-center flex-shrink-0">
            <Network className="w-5.5 h-5.5 stroke-[1.5]" />
          </div>
          <div>
            <h2 className="font-serif text-[18px] text-[#3A362F] leading-snug">Attribution Graph</h2>
            <p className="text-[12px] text-[#8A8378] mt-0.5">Interactive topology linking observed IPs, lookup domains, and threat cluster profiles.</p>
          </div>
        </div>

        <button
          onClick={fetchCampaigns}
          disabled={loading}
          className="craft-button px-4 py-2.5 text-xs flex items-center space-x-2"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Main Graph & Sidebar Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* vis-network light canvas */}
        <div className="lg:col-span-2 craft-card p-4 flex flex-col h-[520px] relative bg-white">
          
          {/* Handcrafted Legend Overlay */}
          <div className="absolute top-6 left-6 z-10 bg-white/95 p-3 rounded-lg border border-[#EDE6DA] text-[10.5px] space-y-1.5 font-mono text-[#3A362F]">
            <div className="font-sans font-bold text-[#8A8378] text-[11px] mb-1">Entity Legend</div>
            <div className="flex items-center space-x-2"><span className="w-2.5 h-2.5 rounded-full bg-[#F3ECE0] border border-[#EDE6DA]"></span><span>EMAIL</span></div>
            <div className="flex items-center space-x-2"><span className="w-2.5 h-2.5 rounded-full bg-[#C1654F]"></span><span>THREAT ACTOR</span></div>
            <div className="flex items-center space-x-2"><span className="w-2.5 h-2.5 rounded-full bg-[#C97B4A]"></span><span>IP ADDRESS</span></div>
            <div className="flex items-center space-x-2"><span className="w-2.5 h-2.5 rounded-full bg-[#FFFFFF] border border-[#EDE6DA]"></span><span>DOMAIN</span></div>
            <div className="flex items-center space-x-2"><span className="w-2.5 h-2.5 rounded-full bg-[#7A8B6F]"></span><span>RELAY HOST</span></div>
          </div>

          <div ref={containerRef} className="w-full h-full rounded-xl overflow-hidden bg-[#FBF7F1]/40 border border-[#EDE6DA]/40" />

          {loading && (
            <div className="absolute inset-0 bg-[#FBF7F1]/80 flex items-center justify-center text-xs font-mono text-[#C97B4A]">
              <RefreshCw className="w-5 h-5 animate-spin mr-2" />
              <span>Fetching Campaign Topology...</span>
            </div>
          )}
        </div>

        {/* Sidebar: Campaign Details & Attributions */}
        <div className="space-y-4">

          {/* Threat Actor Match Box */}
          <div className="craft-card p-5 space-y-3 text-left">
            <div className="flex items-center space-x-2 text-xs font-medium text-[#3A362F] uppercase tracking-wider">
              <ShieldAlert className="w-4 h-4 text-[#C1654F]" />
              <span>Threat Actor Attribution</span>
            </div>

            {data?.attributions?.length > 0 ? (
              <div className="space-y-2">
                {data.attributions.map((a) => (
                  <div key={a.actor_id} className="p-3 bg-[#F7E8E3] border border-[#EDE6DA] rounded-lg text-xs">
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-bold text-[#C1654F] font-serif">{a.actor_name}</span>
                      <span className="px-2 py-0.5 bg-white text-[#C1654F] font-mono font-bold rounded text-[10px] border border-[#EDE6DA]">
                        {a.confidence}% MATCH
                      </span>
                    </div>
                    <p className="text-[11px] text-[#8A8378] mb-1">{a.tactics}</p>
                    <span className="text-[10px] text-[#8A8378] font-mono block truncate">Matches: {a.matched_indicators?.join(', ')}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-[#8A8378] italic">No threat actor profile matched.</p>
            )}
          </div>

          {/* Detected Campaign Clusters List */}
          <div className="craft-card p-5 space-y-3 text-left">
            <div className="flex items-center space-x-2 text-xs font-medium text-[#3A362F] uppercase tracking-wider">
              <Layers className="w-4 h-4 text-[#C97B4A]" />
              <span>Detected Campaigns ({data?.campaigns?.length || 0})</span>
            </div>

            <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
              {data?.campaigns?.map((c) => (
                <div key={c.campaign_id} className="p-3 bg-[#F3ECE0]/20 border border-[#EDE6DA] rounded-lg text-xs space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-[#3A362F] font-mono">{c.campaign_id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                      c.is_phishing ? 'bg-[#F7E8E3] border-[#EDE6DA] text-[#C1654F]' : 'bg-[#EAEFE6] border-[#EDE6DA] text-[#7A8B6F]'
                    }`}>
                      {c.is_phishing ? 'THREAT CLUSTER' : 'BENIGN'}
                    </span>
                  </div>
                  <div className="text-[#8A8378] font-mono text-[11px] truncate">
                    Emails ({c.email_count}): {c.emails?.join(', ')}
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
