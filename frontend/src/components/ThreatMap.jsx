import React, { useState, useEffect, useRef, useCallback } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import {
  Server,
  ShieldAlert,
  EyeOff,
  Cloud,
  Radio,
  Bot,
  Layers,
  Activity,
  Wifi,
  WifiOff,
  RefreshCw,
} from 'lucide-react';

const RISK_COLORS = {
  critical: '#C1654F', // brick red
  high: '#E08A5A',     // soft orange
  medium: '#E0C168',   // muted yellow
  low: '#7A8B6F',      // sage
  no_data: '#8A8378',  // gray
};

const INFRA_TYPES = [
  { id: 'hosting_server', label: 'Hosting Server', icon: Server, color: '#E08A5A' },
  { id: 'vpn_proxy', label: 'VPN/Proxy', icon: ShieldAlert, color: '#E0C168' },
  { id: 'tor_node', label: 'TOR Node', icon: EyeOff, color: '#C1654F' },
  { id: 'cloud_service', label: 'Cloud Service', icon: Cloud, color: '#7A8B6F' },
  { id: 'open_relay', label: 'Open Relay', icon: Radio, color: '#E08A5A' },
  { id: 'botnet_c2', label: 'Botnet/C2', icon: Bot, color: '#C1654F' },
];

// Custom HTML/DivIcon generator for country threat count markers
const createCountIcon = (count, riskLevel, isPulsing, hasHeat) => {
  const color = RISK_COLORS[riskLevel] || RISK_COLORS.medium;
  const size = Math.min(Math.max(26 + count * 2, 30), 46);
  const pulseClass = isPulsing ? 'pulse-marker' : '';
  const heatShadow = hasHeat ? `0 0 16px 4px ${color}` : '0 4px 12px rgba(0,0,0,0.4)';

  return L.divIcon({
    className: 'custom-country-marker-container',
    html: `
      <div class="${pulseClass}" style="
        width: ${size}px;
        height: ${size}px;
        background-color: ${color};
        color: #ffffff;
        border: 2px solid rgba(255, 255, 255, 0.9);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        font-family: system-ui, sans-serif;
        font-size: ${size > 36 ? 14 : 12}px;
        box-shadow: ${heatShadow};
        cursor: pointer;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      ">
        ${count}
      </div>
    `,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
};

export default function ThreatMap() {
  const [countries, setCountries] = useState([]);
  const [infraCounts, setInfraCounts] = useState({
    hosting_server: 0,
    vpn_proxy: 0,
    tor_node: 0,
    cloud_service: 0,
    open_relay: 0,
    botnet_c2: 0,
  });
  const [attackPaths, setAttackPaths] = useState([]);
  const [pulsingCountries, setPulsingCountries] = useState(new Set());
  const [wsConnected, setWsConnected] = useState(false);
  const [lastEventTime, setLastEventTime] = useState(null);

  // Layer toggles
  const [layers, setLayers] = useState({
    threatLocations: true,
    attackPaths: true,
    countryRisk: true,
    infraHeat: true,
  });
  const [showLayerPanel, setShowLayerPanel] = useState(true);

  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);

  // Load initial REST summary data
  const fetchSummary = async () => {
    try {
      const resp = await fetch('http://127.0.0.1:8000/threat-map/summary');
      if (resp.ok) {
        const data = await resp.json();
        if (data.infra_type_counts) {
          setInfraCounts(data.infra_type_counts);
        }
        if (data.countries) {
          setCountries(data.countries);
        }
        if (data.recent_paths) {
          extractPathsFromData(data.recent_paths);
        }
      }
    } catch (err) {
      console.error('Failed to fetch threat map summary:', err);
    }
  };

  const extractPathsFromData = (pathsList) => {
    const extractedLines = [];
    pathsList.forEach((pathItem) => {
      const hops = pathItem.hops || [];
      for (let i = 0; i < hops.length - 1; i++) {
        const h1 = hops[i];
        const h2 = hops[i + 1];
        if (h1.lat != null && h1.lon != null && h2.lat != null && h2.lon != null) {
          extractedLines.push({
            id: `${pathItem.email_id}_${i}`,
            positions: [
              [h1.lat, h1.lon],
              [h2.lat, h2.lon],
            ],
            riskLevel: h2.risk_level || 'high',
            fromCountry: h1.country,
            toCountry: h2.country,
          });
        }
      }
    });
    setAttackPaths(extractedLines.slice(-15)); // Keep latest 15 paths visible
  };

  // Connect WebSocket channel
  const connectWebSocket = useCallback(() => {
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const ws = new WebSocket('ws://127.0.0.1:8000/ws/threat-map');
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.event === 'new_hop_path') {
          handleNewHopPath(payload);
        }
      } catch (err) {
        console.error('WS parse error:', err);
      }
    };

    ws.onclose = () => {
      setWsConnected(false);
      // Auto-reconnect after 2 seconds
      reconnectTimerRef.current = setTimeout(() => {
        connectWebSocket();
      }, 2000);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  const handleNewHopPath = (payload) => {
    setLastEventTime(new Date().toLocaleTimeString());
    const hops = payload.hops || [];
    if (hops.length === 0) return;

    const newPulsing = new Set();
    const newPaths = [];

    // Process hops to update country tallies & infra counters
    setCountries((prevCountries) => {
      const countryMap = new Map(prevCountries.map((c) => [c.country, { ...c }]));

      hops.forEach((hop) => {
        const { country, lat, lon, risk_level, infra_type } = hop;

        // Bump infra counter
        if (infra_type) {
          setInfraCounts((prev) => ({
            ...prev,
            [infra_type]: (prev[infra_type] || 0) + 1,
          }));
        }

        if (country && country !== 'Internal Network' && lat != null && lon != null) {
          newPulsing.add(country);

          if (!countryMap.has(country)) {
            countryMap.set(country, {
              country,
              lat,
              lon,
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              no_data: 0,
              total: 0,
              max_risk: risk_level || 'medium',
            });
          }

          const cEntry = countryMap.get(country);
          cEntry.total += 1;
          const rKey = risk_level || 'medium';
          cEntry[rKey] = (cEntry[rKey] || 0) + 1;

          const riskOrder = ['no_data', 'low', 'medium', 'high', 'critical'];
          if (riskOrder.indexOf(rKey) > riskOrder.indexOf(cEntry.max_risk)) {
            cEntry.max_risk = rKey;
          }
        }
      });

      return Array.from(countryMap.values());
    });

    // Create animated polylines for hops
    for (let i = 0; i < hops.length - 1; i++) {
      const h1 = hops[i];
      const h2 = hops[i + 1];
      if (h1.lat != null && h1.lon != null && h2.lat != null && h2.lon != null) {
        newPaths.push({
          id: `${payload.email_id}_${Date.now()}_${i}`,
          positions: [
            [h1.lat, h1.lon],
            [h2.lat, h2.lon],
          ],
          riskLevel: h2.risk_level || 'high',
          fromCountry: h1.country,
          toCountry: h2.country,
        });
      }
    }

    if (newPaths.length > 0) {
      setAttackPaths((prev) => [...prev, ...newPaths].slice(-20));
    }

    // Trigger pulse state for 2 seconds
    setPulsingCountries((prev) => new Set([...prev, ...newPulsing]));
    setTimeout(() => {
      setPulsingCountries((prev) => {
        const next = new Set(prev);
        newPulsing.forEach((c) => next.delete(c));
        return next;
      });
    }, 2200);
  };

  useEffect(() => {
    fetchSummary();
    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
    };
  }, [connectWebSocket]);

  return (
    <div className="bg-white border border-[#EDE6DA] rounded-[14px] p-6 text-left space-y-6 shadow-none">
      
      {/* 1. Header & Live Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="font-serif text-[19px] text-[#3A362F] font-normal leading-tight">
              Threat Infrastructure Graph
            </h2>
            <span className="bg-[#C97B4A]/10 text-[#C97B4A] text-[10px] font-mono font-medium px-2 py-0.5 rounded-full border border-[#C97B4A]/20 uppercase">
              Live Feed
            </span>
          </div>
          <p className="text-[12.5px] text-[#8A8378] mt-1">
            Real-time IP intelligence, multi-hop relay vectors, and threat infrastructure monitoring.
          </p>
        </div>

        {/* Status Pill */}
        <div className="flex items-center space-x-3 self-start sm:self-auto">
          <button
            onClick={() => fetchSummary()}
            className="p-1.5 rounded-lg border border-[#EDE6DA] text-[#8A8378] hover:text-[#3A362F] hover:bg-[#F3ECE0]/50 transition-all"
            title="Refresh map summary"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>

          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-[#FBF7F1] border border-[#EDE6DA] text-[11.5px]">
            {wsConnected ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-[#7A8B6F]" />
                <span className="text-[#7A8B6F] font-medium font-mono">Live WebSocket</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-[#C1654F]" />
                <span className="text-[#C1654F] font-medium font-mono">Reconnecting...</span>
              </>
            )}
            {lastEventTime && (
              <span className="text-[#8A8378] text-[10.5px] font-mono border-l border-[#EDE6DA] pl-2">
                {lastEventTime}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* 2. Map Container with CartoDB Dark Matter Base Tiles */}
      <div className="h-[460px] rounded-xl overflow-hidden relative border border-[#EDE6DA] bg-[#111111] shadow-inner">
        
        <MapContainer
          center={[20, 0]}
          zoom={2}
          minZoom={2}
          maxZoom={10}
          scrollWheelZoom={true}
          style={{ height: '100%', width: '100%', background: '#09090b' }}
          zoomControl={true}
        >
          {/* Esri World Imagery Base Tiles */}
          <TileLayer
            url="https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"
            attribution="Tiles &copy; Esri"
            maxZoom={18}
          />

          {/* Layer 1: Country Circle Markers */}
          {layers.threatLocations &&
            countries.map((c) => {
              if (c.lat == null || c.lon == null) return null;
              const isPulsing = pulsingCountries.has(c.country);
              const displayRisk = layers.countryRisk ? c.max_risk : 'medium';
              const icon = createCountIcon(c.total, displayRisk, isPulsing, layers.infraHeat);

              return (
                <Marker key={c.country} position={[c.lat, c.lon]} icon={icon}>
                  <Popup className="threat-map-popup">
                    <div className="p-2 min-w-[170px] text-left text-xs font-sans space-y-1.5">
                      <div className="flex items-center justify-between border-b border-[#EDE6DA] pb-1">
                        <span className="font-bold text-[#3A362F]">{c.country}</span>
                        <span
                          className="px-1.5 py-0.5 text-[9.5px] font-mono uppercase font-bold rounded"
                          style={{
                            backgroundColor: `${RISK_COLORS[c.max_risk]}20`,
                            color: RISK_COLORS[c.max_risk],
                          }}
                        >
                          {c.max_risk}
                        </span>
                      </div>
                      <div className="space-y-0.5 text-[#555]">
                        <div>Total Threat Hops: <strong className="text-[#3A362F]">{c.total}</strong></div>
                        {c.critical > 0 && <div>Critical Threats: <strong className="text-[#C1654F]">{c.critical}</strong></div>}
                        {c.high > 0 && <div>High Severity: <strong className="text-[#E08A5A]">{c.high}</strong></div>}
                        {c.medium > 0 && <div>Medium Severity: <strong className="text-[#E0C168]">{c.medium}</strong></div>}
                        {c.low > 0 && <div>Corporate/Low: <strong className="text-[#7A8B6F]">{c.low}</strong></div>}
                      </div>
                    </div>
                  </Popup>
                </Marker>
              );
            })}

          {/* Layer 2: Animated Dash Attack Paths */}
          {layers.attackPaths &&
            attackPaths.map((path) => (
              <Polyline
                key={path.id}
                positions={path.positions}
                pathOptions={{
                  color: RISK_COLORS[path.riskLevel] || '#E08A5A',
                  weight: 2.5,
                  opacity: 0.85,
                  className: 'animated-attack-path',
                }}
              />
            ))}
        </MapContainer>

        {/* 3. Top-Left Overlay: Map Layers Control Panel */}
        <div className="absolute top-3 left-3 z-[1000]">
          <div className="bg-white/95 backdrop-blur-sm border border-[#EDE6DA] rounded-lg p-3 shadow-md text-left text-xs space-y-2 min-w-[170px]">
            <div
              className="flex items-center justify-between cursor-pointer font-serif text-[#3A362F] font-medium border-b border-[#EDE6DA] pb-1.5"
              onClick={() => setShowLayerPanel(!showLayerPanel)}
            >
              <div className="flex items-center space-x-1.5">
                <Layers className="w-3.5 h-3.5 text-[#C97B4A]" />
                <span>Map Layers</span>
              </div>
              <span className="text-[10px] text-[#8A8378] font-mono">{showLayerPanel ? '▲' : '▼'}</span>
            </div>

            {showLayerPanel && (
              <div className="space-y-1.5 pt-1 text-[11.5px] text-[#3A362F]">
                <label className="flex items-center space-x-2 cursor-pointer hover:text-[#C97B4A] transition-colors">
                  <input
                    type="checkbox"
                    checked={layers.threatLocations}
                    onChange={(e) => setLayers({ ...layers, threatLocations: e.target.checked })}
                    className="accent-[#C97B4A] rounded"
                  />
                  <span>Threat Locations</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer hover:text-[#C97B4A] transition-colors">
                  <input
                    type="checkbox"
                    checked={layers.attackPaths}
                    onChange={(e) => setLayers({ ...layers, attackPaths: e.target.checked })}
                    className="accent-[#C97B4A] rounded"
                  />
                  <span>Attack Paths</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer hover:text-[#C97B4A] transition-colors">
                  <input
                    type="checkbox"
                    checked={layers.countryRisk}
                    onChange={(e) => setLayers({ ...layers, countryRisk: e.target.checked })}
                    className="accent-[#C97B4A] rounded"
                  />
                  <span>Country Risk</span>
                </label>

                <label className="flex items-center space-x-2 cursor-pointer hover:text-[#C97B4A] transition-colors">
                  <input
                    type="checkbox"
                    checked={layers.infraHeat}
                    onChange={(e) => setLayers({ ...layers, infraHeat: e.target.checked })}
                    className="accent-[#C97B4A] rounded"
                  />
                  <span>Infrastructure Heat</span>
                </label>
              </div>
            )}
          </div>
        </div>

        {/* 4. Bottom-Left Overlay: Risk Scale Legend */}
        <div className="absolute bottom-3 left-3 z-[1000]">
          <div className="bg-white/95 backdrop-blur-sm border border-[#EDE6DA] rounded-lg px-3 py-2 shadow-md flex items-center space-x-3 text-[11px] font-mono text-[#3A362F]">
            <span className="font-sans font-medium text-[#8A8378]">Risk:</span>
            {Object.entries(RISK_COLORS).map(([risk, color]) => (
              <div key={risk} className="flex items-center space-x-1">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }} />
                <span className="capitalize text-[10.5px]">{risk}</span>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* 5. Bottom Bar: Infrastructure Types Detected */}
      <div className="pt-2">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-serif text-[14px] text-[#3A362F] font-normal">
            Infrastructure Types Detected
          </h3>
          <span className="text-[11px] text-[#8A8378] font-mono">Real-time aggregate tally</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
          {INFRA_TYPES.map((item) => {
            const Icon = item.icon;
            const count = infraCounts[item.id] || 0;

            return (
              <div
                key={item.id}
                className="bg-[#FBF7F1] border border-[#EDE6DA] rounded-xl p-3 flex flex-col justify-between space-y-2 transition-all hover:bg-white hover:border-[#C97B4A]/40"
              >
                <div className="flex items-center justify-between">
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center text-white"
                    style={{ backgroundColor: item.color }}
                  >
                    <Icon className="w-3.5 h-3.5 stroke-[1.75]" />
                  </div>
                  <span className="font-mono text-[16px] font-bold text-[#3A362F]">
                    {count}
                  </span>
                </div>

                <span className="text-[11.5px] text-[#8A8378] font-medium leading-tight block">
                  {item.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
}
