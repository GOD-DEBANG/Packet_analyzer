import pcap from 'pcap-parser';

export async function parsePcap(filePath, blockedApps, blockedIPs, blockedDomains) {
  return new Promise((resolve, reject) => {
    const parser = pcap.parse(filePath);
    const flows = new Map();
    const stats = {
      totalPackets: 0,
      forwarded: 0,
      dropped: 0,
      activeFlows: 0,
      totalBytes: 0,
      tcpPackets: 0,
      udpPackets: 0,
    };
    const appBreakdown = new Map();
    const timelineData = [];
    const timelineIntervalMs = 5000;
    let currentTimelineBucket = null;

    parser.on('packet', (packet) => {
      stats.totalPackets++;
      const packetLen = packet.header?.capturedLen || packet.header?.incl_len || packet.data.length;
      stats.totalBytes += packetLen;

      // Extract timestamp
      const tsMs = packet.header.timestampSeconds * 1000 + Math.floor(packet.header.timestampMicroseconds / 1000);
      
      // Initialize timeline
      if (!currentTimelineBucket) {
        currentTimelineBucket = { startTime: tsMs, packets: 0, dropped: 0 };
      }
      if (tsMs >= currentTimelineBucket.startTime + timelineIntervalMs) {
        timelineData.push({
          t: `${(currentTimelineBucket.startTime - timelineData[0]?.startTime || 0) / 1000}s`,
          packets: currentTimelineBucket.packets,
          dropped: currentTimelineBucket.dropped,
        });
        currentTimelineBucket = { startTime: tsMs, packets: 0, dropped: 0 };
      }

      // Parse Ethernet
      if (packet.data.length < 14) return;
      const ethType = packet.data.readUInt16BE(12);

      // We only handle IPv4
      if (ethType !== 0x0800) return;
      if (packet.data.length < 34) return;

      const ipHeaderLen = (packet.data[14] & 0x0F) * 4;
      const protocol = packet.data[23];
      const srcIp = [packet.data[26], packet.data[27], packet.data[28], packet.data[29]].join('.');
      const dstIp = [packet.data[30], packet.data[31], packet.data[32], packet.data[33]].join('.');

      let srcPort, dstPort, transportName, payloadOffset;

      // Parse Transport Layer
      if (protocol === 6 && packet.data.length >= 14 + ipHeaderLen + 20) {
        // TCP
        stats.tcpPackets++;
        transportName = 'TCP';
        srcPort = packet.data.readUInt16BE(14 + ipHeaderLen);
        dstPort = packet.data.readUInt16BE(14 + ipHeaderLen + 2);
        const tcpHeaderLen = (packet.data[14 + ipHeaderLen + 12] >> 4) * 4;
        payloadOffset = 14 + ipHeaderLen + tcpHeaderLen;
      } else if (protocol === 17 && packet.data.length >= 14 + ipHeaderLen + 8) {
        // UDP
        stats.udpPackets++;
        transportName = 'UDP';
        srcPort = packet.data.readUInt16BE(14 + ipHeaderLen);
        dstPort = packet.data.readUInt16BE(14 + ipHeaderLen + 2);
        payloadOffset = 14 + ipHeaderLen + 8;
      } else {
        return; // Skip other protocols
      }

      // Consistent 5-tuple tracking (lowest IP/port comes first for bidirectional matching)
      const tupleKey = srcIp < dstIp ? `${srcIp}:${srcPort}-${dstIp}:${dstPort}-${protocol}` : `${dstIp}:${dstPort}-${srcIp}:${srcPort}-${protocol}`;
      
      let flow = flows.get(tupleKey);
      if (!flow) {
        flow = {
          id: stats.activeFlows + 1,
          srcIp,
          dstIp,
          srcPort,
          dstPort,
          protocol: transportName,
          app: 'Unknown',
          sni: '',
          packets: 0,
          bytes: 0,
          blocked: false,
          state: 'NEW',
        };
        stats.activeFlows++;
        flows.set(tupleKey, flow);
      }

      flow.packets++;
      flow.bytes += packet.data.length;

      // App Classification & SNI Extraction
      const payload = packet.data.subarray(payloadOffset);
      if (flow.app === 'Unknown' && payload.length > 5 && transportName === 'TCP' && (dstPort === 443 || srcPort === 443)) {
        // Attempt TLS Client Hello parsing for SNI
        if (payload[0] === 0x16 && payload[5] === 0x01) {
          flow.sni = extractTlsSni(payload) || flow.sni;
          if (flow.sni) flow.app = mapSniToApp(flow.sni);
        } else {
          flow.app = 'HTTPS';
        }
      } else if (flow.app === 'Unknown' && transportName === 'TCP' && (dstPort === 80 || srcPort === 80)) {
        if (payload.length > 0) {
          const host = extractHttpHost(payload);
          if (host) {
            flow.sni = host;
            flow.app = mapSniToApp(host);
          }
        } else {
          flow.app = 'HTTP';
        }
      } else if (flow.app === 'Unknown' && transportName === 'UDP' && (dstPort === 53 || srcPort === 53)) {
        flow.app = 'DNS';
      }

      // Check blocking rules
      if (!flow.blocked) {
        let isBlocked = blockedIPs.includes(srcIp);
        if (!isBlocked && blockedApps.includes(flow.app)) isBlocked = true;
        if (!isBlocked && flow.sni && blockedDomains.some(d => flow.sni.includes(d))) isBlocked = true;
        flow.blocked = isBlocked;
      }

      // Update counters
      if (flow.blocked) {
        stats.dropped++;
        currentTimelineBucket.dropped++;
      } else {
        stats.forwarded++;
        currentTimelineBucket.packets++;
      }
    });

    parser.on('end', () => {
      // Push last bucket
      if (currentTimelineBucket) {
        timelineData.push({
          t: `${(currentTimelineBucket.startTime - timelineData[0]?.startTime || 0) / 1000}s`,
          packets: currentTimelineBucket.packets,
          dropped: currentTimelineBucket.dropped,
        });
      }

      // Prepare final structures
      const finalFlows = Array.from(flows.values());
      const protocolBreakdown = [
        { name: 'TCP', value: stats.tcpPackets },
        { name: 'UDP', value: stats.udpPackets },
      ];

      // Sum apps
      finalFlows.forEach(f => {
        if (!appBreakdown.has(f.app)) appBreakdown.set(f.app, { name: f.app, packets: 0, bytes: 0, color: getAppColor(f.app) });
        const appInfo = appBreakdown.get(f.app);
        appInfo.packets += f.packets;
        appInfo.bytes += f.bytes;
      });

      const sortedApps = Array.from(appBreakdown.values()).sort((a, b) => b.packets - a.packets);

      resolve({
        stats,
        flows: finalFlows,
        appBreakdown: sortedApps,
        protocolBreakdown,
        timelineData,
      });
    });

    parser.on('error', (err) => {
      reject(err);
    });
  });
}

// Helpers
function extractHttpHost(buffer) {
  try {
    const text = buffer.toString('utf8');
    const match = text.match(/^Host:\s*(.+)\r\n/mi);
    return match ? match[1].trim() : null;
  } catch { return null; }
}

function extractTlsSni(payload) {
  try {
    let offset = 43;
    const sessionLen = payload[offset];
    offset += 1 + sessionLen;
    const cipherLen = payload.readUInt16BE(offset);
    offset += 2 + cipherLen;
    const compLen = payload[offset];
    offset += 1 + compLen;
    if (offset + 2 > payload.length) return null;
    
    const extLen = payload.readUInt16BE(offset);
    offset += 2;
    const extEnd = offset + extLen;
    
    while (offset + 4 <= extEnd && offset + 4 <= payload.length) {
      const type = payload.readUInt16BE(offset);
      const len = payload.readUInt16BE(offset + 2);
      offset += 4;
      if (type === 0x0000 && offset + len <= payload.length) { // SNI
        const sniLen = payload.readUInt16BE(offset + 3);
        if (offset + 5 + sniLen <= payload.length) {
          return payload.toString('utf8', offset + 5, offset + 5 + sniLen);
        }
      }
      offset += len;
    }
  } catch { return null; }
  return null;
}

function mapSniToApp(sni) {
  const s = sni.toLowerCase();
  if (s.includes('youtube')) return 'YouTube';
  if (s.includes('facebook') || s.includes('fbcdn')) return 'Facebook';
  if (s.includes('google')) return 'Google';
  if (s.includes('netflix')) return 'Netflix';
  if (s.includes('instagram')) return 'Instagram';
  if (s.includes('twitter') || s.includes('twimg')) return 'Twitter';
  if (s.includes('tiktok') || s.includes('byte')) return 'TikTok';
  if (s.includes('discord')) return 'Discord';
  if (s.includes('zoom.us')) return 'Zoom';
  if (s.includes('whatsapp')) return 'WhatsApp';
  if (s.includes('telegram')) return 'Telegram';
  if (s.includes('spotify')) return 'Spotify';
  if (s.includes('github')) return 'GitHub';
  if (s.includes('amazon') || s.includes('aws')) return 'Amazon';
  if (s.includes('microsoft') || s.includes('windows')) return 'Microsoft';
  if (s.includes('cloudflare')) return 'Cloudflare';
  return 'Unknown';
}

function getAppColor(app) {
  const colors = {
    YouTube: '#ff0000', Facebook: '#1877f2', Google: '#4285f4', Netflix: '#e50914',
    Instagram: '#e1306c', Twitter: '#1da1f2', TikTok: '#69c9d0', Discord: '#5865f2',
    Zoom: '#2d8cff', WhatsApp: '#25d366', Telegram: '#26a5e4', Spotify: '#1db954',
    GitHub: '#f0f6fc', Amazon: '#ff9900', Microsoft: '#00a4ef', Cloudflare: '#f48120',
    HTTPS: '#22c55e', HTTP: '#94a3b8', DNS: '#a855f7', Unknown: '#475569'
  };
  return colors[app] || '#475569';
}
