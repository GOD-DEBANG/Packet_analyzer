// Mock DPI analysis output — simulates realistic engine results

export const mockStats = {
  totalPackets: 4821,
  forwarded: 4127,
  dropped: 694,
  activeFlows: 142,
  totalBytes: 28_430_512,
  tcpPackets: 3980,
  udpPackets: 712,
  processingTimeMs: 1247,
};

export const mockAppBreakdown = [
  { name: 'YouTube',    packets: 1102, bytes: 9_200_000, color: '#ff0000' },
  { name: 'Google',     packets: 743,  bytes: 4_100_000, color: '#4285f4' },
  { name: 'Netflix',    packets: 612,  bytes: 7_800_000, color: '#e50914' },
  { name: 'HTTPS',      packets: 588,  bytes: 3_200_000, color: '#22c55e' },
  { name: 'Facebook',   packets: 421,  bytes: 1_800_000, color: '#1877f2' },
  { name: 'Discord',    packets: 317,  bytes: 950_000,   color: '#5865f2' },
  { name: 'Zoom',       packets: 289,  bytes: 2_100_000, color: '#2d8cff' },
  { name: 'Instagram',  packets: 245,  bytes: 1_200_000, color: '#e1306c' },
  { name: 'DNS',        packets: 198,  bytes: 120_000,   color: '#a855f7' },
  { name: 'Spotify',    packets: 163,  bytes: 680_000,   color: '#1db954' },
  { name: 'TikTok',     packets: 97,   bytes: 950_000,   color: '#69c9d0' },
  { name: 'Unknown',    packets: 46,   bytes: 330_000,   color: '#475569' },
];

export const mockProtocolBreakdown = [
  { name: 'TCP',  value: 3980 },
  { name: 'UDP',  value: 712  },
  { name: 'DNS',  value: 198  },
];

export const mockTimelineData = [
  { t: '0s',   packets: 120, dropped: 12 },
  { t: '5s',   packets: 340, dropped: 45 },
  { t: '10s',  packets: 560, dropped: 88 },
  { t: '15s',  packets: 490, dropped: 72 },
  { t: '20s',  packets: 710, dropped: 105 },
  { t: '25s',  packets: 620, dropped: 98 },
  { t: '30s',  packets: 780, dropped: 121 },
  { t: '35s',  packets: 650, dropped: 93 },
  { t: '40s',  packets: 890, dropped: 140 },
  { t: '45s',  packets: 720, dropped: 112 },
  { t: '50s',  packets: 540, dropped: 66 },
  { t: '55s',  packets: 421, dropped: 52 },
];

export const mockFlows = [
  { id: 1,  srcIp: '192.168.1.101', dstIp: '172.217.14.206', srcPort: 54321, dstPort: 443, protocol: 'TCP', app: 'YouTube',   sni: 'www.youtube.com',    packets: 1102, bytes: 9_200_000, blocked: true,  state: 'CLASSIFIED' },
  { id: 2,  srcIp: '192.168.1.102', dstIp: '157.240.2.35',   srcPort: 55120, dstPort: 443, protocol: 'TCP', app: 'Facebook',  sni: 'www.facebook.com',   packets: 421,  bytes: 1_800_000, blocked: true,  state: 'CLASSIFIED' },
  { id: 3,  srcIp: '192.168.1.103', dstIp: '142.250.185.14', srcPort: 56000, dstPort: 443, protocol: 'TCP', app: 'Google',    sni: 'accounts.google.com', packets: 743,  bytes: 4_100_000, blocked: false, state: 'ESTABLISHED' },
  { id: 4,  srcIp: '192.168.1.104', dstIp: '54.239.28.85',   srcPort: 49123, dstPort: 443, protocol: 'TCP', app: 'Netflix',   sni: 'api.netflix.com',     packets: 612,  bytes: 7_800_000, blocked: false, state: 'CLASSIFIED' },
  { id: 5,  srcIp: '192.168.1.101', dstIp: '8.8.8.8',        srcPort: 51234, dstPort: 53,  protocol: 'UDP', app: 'DNS',       sni: '',                    packets: 198,  bytes: 120_000,   blocked: false, state: 'CLASSIFIED' },
  { id: 6,  srcIp: '192.168.1.105', dstIp: '162.159.130.234',srcPort: 60001, dstPort: 443, protocol: 'TCP', app: 'Discord',   sni: 'discord.com',         packets: 317,  bytes: 950_000,   blocked: true,  state: 'CLASSIFIED' },
  { id: 7,  srcIp: '192.168.1.106', dstIp: '149.154.167.51', srcPort: 60234, dstPort: 443, protocol: 'TCP', app: 'Telegram',  sni: 'api.telegram.org',    packets: 188,  bytes: 540_000,   blocked: false, state: 'ESTABLISHED' },
  { id: 8,  srcIp: '192.168.1.107', dstIp: '170.114.52.200', srcPort: 58001, dstPort: 443, protocol: 'TCP', app: 'Zoom',      sni: 'zoom.us',             packets: 289,  bytes: 2_100_000, blocked: false, state: 'CLASSIFIED' },
  { id: 9,  srcIp: '192.168.1.108', dstIp: '199.59.148.209', srcPort: 52800, dstPort: 443, protocol: 'TCP', app: 'Twitter',   sni: 'api.twitter.com',     packets: 214,  bytes: 890_000,   blocked: true,  state: 'CLASSIFIED' },
  { id: 10, srcIp: '192.168.1.109', dstIp: '185.60.216.53',  srcPort: 53100, dstPort: 443, protocol: 'TCP', app: 'Instagram', sni: 'www.instagram.com',   packets: 245,  bytes: 1_200_000, blocked: true,  state: 'CLASSIFIED' },
  { id: 11, srcIp: '192.168.1.110', dstIp: '52.94.236.248',  srcPort: 54900, dstPort: 443, protocol: 'TCP', app: 'Amazon',    sni: 'www.amazon.com',      packets: 189,  bytes: 1_500_000, blocked: false, state: 'ESTABLISHED' },
  { id: 12, srcIp: '192.168.1.111', dstIp: '140.82.121.3',   srcPort: 61234, dstPort: 443, protocol: 'TCP', app: 'GitHub',    sni: 'github.com',          packets: 134,  bytes: 780_000,   blocked: false, state: 'CLASSIFIED' },
  { id: 13, srcIp: '192.168.1.112', dstIp: '35.186.224.25',  srcPort: 49900, dstPort: 80,  protocol: 'TCP', app: 'HTTP',      sni: 'example.com',         packets: 52,   bytes: 230_000,   blocked: false, state: 'CLASSIFIED' },
  { id: 14, srcIp: '192.168.1.113', dstIp: '131.253.14.76',  srcPort: 58990, dstPort: 443, protocol: 'TCP', app: 'Microsoft', sni: 'login.microsoft.com', packets: 211,  bytes: 940_000,   blocked: false, state: 'ESTABLISHED' },
  { id: 15, srcIp: '192.168.1.114', dstIp: '178.16.215.84',  srcPort: 55577, dstPort: 443, protocol: 'TCP', app: 'Spotify',   sni: 'api.spotify.com',     packets: 163,  bytes: 680_000,   blocked: false, state: 'CLASSIFIED' },
  { id: 16, srcIp: '192.168.1.115', dstIp: '104.18.22.46',   srcPort: 57123, dstPort: 443, protocol: 'TCP', app: 'TikTok',    sni: 'api.tiktok.com',      packets: 97,   bytes: 950_000,   blocked: true,  state: 'CLASSIFIED' },
  { id: 17, srcIp: '192.168.1.101', dstIp: '1.1.1.1',        srcPort: 53412, dstPort: 443, protocol: 'TCP', app: 'Cloudflare',sni: 'cloudflare.com',      packets: 88,   bytes: 290_000,   blocked: false, state: 'NEW' },
  { id: 18, srcIp: '192.168.1.116', dstIp: '77.88.55.77',    srcPort: 61001, dstPort: 443, protocol: 'TCP', app: 'HTTPS',     sni: 'yandex.ru',           packets: 44,   bytes: 210_000,   blocked: false, state: 'CLASSIFIED' },
  { id: 19, srcIp: '192.168.1.117', dstIp: '23.227.38.65',   srcPort: 62341, dstPort: 443, protocol: 'TCP', app: 'Unknown',   sni: '',                    packets: 21,   bytes: 95_000,    blocked: false, state: 'NEW' },
  { id: 20, srcIp: '192.168.1.118', dstIp: '152.199.21.141', srcPort: 49811, dstPort: 443, protocol: 'TCP', app: 'WhatsApp',  sni: 'web.whatsapp.com',    packets: 176,  bytes: 620_000,   blocked: false, state: 'ESTABLISHED' },
];

export const defaultBlockedApps = ['YouTube', 'Facebook', 'Discord', 'Twitter', 'Instagram', 'TikTok'];
export const defaultBlockedIPs  = ['192.168.1.101', '192.168.1.115'];
export const defaultBlockedDomains = ['youtube.com', 'facebook.com', 'tiktok.com'];

export const allApps = [
  'YouTube', 'Facebook', 'Google', 'Netflix', 'Instagram', 'Twitter',
  'TikTok', 'Discord', 'Zoom', 'WhatsApp', 'Telegram', 'Spotify',
  'GitHub', 'Amazon', 'Microsoft', 'Cloudflare',
];

export function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

export function getAppClass(app) {
  return 'app-' + (app || 'unknown').toLowerCase();
}

export const APP_COLORS = {
  YouTube:    '#ff0000',
  Facebook:   '#1877f2',
  Google:     '#4285f4',
  Netflix:    '#e50914',
  Instagram:  '#e1306c',
  Twitter:    '#1da1f2',
  TikTok:     '#69c9d0',
  Discord:    '#5865f2',
  Zoom:       '#2d8cff',
  WhatsApp:   '#25d366',
  Telegram:   '#26a5e4',
  Spotify:    '#1db954',
  GitHub:     '#f0f6fc',
  Amazon:     '#ff9900',
  Microsoft:  '#00a4ef',
  Cloudflare: '#f48120',
  DNS:        '#a855f7',
  HTTPS:      '#22c55e',
  HTTP:       '#94a3b8',
  Unknown:    '#475569',
};
