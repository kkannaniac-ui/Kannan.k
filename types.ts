
export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS';

export interface Packet {
  id: string;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  sourcePort: number;
  destPort: number;
  protocol: Protocol;
  size: number;
  flags?: string;
}

export enum ThreatSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface Threat {
  id: string;
  timestamp: string;
  type: 'Port Scan' | 'Failed Login' | 'Blacklisted IP' | 'DDoS Attempt';
  sourceIp: string;
  severity: ThreatSeverity;
  description: string;
}

export interface Stats {
  packetsProcessed: number;
  threatsDetected: number;
  activeConnections: number;
  bandwidthMbps: number;
}
