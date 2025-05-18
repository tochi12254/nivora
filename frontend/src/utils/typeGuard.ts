// utils/typeGuards.ts
import { Threat, NetworkPacket } from "@/types/types";
export function isThreat(message: any): message is Threat {
  return (
    typeof message === 'object' &&
    'threat_type' in message &&
    'source_ip' in message &&
    'timestamp' in message
  );
}

export function isNetworkPacket(message: any): message is NetworkPacket {
  return (
    typeof message === 'object' &&
    'protocol' in message &&
    'source_ip' in message &&
    'timestamp' in message
  );
}