import { useState, useEffect } from 'react';
import {
  LockClosedIcon,
  CodeIcon,
  GlobeIcon,
  TimerIcon,
  RocketIcon,
  ExclamationTriangleIcon,
  QuestionMarkCircledIcon,
  DesktopIcon,
  DrawingPinIcon,
  PersonIcon
} from '@radix-ui/react-icons';
import { Badge, Flex, Tooltip } from '@radix-ui/themes';
import { Theme } from '@radix-ui/themes';
import '@radix-ui/themes/styles.css';

interface PacketInfo {
  timestamp: string;
  src_ip: string;
  src_port?: number;
  dst_ip: string;
  dst_port?: number;
  protocol: string;
  size: number;
  flags?: string;
  dns_query?: string;
  http_method?: string;
  http_path?: string;
  threat_score?: number;
  threat_type?: string;
  entropy?: number;
}

const ProtocolBadge = ({ protocol }: { protocol: string }) => {
  const iconMap: { [key: string]: JSX.Element } = {
    HTTPS: <LockClosedIcon width="14" height="14" />,
    HTTP: <CodeIcon width="14" height="14" />,
    DNS: <GlobeIcon width="14" height="14" />,
    TCP: <TimerIcon width="14" height="14" />,
    UDP: <RocketIcon width="14" height="14" />,
    ICMP: <DrawingPinIcon width="14" height="14" />,
    Critical: <ExclamationTriangleIcon width="14" height="14" />
  };

  const colorMap: { [key: string]: string } = {
    HTTPS: 'bg-jade-900 text-jade-100 border border-jade-700',
    HTTP: 'bg-amber-900 text-amber-100 border border-amber-700',
    DNS: 'bg-sky-900 text-sky-100 border border-sky-700',
    TCP: 'bg-violet-900 text-violet-100 border border-violet-700',
    UDP: 'bg-cyan-900 text-cyan-100 border border-cyan-700',
    ICMP: 'bg-slate-900 text-slate-100 border border-slate-700',
    Critical: 'bg-ruby-900 text-ruby-100 border border-ruby-700'
  };

  return (
    <Badge
      radius="full"
      className={`gap-1.5 px-2.5 py-1 text-xs font-medium ${colorMap[protocol]}`}
    >
      {iconMap[protocol]}
      {protocol}
    </Badge>
  );
};

const PacketFeed = () => {
  const [packets, setPackets] = useState<PacketInfo[]>([]);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  useEffect(() => {
    const interval = setInterval(() => {
      const mockPacket: PacketInfo = {
        timestamp: new Date().toISOString(),
        src_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
        dst_ip: `10.0.0.${Math.floor(Math.random() * 255)}`,
        protocol: ['HTTPS', 'HTTP', 'DNS', 'TCP', 'UDP'][Math.floor(Math.random() * 5)],
        size: Math.floor(Math.random() * 1500) + 100,
        src_port: Math.floor(Math.random() * 65535),
        dst_port: Math.floor(Math.random() * 65535),
        flags: ['SYN', 'ACK', 'PSH', 'RST'][Math.floor(Math.random() * 4)],
        threat_score: Math.random() > 0.9 ? Math.floor(Math.random() * 100) : undefined,
        dns_query: Math.random() > 0.8 ? `query-${Math.floor(Math.random() * 1000)}.example.com` : undefined,
        http_method: Math.random() > 0.7 ? ['GET', 'POST'][Math.floor(Math.random() * 2)] : undefined,
        http_path: Math.random() > 0.7 ? `/path/${Math.floor(Math.random() * 100)}` : undefined,
        entropy: Math.random() * 8
      };

      setPackets(prev => [mockPacket, ...prev].slice(0, 100));
      setLastUpdate(new Date());
    }, 300);

    return () => clearInterval(interval);
  }, []);

  return (
    <Theme appearance="dark" accentColor="jade" grayColor="slate" radius="large">
      <div className="min-h-screen bg-slate-1 p-6 font-sans">
        <div className="max-w-7xl mx-auto bg-slate-2 rounded-3xl shadow-xl shadow-slate-900/50 overflow-hidden border border-slate-6">
          {/* Header */}
          <div className="p-6 bg-slate-3">
            <Flex justify="between" align="center">
              <Flex align="center" gap="4">
                <GlobeIcon className="w-6 h-6 text-jade-9" />
                <div>
                  <h1 className="text-xl font-semibold text-slate-12">Network Traffic Monitor</h1>
                  <p className="text-slate-11 text-sm mt-0.5">
                    Live packet analysis • Updated: {lastUpdate.toLocaleTimeString()}
                  </p>
                </div>
              </Flex>
              <Badge color="jade" variant="soft" radius="full" className="px-3 py-1.5">
                <PersonIcon className="w-4 h-4 mr-1.5 text-slate-12" />
                <span className="text-slate-12">{packets.length} active packets</span>
              </Badge>
            </Flex>
          </div>

          {/* Table Container */}
          <div className="overflow-x-auto max-h-[70vh]">
            <table className="w-full text-sm border-collapse">
              <thead className="bg-slate-3 sticky top-0">
                <tr className="border-b border-slate-6">
                  {[
                    'Timestamp',
                    'Source IP:Port',
                    'Destination IP:Port',
                    'Protocol',
                    'Size',
                    'Flags',
                    'Details',
                    'Entropy'
                  ].map((header) => (
                    <th
                      key={header}
                      className="px-5 py-3.5 text-left text-slate-12 font-medium text-xs uppercase tracking-wide"
                    >
                      <Flex align="center" gap="2">
                        {header}
                        <Tooltip content={`Click to sort by ${header}`}>
                          <QuestionMarkCircledIcon className="w-3.5 h-3.5 text-slate-11 hover:text-slate-12 cursor-help" />
                        </Tooltip>
                      </Flex>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-6">
                {packets.map((pkt, i) => (
                  <tr
                    key={i}
                    className="group hover:bg-slate-3 transition-colors duration-150"
                  >
                    <td className="px-5 py-3 text-slate-12 font-mono text-xs">
                      {new Date(pkt.timestamp).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        fractionalSecondDigits: 3
                      })}
                    </td>
                    <td className="px-5 py-3">
                      <Flex align="center" gap="1">
                        <DesktopIcon className="w-4 h-4 text-slate-11" />
                        <span className="text-slate-12 font-medium">{pkt.src_ip}</span>
                        {pkt.src_port && (
                          <span className="text-slate-11 font-mono">:{pkt.src_port}</span>
                        )}
                      </Flex>
                    </td>
                    <td className="px-5 py-3">
                      <Flex align="center" gap="1">
                        <DrawingPinIcon className="w-4 h-4 text-slate-11" />
                        <span className="text-slate-12 font-medium">{pkt.dst_ip}</span>
                        {pkt.dst_port && (
                          <span className="text-slate-11 font-mono">:{pkt.dst_port}</span>
                        )}
                      </Flex>
                    </td>
                    <td className="px-5 py-3">
                      <ProtocolBadge protocol={pkt.protocol} />
                    </td>
                    <td className="px-5 py-3">
                      <Flex align="center" gap="1" justify="end">
                        <span className="text-slate-12 font-medium">{pkt.size}</span>
                        <span className="text-slate-11 text-xs">bytes</span>
                      </Flex>
                    </td>
                    <td className="px-5 py-3">
                      <Flex gap="1">
                        {pkt.flags?.split('').map((flag, i) => (
                          <Badge
                            key={i}
                            variant="outline"
                            radius="full"
                            className="border-slate-6 bg-slate-4 text-slate-12 px-1.5"
                          >
                            {flag}
                          </Badge>
                        ))}
                      </Flex>
                    </td>
                    <td className="px-5 py-3 max-w-[280px] truncate">
                      {pkt.threat_score && (
                        <Badge color="ruby" variant="soft" radius="full" className="mr-2">
                          <ExclamationTriangleIcon className="w-3.5 h-3.5 mr-1 text-ruby-11" />
                          <span className="text-ruby-11">Threat ({pkt.threat_score}%)</span>
                        </Badge>
                      )}
                      {pkt.dns_query && (
                        <Badge variant="soft" color="sky" radius="full" className="mr-2">
                          <GlobeIcon className="w-3.5 h-3.5 mr-1 text-sky-11" />
                          <span className="text-sky-11">{pkt.dns_query}</span>
                        </Badge>
                      )}
                      {pkt.http_method && (
                        <Badge variant="soft" color="amber" radius="full">
                          <CodeIcon className="w-3.5 h-3.5 mr-1 text-amber-11" />
                          <span className="text-amber-11">{pkt.http_method} {pkt.http_path}</span>
                        </Badge>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      <Tooltip content={`Entropy score: ${pkt.entropy?.toFixed(2)}`}>
                        <Flex align="center" gap="2">
                          <div className="w-16 h-1.5 bg-slate-6 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-jade-9 to-cyan-9"
                              style={{ width: `${((pkt.entropy || 0) / 8) * 100}%` }}
                            />
                          </div>
                          <span className="text-slate-12 text-xs">
                            {pkt.entropy?.toFixed(1)}
                          </span>
                        </Flex>
                      </Tooltip>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Footer */}
          <div className="p-4 bg-slate-3 border-t border-slate-6">
            <Flex gap="5" justify="center">
              {[
                { color: 'jade', icon: LockClosedIcon, label: 'HTTPS' },
                { color: 'amber', icon: CodeIcon, label: 'HTTP' },
                { color: 'sky', icon: GlobeIcon, label: 'DNS' },
                { color: 'ruby', icon: ExclamationTriangleIcon, label: 'Threat' },
                { color: 'cyan', icon: PersonIcon, label: 'Entropy' }
              ].map((item) => (
                <Flex key={item.label} align="center" gap="2">
                  <item.icon className={`w-4 h-4 text-${item.color}-11`} />
                  <span className="text-slate-12 text-sm">{item.label}</span>
                </Flex>
              ))}
            </Flex>
          </div>
        </div>
      </div>
    </Theme>
  );
};

export default PacketFeed;