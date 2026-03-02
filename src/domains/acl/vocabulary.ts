import { AudienceLevel } from './audience';

/**
 * NETWORKING TERMINOLOGY
 * ======================================
 *
 * This file provides graduated terminology mappings for networking concepts
 * across five levels from absolute beginner to research professional.
 *
 * REQUIREMENTS FOR NEW ENTRIES:
 *
 * 1. Audience Level Guidelines:
 *
 *    BEGINNER (A2 English):
 *    - Use simple, concrete words (max 2-3 syllables)
 *    - Prefer everyday metaphors (door, helper, finder, etc.)
 *    - No acronyms ever
 *    - Single words or short phrases only
 *    - Think: explaining to a child
 *
 *    INTERMEDIATE (B1 English):
 *    - Simple descriptions and explanations
 *    - May use basic technical terms with context
 *    - Still no acronyms
 *    - Can be short phrases that explain the concept
 *    - Think: explaining to a teenager
 *
 *    ADVANCED (B2 English / CCNA Student):
 *    - Full technical names with acronyms in parentheses
 *    - May use standard networking terminology
 *    - Acronym format: "Full Name (ACRONYM)"
 *    - Think: textbook explanation
 *
 *    EXPERT (C1 English / Network Engineer):
 *    - Acronyms only (no explanations needed)
 *    - Assume full familiarity with terms
 *    - May use industry standard abbreviations
 *    - Think: professional conversation
 *
 *    MASTER (C2 English / Researcher):
 *    - RFC numbers for IETF standards
 *    - IEEE specifications for Ethernet standards
 *    - Formal specification references
 *    - May include multiple RFCs (comma separated)
 *    - Think: academic paper citations
 *
 * 2. Acceptance Criteria:
 *    - Each level must be distinct from adjacent levels
 *    - Beginner must NEVER use acronyms
 *    - Intermediate must NEVER use acronyms
 *    - Advanced must use "Full Name (ACRONYM)" format
 *    - Expert must use acronym only
 *    - Master must use specification references (RFC, IEEE, ISO, etc.)
 *    - All 5 levels must be populated (no empty entries)
 *    - Strings should be concise (max 10-15 words except Master or Expert references)
 *    - Cite accessible resources, if possible provide hyperlinks or DOI
 *
 * 3. Reference Formats:
 *    - IETF RFC: "RFC XXXX" or "RFC XXXX, RFC YYYY" for multiple
 *    - IEEE: "IEEE 802.3ab" format (include year if relevant)
 *    - ISO: "ISO/IEC XXXX-X" format
 *    - Other standards: Use formal specification name
 *    - IEEE citation style
 */

export const NETWORKING_TERMS: Record<string, Record<AudienceLevel, string>> = {
  tcp: {
    [AudienceLevel.Beginner]: 'reliable messenger',
    [AudienceLevel.Intermediate]: 'reliable connection protocol',
    [AudienceLevel.Advanced]: 'Transmission Control Protocol (TCP)',
    [AudienceLevel.Expert]: 'TCP',
    [AudienceLevel.Master]: 'RFC 793',
  },
  udp: {
    [AudienceLevel.Beginner]: 'quick messenger',
    [AudienceLevel.Intermediate]: 'fast delivery protocol',
    [AudienceLevel.Advanced]: 'User Datagram Protocol (UDP)',
    [AudienceLevel.Expert]: 'UDP',
    [AudienceLevel.Master]: 'RFC 768',
  },
  icmp: {
    [AudienceLevel.Beginner]: 'helper',
    [AudienceLevel.Intermediate]: 'network diagnostic protocol',
    [AudienceLevel.Advanced]: 'Internet Control Message Protocol (ICMP)',
    [AudienceLevel.Expert]: 'ICMP',
    [AudienceLevel.Master]: 'RFC 792',
  },
  ospf: {
    [AudienceLevel.Beginner]: 'path finder',
    [AudienceLevel.Intermediate]: 'routing protocol',
    [AudienceLevel.Advanced]: 'Open Shortest Path First (OSPF)',
    [AudienceLevel.Expert]: 'OSPF',
    [AudienceLevel.Master]: 'RFC 2328, RFC 5340',
  },
  http: {
    [AudienceLevel.Beginner]: 'web helper',
    [AudienceLevel.Intermediate]: 'web transfer protocol',
    [AudienceLevel.Advanced]: 'Hypertext Transfer Protocol (HTTP)',
    [AudienceLevel.Expert]: 'HTTP',
    [AudienceLevel.Master]: 'RFC 7230, RFC 7231, RFC 7232, RFC 7233, RFC 7234, RFC 7235',
  },
  quic: {
    [AudienceLevel.Beginner]: 'fast messenger',
    [AudienceLevel.Intermediate]: 'fast transport protocol',
    [AudienceLevel.Advanced]: 'Quick UDP Internet Connections (QUIC)',
    [AudienceLevel.Expert]: 'QUIC',
    [AudienceLevel.Master]: 'RFC 9000',
  },
  dns: {
    [AudienceLevel.Beginner]: 'name finder',
    [AudienceLevel.Intermediate]: 'name resolution service',
    [AudienceLevel.Advanced]: 'Domain Name System (DNS)',
    [AudienceLevel.Expert]: 'DNS',
    [AudienceLevel.Master]: 'RFC 1035, RFC 1034',
  },
  port: {
    [AudienceLevel.Beginner]: 'door',
    [AudienceLevel.Intermediate]: 'application endpoint',
    [AudienceLevel.Advanced]: 'port number for application identification',
    [AudienceLevel.Expert]: 'Port',
    [AudienceLevel.Master]: 'RFC 6335',
  },
  segment: {
    [AudienceLevel.Beginner]: 'piece',
    [AudienceLevel.Intermediate]: 'transport layer message',
    [AudienceLevel.Advanced]: 'TCP segment with header and data',
    [AudienceLevel.Expert]: 'Segment',
    [AudienceLevel.Master]: 'RFC 793 Section 2.7',
  },
  sliding_window: {
    [AudienceLevel.Beginner]: 'moving window',
    [AudienceLevel.Intermediate]: 'flow control mechanism',
    [AudienceLevel.Advanced]: 'sliding window for flow control',
    [AudienceLevel.Expert]: 'Sliding Window',
    [AudienceLevel.Master]: 'RFC 793 Section 3.7',
  },
  flow_control: {
    [AudienceLevel.Beginner]: 'speed control',
    [AudienceLevel.Intermediate]: 'data rate regulation',
    [AudienceLevel.Advanced]: 'flow control mechanism (windowing)',
    [AudienceLevel.Expert]: 'Flow Control',
    [AudienceLevel.Master]: 'RFC 793 Section 3.7',
  },
  forward_acknowledgment: {
    [AudienceLevel.Beginner]: 'got it signal',
    [AudienceLevel.Intermediate]: 'receipt confirmation',
    [AudienceLevel.Advanced]: 'Forward acknowledgment in TCP',
    [AudienceLevel.Expert]: 'ACK',
    [AudienceLevel.Master]: 'RFC 793 Section 3.3',
  },
  error_detection: {
    [AudienceLevel.Beginner]: 'mistake finder',
    [AudienceLevel.Intermediate]: 'corruption checking',
    [AudienceLevel.Advanced]: 'error detection using checksums',
    [AudienceLevel.Expert]: 'Error Detection',
    [AudienceLevel.Master]: 'RFC 1071',
  },
  error_recovery: {
    [AudienceLevel.Beginner]: 'mistake fixer',
    [AudienceLevel.Intermediate]: 'retransmission process',
    [AudienceLevel.Advanced]: 'error recovery through retransmission',
    [AudienceLevel.Expert]: 'Error Recovery',
    [AudienceLevel.Master]: 'RFC 793 Section 3.7',
  },
  connection_establishment: {
    [AudienceLevel.Beginner]: 'handshake',
    [AudienceLevel.Intermediate]: 'three-way handshake',
    [AudienceLevel.Advanced]: 'TCP connection establishment (SYN, SYN-ACK, ACK)',
    [AudienceLevel.Expert]: 'Three-Way Handshake',
    [AudienceLevel.Master]: 'RFC 793 Section 3.4',
  },
  wildcard_mask: {
    [AudienceLevel.Beginner]: 'match pattern',
    [AudienceLevel.Intermediate]: 'inverse network mask',
    [AudienceLevel.Advanced]: 'wildcard mask for ACL matching',
    [AudienceLevel.Expert]: 'Wildcard Mask',
    [AudienceLevel.Master]: 'RFC 1918, RFC 4632',
  },
  access_control_entry: {
    [AudienceLevel.Beginner]: 'permission rule',
    [AudienceLevel.Intermediate]: 'access rule',
    [AudienceLevel.Advanced]: 'Access Control Entry (ACE)',
    [AudienceLevel.Expert]: 'ACE',
    [AudienceLevel.Master]: 'RFC 2401, RFC 3550',
  },
  named_access_list: {
    [AudienceLevel.Beginner]: 'named rules',
    [AudienceLevel.Intermediate]: 'named rule set',
    [AudienceLevel.Advanced]: 'named access list with symbolic names',
    [AudienceLevel.Expert]: 'Named ACL',
    [AudienceLevel.Master]: 'RFC 2401',
  },
  standard_access_list: {
    [AudienceLevel.Beginner]: 'basic rules',
    [AudienceLevel.Intermediate]: 'source-based filtering',
    [AudienceLevel.Advanced]: 'standard access list (source IP only)',
    [AudienceLevel.Expert]: 'Standard ACL',
    [AudienceLevel.Master]: 'RFC 2401',
  },
  extended_access_list: {
    [AudienceLevel.Beginner]: 'detailed rules',
    [AudienceLevel.Intermediate]: 'advanced filtering',
    [AudienceLevel.Advanced]: 'extended access list (source, destination, protocol, port)',
    [AudienceLevel.Expert]: 'Extended ACL',
    [AudienceLevel.Master]: 'RFC 2401',
  },
  vty_acl: {
    [AudienceLevel.Beginner]: 'login rules',
    [AudienceLevel.Intermediate]: 'terminal access control',
    [AudienceLevel.Advanced]: 'vty access list for SSH/Telnet',
    [AudienceLevel.Expert]: 'VTY ACL',
    [AudienceLevel.Master]: 'RFC 4251, RFC 854',
  },
  web_server: {
    [AudienceLevel.Beginner]: 'web helper',
    [AudienceLevel.Intermediate]: 'web content provider',
    [AudienceLevel.Advanced]: 'Web server hosting HTTP content',
    [AudienceLevel.Expert]: 'Web Server',
    [AudienceLevel.Master]: 'RFC 7230, RFC 7231',
  },
  uri: {
    [AudienceLevel.Beginner]: 'web address',
    [AudienceLevel.Intermediate]: 'resource locator',
    [AudienceLevel.Advanced]: 'Uniform Resource Identifier (URI)',
    [AudienceLevel.Expert]: 'URI',
    [AudienceLevel.Master]: 'RFC 3986',
  },
  secure_http: {
    [AudienceLevel.Beginner]: 'safe web',
    [AudienceLevel.Intermediate]: 'encrypted web protocol',
    [AudienceLevel.Advanced]: 'HTTPS (HTTP over TLS)',
    [AudienceLevel.Expert]: 'HTTPS',
    [AudienceLevel.Master]: 'RFC 2818, RFC 5246',
  },
};

export const PROTOCOL_NAMES: Record<string, Record<AudienceLevel, string>> = {
  ip: {
    [AudienceLevel.Beginner]: 'the address',
    [AudienceLevel.Intermediate]: 'the addressing system that gets your data to the right place',
    [AudienceLevel.Advanced]: 'the Internet Protocol (IP)',
    [AudienceLevel.Expert]: 'IP',
    [AudienceLevel.Master]: 'RFC 791',
  },
  tcp: {
    [AudienceLevel.Beginner]: 'the reliable connection',
    [AudienceLevel.Intermediate]: 'the delivery service that checks everything arrived',
    [AudienceLevel.Advanced]: 'the Transmission Control Protocol (TCP)',
    [AudienceLevel.Expert]: 'TCP',
    [AudienceLevel.Master]: 'RFC 793',
  },
  udp: {
    [AudienceLevel.Beginner]: 'the fast message',
    [AudienceLevel.Intermediate]: 'the delivery service that sends without waiting',
    [AudienceLevel.Advanced]: 'the User Datagram Protocol (UDP)',
    [AudienceLevel.Expert]: 'UDP',
    [AudienceLevel.Master]: 'RFC 768',
  },
  icmp: {
    [AudienceLevel.Beginner]: 'the error reporter',
    [AudienceLevel.Intermediate]: 'the system that speaks up when something goes wrong',
    [AudienceLevel.Advanced]: 'the Internet Control Message Protocol (ICMP)',
    [AudienceLevel.Expert]: 'ICMP',
    [AudienceLevel.Master]: 'RFC 792',
  },
  ospf: {
    [AudienceLevel.Beginner]: 'the route finder',
    [AudienceLevel.Intermediate]: 'the system that figures out the best path through the network',
    [AudienceLevel.Advanced]: 'the Open Shortest Path First (OSPF) protocol',
    [AudienceLevel.Expert]: 'OSPF',
    [AudienceLevel.Master]: 'RFC 2328',
  },
  http: {
    [AudienceLevel.Beginner]: 'the web rule',
    [AudienceLevel.Intermediate]: 'the set of rules for getting web pages',
    [AudienceLevel.Advanced]: 'the Hypertext Transfer Protocol (HTTP)',
    [AudienceLevel.Expert]: 'HTTP',
    [AudienceLevel.Master]: 'RFC 2616',
  },
  https: {
    [AudienceLevel.Beginner]: 'the secure web rule',
    [AudienceLevel.Intermediate]: 'the set of rules for getting web pages safely',
    [AudienceLevel.Advanced]: 'the Hypertext Transfer Protocol Secure (HTTPS)',
    [AudienceLevel.Expert]: 'HTTPS',
    [AudienceLevel.Master]: 'RFC 2818',
  },
  arp: {
    [AudienceLevel.Beginner]: 'the finder',
    [AudienceLevel.Intermediate]: 'the system that finds which device has which address',
    [AudienceLevel.Advanced]: 'the Address Resolution Protocol (ARP)',
    [AudienceLevel.Expert]: 'ARP',
    [AudienceLevel.Master]: 'RFC 826',
  },
  dhcp: {
    [AudienceLevel.Beginner]: 'the address giver',
    [AudienceLevel.Intermediate]: 'the system that hands out addresses automatically',
    [AudienceLevel.Advanced]: 'the Dynamic Host Configuration Protocol (DHCP)',
    [AudienceLevel.Expert]: 'DHCP',
    [AudienceLevel.Master]: 'RFC 2131',
  },
  dns: {
    [AudienceLevel.Beginner]: 'the name helper',
    [AudienceLevel.Intermediate]: 'the phonebook that turns names into numbers',
    [AudienceLevel.Advanced]: 'the Domain Name System (DNS)',
    [AudienceLevel.Expert]: 'DNS',
    [AudienceLevel.Master]: 'RFC 1034, RFC 1035',
  },
  bgp: {
    [AudienceLevel.Beginner]: 'the internet connector',
    [AudienceLevel.Intermediate]: 'the system that connects different networks together',
    [AudienceLevel.Advanced]: 'the Border Gateway Protocol (BGP)',
    [AudienceLevel.Expert]: 'BGP',
    [AudienceLevel.Master]: 'RFC 4271',
  },
  eigrp: {
    [AudienceLevel.Beginner]: 'the route chooser',
    [AudienceLevel.Intermediate]: 'Cisco\'s system for finding the best path',
    [AudienceLevel.Advanced]: 'the Enhanced Interior Gateway Routing Protocol (EIGRP)',
    [AudienceLevel.Expert]: 'EIGRP',
    [AudienceLevel.Master]: 'RFC 7868',
  },
  rip: {
    [AudienceLevel.Beginner]: 'the simple path finder',
    [AudienceLevel.Intermediate]: 'the basic system that counts hops between networks',
    [AudienceLevel.Advanced]: 'the Routing Information Protocol (RIP)',
    [AudienceLevel.Expert]: 'RIP',
    [AudienceLevel.Master]: 'RFC 2453',
  },
  vrrp: {
    [AudienceLevel.Beginner]: 'the backup router',
    [AudienceLevel.Intermediate]: 'the system that provides a spare router if one fails',
    [AudienceLevel.Advanced]: 'the Virtual Router Redundancy Protocol (VRRP)',
    [AudienceLevel.Expert]: 'VRRP',
    [AudienceLevel.Master]: 'RFC 5798',
  },
  hsrp: {
    [AudienceLevel.Beginner]: 'Cisco\'s backup router',
    [AudienceLevel.Intermediate]: 'Cisco\'s system for having a spare router ready',
    [AudienceLevel.Advanced]: 'the Hot Standby Router Protocol (HSRP)',
    [AudienceLevel.Expert]: 'HSRP',
    [AudienceLevel.Master]: 'RFC 2281',
  },
  stp: {
    [AudienceLevel.Beginner]: 'the loop stopper',
    [AudienceLevel.Intermediate]: 'the system that prevents network loops',
    [AudienceLevel.Advanced]: 'the Spanning Tree Protocol (STP)',
    [AudienceLevel.Expert]: 'STP',
    [AudienceLevel.Master]: 'IEEE 802.1D',
  },
  rstp: {
    [AudienceLevel.Beginner]: 'the faster loop stopper',
    [AudienceLevel.Intermediate]: 'the quicker version of the loop prevention system',
    [AudienceLevel.Advanced]: 'the Rapid Spanning Tree Protocol (RSTP)',
    [AudienceLevel.Expert]: 'RSTP',
    [AudienceLevel.Master]: 'IEEE 802.1w',
  },
  mstp: {
    [AudienceLevel.Beginner]: 'the multi-loop stopper',
    [AudienceLevel.Intermediate]: 'the system that handles many loops at once',
    [AudienceLevel.Advanced]: 'the Multiple Spanning Tree Protocol (MSTP)',
    [AudienceLevel.Expert]: 'MSTP',
    [AudienceLevel.Master]: 'IEEE 802.1s',
  },
  vlan: {
    [AudienceLevel.Beginner]: 'the splitter',
    [AudienceLevel.Intermediate]: 'the way to split one network into smaller pieces',
    [AudienceLevel.Advanced]: 'Virtual Local Area Network (VLAN)',
    [AudienceLevel.Expert]: 'VLAN',
    [AudienceLevel.Master]: 'IEEE 802.1Q',
  },
  lacp: {
    [AudienceLevel.Beginner]: 'the link combiner',
    [AudienceLevel.Intermediate]: 'the system that joins multiple cables into one bigger pipe',
    [AudienceLevel.Advanced]: 'the Link Aggregation Control Protocol (LACP)',
    [AudienceLevel.Expert]: 'LACP',
    [AudienceLevel.Master]: 'IEEE 802.3ad',
  },
  nat: {
    [AudienceLevel.Beginner]: 'the address translator',
    [AudienceLevel.Intermediate]: 'the system that lets many devices share one public address',
    [AudienceLevel.Advanced]: 'Network Address Translation (NAT)',
    [AudienceLevel.Expert]: 'NAT',
    [AudienceLevel.Master]: 'RFC 3022',
  },
  pat: {
    [AudienceLevel.Beginner]: 'the port translator',
    [AudienceLevel.Intermediate]: 'the system that uses port numbers to share one address',
    [AudienceLevel.Advanced]: 'Port Address Translation (PAT)',
    [AudienceLevel.Expert]: 'PAT',
    [AudienceLevel.Master]: 'RFC 3022',
  },
  snmp: {
    [AudienceLevel.Beginner]: 'the network watcher',
    [AudienceLevel.Intermediate]: 'the system that monitors and manages network devices',
    [AudienceLevel.Advanced]: 'the Simple Network Management Protocol (SNMP)',
    [AudienceLevel.Expert]: 'SNMP',
    [AudienceLevel.Master]: 'RFC 1157',
  },
  ssh: {
    [AudienceLevel.Beginner]: 'the secure shell',
    [AudienceLevel.Intermediate]: 'the secure way to remotely control a device',
    [AudienceLevel.Advanced]: 'Secure Shell (SSH)',
    [AudienceLevel.Expert]: 'SSH',
    [AudienceLevel.Master]: 'RFC 4251',
  },
  telnet: {
    [AudienceLevel.Beginner]: 'the remote controller',
    [AudienceLevel.Intermediate]: 'the old way to control a device from far away',
    [AudienceLevel.Advanced]: 'Telnet',
    [AudienceLevel.Expert]: 'Telnet',
    [AudienceLevel.Master]: 'RFC 854',
  },
  ftp: {
    [AudienceLevel.Beginner]: 'the file mover',
    [AudienceLevel.Intermediate]: 'the system that transfers files between computers',
    [AudienceLevel.Advanced]: 'the File Transfer Protocol (FTP)',
    [AudienceLevel.Expert]: 'FTP',
    [AudienceLevel.Master]: 'RFC 959',
  },
  sftp: {
    [AudienceLevel.Beginner]: 'the secure file mover',
    [AudienceLevel.Intermediate]: 'the secure way to transfer files',
    [AudienceLevel.Advanced]: 'the SSH File Transfer Protocol (SFTP)',
    [AudienceLevel.Expert]: 'SFTP',
    [AudienceLevel.Master]: 'RFC 4251',
  },
  tftp: {
    [AudienceLevel.Beginner]: 'the simple file mover',
    [AudienceLevel.Intermediate]: 'the basic system for transferring files',
    [AudienceLevel.Advanced]: 'the Trivial File Transfer Protocol (TFTP)',
    [AudienceLevel.Expert]: 'TFTP',
    [AudienceLevel.Master]: 'RFC 1350',
  },
  ntp: {
    [AudienceLevel.Beginner]: 'the time keeper',
    [AudienceLevel.Intermediate]: 'the system that keeps all devices in sync time-wise',
    [AudienceLevel.Advanced]: 'the Network Time Protocol (NTP)',
    [AudienceLevel.Expert]: 'NTP',
    [AudienceLevel.Master]: 'RFC 5905',
  },
  lldp: {
    [AudienceLevel.Beginner]: 'the neighbor finder',
    [AudienceLevel.Intermediate]: 'the system that discovers nearby devices',
    [AudienceLevel.Advanced]: 'the Link Layer Discovery Protocol (LLDP)',
    [AudienceLevel.Expert]: 'LLDP',
    [AudienceLevel.Master]: 'IEEE 802.1AB',
  },
  cdp: {
    [AudienceLevel.Beginner]: 'Cisco\'s neighbor finder',
    [AudienceLevel.Intermediate]: 'Cisco\'s system for discovering nearby Cisco devices',
    [AudienceLevel.Advanced]: 'the Cisco Discovery Protocol (CDP)',
    [AudienceLevel.Expert]: 'CDP',
    [AudienceLevel.Master]: 'Cisco proprietary',
  },
  quic: {
    [AudienceLevel.Beginner]: 'the fast web rule',
    [AudienceLevel.Intermediate]: 'the new protocol that makes websites load quicker',
    [AudienceLevel.Advanced]: 'the Quick UDP Internet Connections (QUIC) protocol',
    [AudienceLevel.Expert]: 'QUIC',
    [AudienceLevel.Master]: 'RFC 9000',
  },
  tls: {
    [AudienceLevel.Beginner]: 'the security wrapper',
    [AudienceLevel.Intermediate]: 'the layer that keeps your data private',
    [AudienceLevel.Advanced]: 'the Transport Layer Security (TLS) protocol',
    [AudienceLevel.Expert]: 'TLS',
    [AudienceLevel.Master]: 'RFC 8446',
  },
  ssl: {
    [AudienceLevel.Beginner]: 'the old security wrapper',
    [AudienceLevel.Intermediate]: 'the older system that kept data private',
    [AudienceLevel.Advanced]: 'the Secure Sockets Layer (SSL)',
    [AudienceLevel.Expert]: 'SSL',
    [AudienceLevel.Master]: 'RFC 6101 (obsolete)',
  },
  '1000BASE-T': {
    [AudienceLevel.Beginner]: 'gigabit over copper',
    [AudienceLevel.Intermediate]: 'gigabit ethernet that runs on regular cables',
    [AudienceLevel.Advanced]: 'Gigabit Ethernet over copper (1000BASE-T)',
    [AudienceLevel.Expert]: '1000BASE-T',
    [AudienceLevel.Master]: 'IEEE 802.3ab',
  },
  '10GBASE-T': {
    [AudienceLevel.Beginner]: '10-gigabit over copper',
    [AudienceLevel.Intermediate]: '10-gigabit ethernet that runs on copper cables',
    [AudienceLevel.Advanced]: '10-Gigabit Ethernet over copper (10GBASE-T)',
    [AudienceLevel.Expert]: '10GBASE-T',
    [AudienceLevel.Master]: 'IEEE 802.3an',
  },
  '40GBASE-T': {
    [AudienceLevel.Beginner]: '40-gigabit over copper',
    [AudienceLevel.Intermediate]: '40-gigabit ethernet on twisted pair',
    [AudienceLevel.Advanced]: '40-Gigabit Ethernet over copper (40GBASE-T)',
    [AudienceLevel.Expert]: '40GBASE-T',
    [AudienceLevel.Master]: 'IEEE 802.3ba',
  },
  '2.5GBASE-T': {
    [AudienceLevel.Beginner]: '2.5-gigabit over copper',
    [AudienceLevel.Intermediate]: 'multigigabit ethernet for existing cables',
    [AudienceLevel.Advanced]: '2.5-Gigabit Ethernet (2.5GBASE-T)',
    [AudienceLevel.Expert]: '2.5GBASE-T',
    [AudienceLevel.Master]: 'IEEE 802.3bz',
  },
  '5GBASE-T': {
    [AudienceLevel.Beginner]: '5-gigabit over copper',
    [AudienceLevel.Intermediate]: 'faster multigigabit ethernet',
    [AudienceLevel.Advanced]: '5-Gigabit Ethernet (5GBASE-T)',
    [AudienceLevel.Expert]: '5GBASE-T',
    [AudienceLevel.Master]: 'IEEE 802.3bz',
  },
  '10GBASE-SR': {
    [AudienceLevel.Beginner]: '10-gigabit over fiber',
    [AudienceLevel.Intermediate]: '10-gigabit ethernet for short fiber runs',
    [AudienceLevel.Advanced]: '10-Gigabit Ethernet over multimode fiber (10GBASE-SR)',
    [AudienceLevel.Expert]: '10GBASE-SR',
    [AudienceLevel.Master]: 'IEEE 802.3ae',
  },
  'http/1.0': {
    [AudienceLevel.Beginner]: 'first web rule',
    [AudienceLevel.Intermediate]: 'the original version of web rules from the 1990s',
    [AudienceLevel.Advanced]: 'HTTP/1.0',
    [AudienceLevel.Expert]: 'HTTP/1.0',
    [AudienceLevel.Master]: 'RFC 1945',
  },
  'http/1.1': {
    [AudienceLevel.Beginner]: 'better web rule',
    [AudienceLevel.Intermediate]: 'the improved version of web rules from the 1990s',
    [AudienceLevel.Advanced]: 'HTTP/1.1',
    [AudienceLevel.Expert]: 'HTTP/1.1',
    [AudienceLevel.Master]: 'RFC 2616',
  },
  'http/2': {
    [AudienceLevel.Beginner]: 'faster web rule',
    [AudienceLevel.Intermediate]: 'the web rules from the 2010s that make pages load faster',
    [AudienceLevel.Advanced]: 'HTTP/2',
    [AudienceLevel.Expert]: 'HTTP/2',
    [AudienceLevel.Master]: 'RFC 7540',
  },
  'http/3': {
    [AudienceLevel.Beginner]: 'fastest web rule',
    [AudienceLevel.Intermediate]: 'the newest web rules from 2022 that make pages load even faster',
    [AudienceLevel.Advanced]: 'HTTP/3',
    [AudienceLevel.Expert]: 'HTTP/3',
    [AudienceLevel.Master]: 'RFC 9114',
  },
  'secure http': {
    [AudienceLevel.Beginner]: 'safe web rule',
    [AudienceLevel.Intermediate]: 'the rules for getting web pages safely using security wrappers',
    [AudienceLevel.Advanced]: 'Secure HTTP (HTTP over TLS)',
    [AudienceLevel.Expert]: 'HTTPS',
    [AudienceLevel.Master]: 'RFC 2818',
  },
  'recursive dns server': {
    [AudienceLevel.Beginner]: 'name helper that asks around',
    [AudienceLevel.Intermediate]: 'a name helper that asks other helpers until it finds the answer',
    [AudienceLevel.Advanced]: 'recursive DNS server',
    [AudienceLevel.Expert]: 'recursive resolver',
    [AudienceLevel.Master]: 'RFC 1034',
  },
  'web server': {
    [AudienceLevel.Beginner]: 'page keeper',
    [AudienceLevel.Intermediate]: 'a computer that stores and sends web pages to your browser',
    [AudienceLevel.Advanced]: 'web server',
    [AudienceLevel.Expert]: 'web server',
    [AudienceLevel.Master]: 'RFC 2616',
  },
};

export const ACL_TERMS: Record<string, Record<AudienceLevel, string>> = {
  'access control entry': {
    [AudienceLevel.Beginner]: 'one rule',
    [AudienceLevel.Intermediate]: 'a single line in a list of permission rules',
    [AudienceLevel.Advanced]: 'Access Control Entry (ACE)',
    [AudienceLevel.Expert]: 'ACE',
    [AudienceLevel.Master]: 'One configuration line in an ACL',
  },
  'access control list': {
    [AudienceLevel.Beginner]: 'rule list',
    [AudienceLevel.Intermediate]: 'a list of rules that decide what traffic gets through',
    [AudienceLevel.Advanced]: 'Access Control List (ACL)',
    [AudienceLevel.Expert]: 'ACL',
    [AudienceLevel.Master]: 'RFC 3198',
  },
  'acl persistence': {
    [AudienceLevel.Beginner]: 'rule keeper',
    [AudienceLevel.Intermediate]: 'keeps rule numbers the same when the router restarts',
    [AudienceLevel.Advanced]: 'ACL persistence',
    [AudienceLevel.Expert]: 'ACL persistence',
    [AudienceLevel.Master]: 'IOS XE feature',
  },
  'acl resequencing': {
    [AudienceLevel.Beginner]: 'renumbering rules',
    [AudienceLevel.Intermediate]: 'giving rules new numbers to make room for more',
    [AudienceLevel.Advanced]: 'ACL resequencing',
    [AudienceLevel.Expert]: 'ACL resequencing',
    [AudienceLevel.Master]: 'Cisco IOS feature',
  },
  'acl sequence number': {
    [AudienceLevel.Beginner]: 'rule number',
    [AudienceLevel.Intermediate]: 'a number that identifies each rule in a list',
    [AudienceLevel.Advanced]: 'ACL sequence number',
    [AudienceLevel.Expert]: 'sequence number',
    [AudienceLevel.Master]: 'Cisco IOS numbering',
  },
  'common acl': {
    [AudienceLevel.Beginner]: 'shared rule list',
    [AudienceLevel.Intermediate]: 'a rule list that can be used twice on the same connection',
    [AudienceLevel.Advanced]: 'Common ACL',
    [AudienceLevel.Expert]: 'Common ACL',
    [AudienceLevel.Master]: 'IOS XE feature',
  },
  'extended access list': {
    [AudienceLevel.Beginner]: 'detailed rule list',
    [AudienceLevel.Intermediate]: 'a rule list that looks at many parts of the traffic',
    [AudienceLevel.Advanced]: 'extended access list',
    [AudienceLevel.Expert]: 'extended ACL',
    [AudienceLevel.Master]: 'Cisco IOS feature',
  },
  'named access list': {
    [AudienceLevel.Beginner]: 'named rule list',
    [AudienceLevel.Intermediate]: 'a rule list identified by a name instead of a number',
    [AudienceLevel.Advanced]: 'named access list',
    [AudienceLevel.Expert]: 'named ACL',
    [AudienceLevel.Master]: 'Cisco IOS feature',
  },
  'standard access list': {
    [AudienceLevel.Beginner]: 'simple rule list',
    [AudienceLevel.Intermediate]: 'a rule list that only looks at where traffic comes from',
    [AudienceLevel.Advanced]: 'standard access list',
    [AudienceLevel.Expert]: 'standard ACL',
    [AudienceLevel.Master]: 'Cisco IOS feature',
  },
  'vty acl': {
    [AudienceLevel.Beginner]: 'remote control rule list',
    [AudienceLevel.Intermediate]: 'a rule list that controls who can remotely control the device',
    [AudienceLevel.Advanced]: 'VTY ACL',
    [AudienceLevel.Expert]: 'VTY ACL',
    [AudienceLevel.Master]: 'Cisco IOS feature',
  },
  'wildcard mask': {
    [AudienceLevel.Beginner]: 'matching helper',
    [AudienceLevel.Intermediate]: 'a pattern that tells which parts of an address to check',
    [AudienceLevel.Advanced]: 'wildcard mask',
    [AudienceLevel.Expert]: 'wildcard mask',
    [AudienceLevel.Master]: 'Cisco ACL matching',
  },
};

export const CONNECTION_TERMS: Record<string, Record<AudienceLevel, string>> = {
  'connection establishment': {
    [AudienceLevel.Beginner]: 'handshake',
    [AudienceLevel.Intermediate]: 'the three-way handshake to set up a reliable connection',
    [AudienceLevel.Advanced]: 'connection establishment',
    [AudienceLevel.Expert]: 'TCP 3-way handshake',
    [AudienceLevel.Master]: 'TCP connection establishment (RFC 793)',
  },
  'forward acknowledgment': {
    [AudienceLevel.Beginner]: 'receipt confirmation',
    [AudienceLevel.Intermediate]: 'letting the sender know data was received',
    [AudienceLevel.Advanced]: 'forward acknowledgment',
    [AudienceLevel.Expert]: 'ACK',
    [AudienceLevel.Master]: 'TCP acknowledgment (RFC 793)',
  },
  'ordered data transfer': {
    [AudienceLevel.Beginner]: 'in-order delivery',
    [AudienceLevel.Intermediate]: 'making sure data arrives in the correct order',
    [AudienceLevel.Advanced]: 'ordered data transfer',
    [AudienceLevel.Expert]: 'sequence number ordering',
    [AudienceLevel.Master]: 'TCP ordered delivery (RFC 793)',
  },
  'segment': {
    [AudienceLevel.Beginner]: 'data chunk',
    [AudienceLevel.Intermediate]: 'a piece of data with a TCP wrapper around it',
    [AudienceLevel.Advanced]: 'TCP segment',
    [AudienceLevel.Expert]: 'segment',
    [AudienceLevel.Master]: 'TCP segment (RFC 793)',
  },
  'uri': {
    [AudienceLevel.Beginner]: 'web address',
    [AudienceLevel.Intermediate]: 'the address you type to find something on the web',
    [AudienceLevel.Advanced]: 'Uniform Resource Identifier (URI)',
    [AudienceLevel.Expert]: 'URI',
    [AudienceLevel.Master]: 'RFC 3986',
  },
  'port': {
    [AudienceLevel.Beginner]: 'door',
    [AudienceLevel.Intermediate]: 'a numbered door that leads to a specific application',
    [AudienceLevel.Advanced]: 'port number',
    [AudienceLevel.Expert]: 'port',
    [AudienceLevel.Master]: 'transport layer port (RFC 6335)',
  },
};

export const ACTION_VERBS: Record<string, Record<AudienceLevel, string>> = {
  permit: {
    [AudienceLevel.Beginner]: 'Lets through',
    [AudienceLevel.Intermediate]: 'Lets in',
    [AudienceLevel.Advanced]: 'Permits',
    [AudienceLevel.Expert]: 'Permits',
    [AudienceLevel.Master]: 'Permits (action of PASS)',
  },
  deny: {
    [AudienceLevel.Beginner]: 'Stops',
    [AudienceLevel.Intermediate]: 'Keeps out',
    [AudienceLevel.Advanced]: 'Denies',
    [AudienceLevel.Expert]: 'Denies',
    [AudienceLevel.Master]: 'Denies (action of DROP)',
  },
};

export const ACTION_VERBS_LOWER: Record<string, Record<AudienceLevel, string>> = {
  permit: {
    [AudienceLevel.Beginner]: 'lets through',
    [AudienceLevel.Intermediate]: 'lets in',
    [AudienceLevel.Advanced]: 'permits',
    [AudienceLevel.Expert]: 'permits',
    [AudienceLevel.Master]: 'permits (PASS)',
  },
  deny: {
    [AudienceLevel.Beginner]: 'stops',
    [AudienceLevel.Intermediate]: 'keeps out',
    [AudienceLevel.Advanced]: 'denies',
    [AudienceLevel.Expert]: 'denies',
    [AudienceLevel.Master]: 'denies (DROP)',
  },
};

export const COMMUNICATION_TERMS: Record<AudienceLevel, string[]> = {
  [AudienceLevel.Beginner]: ['messages', 'stuff you send', 'information'],
  [AudienceLevel.Intermediate]: ['data', 'traffic', 'communications'],
  [AudienceLevel.Advanced]: ['packets', 'segments', 'datagrams'],
  [AudienceLevel.Expert]: ['packets', 'segments', 'datagrams'],
  [AudienceLevel.Master]: ['PDUs', 'packets', 'datagrams'],
};

export const LAYER_DESCRIPTIONS: Record<AudienceLevel, string> = {
  [AudienceLevel.Beginner]: 'way of sending',
  [AudienceLevel.Intermediate]: 'how the information is packaged',
  [AudienceLevel.Advanced]: 'protocol layer',
  [AudienceLevel.Expert]: 'OSI layer',
  [AudienceLevel.Master]: 'OSI layer (ISO/IEC 7498-1)',
};

export const INSPECTION_TERMS: Record<AudienceLevel, string> = {
  [AudienceLevel.Beginner]: 'looks at',
  [AudienceLevel.Intermediate]: 'takes a peek at',
  [AudienceLevel.Advanced]: 'inspects',
  [AudienceLevel.Expert]: 'inspects',
  [AudienceLevel.Master]: 'performs stateful inspection (RFC 2979)',
};

export const PORT_TERMS: Record<string, Record<AudienceLevel, string>> = {
  port: {
    [AudienceLevel.Beginner]: 'door',
    [AudienceLevel.Intermediate]: 'door number that leads to a specific application',
    [AudienceLevel.Advanced]: 'port number',
    [AudienceLevel.Expert]: 'port',
    [AudienceLevel.Master]: 'transport layer port (RFC 6335)',
  },
};

export const SEQUENCE_TERMS: Record<string, Record<AudienceLevel, string>> = {
  'sequence number': {
    [AudienceLevel.Beginner]: 'order number',
    [AudienceLevel.Intermediate]: 'number that puts pieces back in the right order',
    [AudienceLevel.Advanced]: 'sequence number',
    [AudienceLevel.Expert]: 'sequence number',
    [AudienceLevel.Master]: '32-bit sequence number (RFC 793)',
  },
};

export const ERROR_TERMS: Record<string, Record<AudienceLevel, string>> = {
  'error detection': {
    [AudienceLevel.Beginner]: 'finding mistakes',
    [AudienceLevel.Intermediate]: 'spotting if something got messed up along the way',
    [AudienceLevel.Advanced]: 'error detection',
    [AudienceLevel.Expert]: 'error detection',
    [AudienceLevel.Master]: 'checksum verification (RFC 793, RFC 768)',
  },
  'error recovery': {
    [AudienceLevel.Beginner]: 'fixing mistakes',
    [AudienceLevel.Intermediate]: 'asking for the messed-up part again',
    [AudienceLevel.Advanced]: 'error recovery',
    [AudienceLevel.Expert]: 'error recovery',
    [AudienceLevel.Master]: 'automatic repeat request (ARQ) (RFC 793)',
  },
};

export const FLOW_CONTROL_TERMS: Record<string, Record<AudienceLevel, string>> = {
  'flow control': {
    [AudienceLevel.Beginner]: 'speed matching',
    [AudienceLevel.Intermediate]: 'not sending faster than the receiver can handle',
    [AudienceLevel.Advanced]: 'flow control',
    [AudienceLevel.Expert]: 'flow control',
    [AudienceLevel.Master]: 'sliding window flow control (RFC 793)',
  },
  'sliding windows': {
    [AudienceLevel.Beginner]: 'sending windows',
    [AudienceLevel.Intermediate]: 'sending several pieces before waiting for a "got it"',
    [AudienceLevel.Advanced]: 'sliding windows',
    [AudienceLevel.Expert]: 'sliding windows',
    [AudienceLevel.Master]: 'sliding window mechanism (RFC 793)',
  },
  'congestion control': {
    [AudienceLevel.Beginner]: 'traffic management',
    [AudienceLevel.Intermediate]: 'slowing down when the network is busy',
    [AudienceLevel.Advanced]: 'congestion control',
    [AudienceLevel.Expert]: 'congestion control',
    [AudienceLevel.Master]: 'TCP congestion control (RFC 5681)',
  },
};

export const ADDRESSING_TERMS: Record<string, Record<AudienceLevel, string>> = {
  'mac address': {
    [AudienceLevel.Beginner]: 'hardware ID',
    [AudienceLevel.Intermediate]: 'the unique ID burned into your network card',
    [AudienceLevel.Advanced]: 'MAC address',
    [AudienceLevel.Expert]: 'MAC address',
    [AudienceLevel.Master]: 'Media Access Control address (IEEE 802)',
  },
  'ipv4 address': {
    [AudienceLevel.Beginner]: 'network ID',
    [AudienceLevel.Intermediate]: 'the 32-bit number that identifies your device',
    [AudienceLevel.Advanced]: 'IPv4 address',
    [AudienceLevel.Expert]: 'IPv4 address',
    [AudienceLevel.Master]: '32-bit IPv4 address (RFC 791)',
  },
  'ipv6 address': {
    [AudienceLevel.Beginner]: 'new network ID',
    [AudienceLevel.Intermediate]: 'the 128-bit number that identifies your device',
    [AudienceLevel.Advanced]: 'IPv6 address',
    [AudienceLevel.Expert]: 'IPv6 address',
    [AudienceLevel.Master]: '128-bit IPv6 address (RFC 8200)',
  },
  'subnet mask': {
    [AudienceLevel.Beginner]: 'network divider',
    [AudienceLevel.Intermediate]: 'the number that splits network from device',
    [AudienceLevel.Advanced]: 'subnet mask',
    [AudienceLevel.Expert]: 'subnet mask',
    [AudienceLevel.Master]: 'network mask (RFC 950)',
  },
  'cidr': {
    [AudienceLevel.Beginner]: 'slash notation',
    [AudienceLevel.Intermediate]: 'the /number after an IP address',
    [AudienceLevel.Advanced]: 'CIDR notation',
    [AudienceLevel.Expert]: 'CIDR',
    [AudienceLevel.Master]: 'Classless Inter-Domain Routing (RFC 4632)',
  },
  'default gateway': {
    [AudienceLevel.Beginner]: 'the exit door',
    [AudienceLevel.Intermediate]: 'the router that leads out of your network',
    [AudienceLevel.Advanced]: 'default gateway',
    [AudienceLevel.Expert]: 'default gateway',
    [AudienceLevel.Master]: 'default route (RFC 1812)',
  },
};