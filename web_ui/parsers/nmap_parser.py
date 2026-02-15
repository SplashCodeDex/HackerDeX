import re
from parsers.base_parser import BaseParser

class NmapParser(BaseParser):
    def can_parse(self, tool_name: str) -> bool:
        return tool_name.lower() in ['nmap', 'network map', 'nmap scan']

    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        findings = {
            "ports": [],
            "vulns": [],
            "urls": [],
            "technologies": [],
            "os_info": {}
        }

        try:
            # Check if output is actually XML (sometimes nmap fails and prints text)
            if not raw_output.strip().startswith('<?xml') and not raw_output.strip().startswith('<nmaprun'):
                # Fallback to simple text parsing or return partial
                return self._parse_text_fallback(raw_output, findings)

            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_output)

            for host in root.findall('host'):
                # OS Detection
                os_match = host.find('os/osmatch')
                if os_match:
                    findings['os_info']['name'] = os_match.get('name')
                    findings['os_info']['accuracy'] = os_match.get('accuracy')

                # Port Scanning
                ports = host.find('ports')
                if ports:
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_id = int(port.get('portid'))
                            protocol = port.get('protocol')

                            service = port.find('service')
                            service_name = "unknown"
                            version = ""

                            if service is not None:
                                service_name = service.get('name', 'unknown')
                                product = service.get('product', '')
                                version = service.get('version', '')
                                extrainfo = service.get('extrainfo', '')
                                full_version = f"{product} {version} {extrainfo}".strip()

                                # Tech detection
                                if product:
                                    findings['technologies'].append({
                                        'name': product,
                                        'version': version,
                                        'type': service_name
                                    })
                            else:
                                full_version = ""

                            findings['ports'].append({
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "version": full_version
                            })

                            # Script Outputs (vulns, http-title)
                            for script in port.findall('script'):
                                script_id = script.get('id')
                                output = script.get('output')

                                if script_id == 'http-title':
                                    title = output.strip()
                                    findings['urls'].append(f"http://{target}:{port_id}/ - {title}")

                                if 'vuln' in script_id or 'exploit' in script_id:
                                    findings['vulns'].append({
                                        "title": f"Nmap NSE: {script_id}",
                                        "severity": "high",
                                        "details": output,
                                        "url": f"{target}:{port_id}"
                                    })

        except Exception as e:
            print(f"XML Parsing failed: {e}. Falling back to text.")
            return self._parse_text_fallback(raw_output, findings)

        return findings

    def _parse_text_fallback(self, raw_output, findings):
        # Quick fallback for non-XML output
        port_pattern = re.compile(r'(\d+)/(tcp|udp)\s+(open|filtered)\s+([^\s]+)\s*(.*)', re.IGNORECASE)
        for line in raw_output.splitlines():
            match = port_pattern.search(line)
            if match and match.group(3) == 'open':
                findings['ports'].append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "service": match.group(4),
                    "version": match.group(5).strip()
                })
        return findings
