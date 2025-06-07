import os
import re
import socket
import datetime
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET

class GrandstreamTemplateGenerator:
    """Template generator for Grandstream devices (cfgmac.xml files)"""

    def _normalize_mac(self, mac):
        """Normalize MAC address: remove colons and convert to lowercase"""
        return mac.replace(":", "").lower()

    def _validate_mac(self, mac):
        """Accept both colon-separated and non-colon formats (12 hex digits)"""
        mac_clean = mac.replace(":", "").upper()
        if not re.fullmatch(r"[0-9A-F]{12}", mac_clean):
            raise ValueError(f"Invalid MAC address format: {mac}")
        return mac_clean.lower()

    def _validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
        except socket.error:
            raise ValueError(f"Invalid IP address: {ip}")

    def generate_xml_file(self, mac, local_ip, port):
        """Generate Grandstream XML configuration file (cfgmac.xml format)"""
        mac = self._validate_mac(mac)
        self._validate_ip(local_ip)

        xml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
<gs_provision version="1">
  <config version="1">
    <P8>1</P8>
    <P84>pool.ntp.org</P84>

    <!-- Account 1 -->
    <P271>1</P271>
    <P47>sip.example.com</P47>
    <P48>5060</P48>
    <P35>{mac}</P35>
    <P34>password123</P34>
    <P3>{mac}</P3>

    <!-- Provisioning and Upgrade Settings -->
    <P237>1</P237>
    <P192>http://{local_ip}:{port}/configs</P192>
    <P1359>admin</P1359>
    <P1360>admin</P1360>
    <P238>1</P238>
    <P240>1</P240>
    <P194>60</P194>
    <P232>admin</P232>
    <P2>Admin</P2>
    <P212>1</P212>
    <P193>1</P193>
    <P145>1</P145>
    <P285>1</P285>
  </config>
</gs_provision>
"""
        ET.fromstring(xml_template)
        return xml_template

    def generate_xml_file_with_extensions(self, mac, local_ip, port, extension_data_list):
        """Generate Grandstream XML configuration file with multiple extensions (cfgmac.xml format)"""
        mac = self._validate_mac(mac)
        self._validate_ip(local_ip)
        
        xml_template = """<?xml version="1.0" encoding="UTF-8"?>
<gs_provision version="1">
  <config version="2">
"""
        
        # Add comment for clarity
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        xml_template += f"    <!-- Configuration for cfg{mac}.xml generated on {now} -->\n"
        
        # Add network settings
        xml_template += """
    <!-- Network Settings -->
    <P8>1</P8>
    <P84>pool.ntp.org</P84>
"""
        
        # Add account settings using P-value format
        for i, ext in enumerate(extension_data_list, 1):
            if i > 6:  # Grandstream typically supports up to 6 accounts
                break
                
            extension = escape(ext.get("extension", f"Ext{i}"))
            username = escape(ext.get("username", ""))
            password = escape(ext.get("password", ""))
            domain = escape(ext.get("domain", ""))
            
            # Calculate P-value offsets for each account
            base_offset = (i - 1) * 100 if i > 1 else 0
            
            xml_template += f"""
    <!-- Account {i} Settings -->
    <P{271 + base_offset}>1</P{271 + base_offset}>
    <P{270 + base_offset}>{extension}</P{270 + base_offset}>
    <P{47 + base_offset}>{domain}</P{47 + base_offset}>
    <P{48 + base_offset}>5060</P{48 + base_offset}>
    <P{35 + base_offset}>{username}</P{35 + base_offset}>
    <P{36 + base_offset}>{username}</P{36 + base_offset}>
    <P{34 + base_offset}>{password}</P{34 + base_offset}>
    <P{3 + base_offset}>{extension}</P{3 + base_offset}>
"""
        
        # Add provisioning settings
        xml_template += f"""
    <!-- Provisioning Settings -->
    <P237>1</P237>
    <P192>http://{local_ip}:{port}/configs</P192>
    <P1359>admin</P1359>
    <P1360>admin</P1360>
    <P238>1</P238>
    <P240>1</P240>
    <P194>60</P194>
    <P232>admin</P232>
    <P2>Admin</P2>
    <P212>1</P212>
    <P193>1</P193>
    <P145>1</P145>
    <P285>1</P285>
  </config>
</gs_provision>
"""
        
        # Validate XML
        ET.fromstring(xml_template)
        return xml_template

    def _write_file(self, path, content):
        with open(path, "w") as f:
            f.write(content)

    def generate_all_config_files(self, mac, configs_dir, local_ip, port):
        """Generate standard config files (cfgmac.xml format)"""
        mac_clean = self._validate_mac(mac)
        config_files = []

        # Generate XML file in cfgmac.xml format
        xml_content = self.generate_xml_file(mac, local_ip, port)
        
        # Save as cfg{mac}.xml (standard Grandstream format)
        xml_file = os.path.join(configs_dir, f"cfg{mac_clean}.xml")
        self._write_file(xml_file, xml_content)
        config_files.append(xml_file)
            
        return config_files

    def generate_all_config_files_with_extensions(self, mac, configs_dir, local_ip, port, extension_data_list):
        """Generate config files with multiple SIP accounts (cfgmac.xml format)"""
        mac_clean = self._validate_mac(mac)
        self._validate_ip(local_ip)
        config_files = []

        # Generate XML content with extensions in cfgmac.xml format
        xml_content = self.generate_xml_file_with_extensions(mac, local_ip, port, extension_data_list)
        
        # Save as cfg{mac}.xml (standard Grandstream format)
        xml_file = os.path.join(configs_dir, f"cfg{mac_clean}.xml")
        self._write_file(xml_file, xml_content)
        config_files.append(xml_file)
            
        return config_files
