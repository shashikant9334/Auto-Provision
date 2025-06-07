import os
import datetime

class CiscoTemplateGenerator:
    """Template generator for Cisco devices (config/CP_xxxx_MPP.cfg format)"""
    
    def generate_config_file(self, mac, local_ip, port):
        """Generate Cisco configuration file"""
        cfg_content = f"""
<device>
  <deviceProtocol>SIP</deviceProtocol>
  <devicePool>
      <dateTimeSetting>
          <ntpServer1>{local_ip}</ntpServer1>
          <timeZone>GMT</timeZone>
      </dateTimeSetting>
  </devicePool>
  <sipProfile>
      <sipProxies>
          <outboundProxy>sip.example.com</outboundProxy>
          <outboundProxyPort>5060</outboundProxyPort>
          <registerWithProxy>true</registerWithProxy>
      </sipProxies>
  </sipProfile>
  <commonProfile>
      <phonePassword>password123</phonePassword>
  </commonProfile>
  <loadInformation>{mac}</loadInformation>
  <authenticationURL>http://{local_ip}:{port}/config</authenticationURL>
</device>
"""
        return cfg_content
    
    def generate_all_config_files(self, mac, configs_dir, local_ip, port):
        """Generate all configuration files for a Cisco device (config/CP_xxxx_MPP.cfg format)"""
        config_files = []
        
        # Create cisco/config directory structure
        cisco_config_dir = os.path.join(os.path.dirname(configs_dir), "config")
        os.makedirs(cisco_config_dir, exist_ok=True)
        
        # Generate and save the configuration file in Cisco format
        cisco_file = os.path.join(cisco_config_dir, f"CP_{mac.upper()}_MPP.cfg")
        with open(cisco_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port))
        config_files.append(cisco_file)
        
        return config_files
    
    def generate_all_config_files_with_extensions(self, mac, configs_dir, local_ip, port, extension_data_list):
        """Generate all configuration files for a Cisco device with multiple extensions (config/CP_xxxx_MPP.cfg format)"""
        config_files = []
        
        # Create cisco/config directory structure
        cisco_config_dir = os.path.join(os.path.dirname(configs_dir),  "config")
        os.makedirs(cisco_config_dir, exist_ok=True)
        
        # Start Cisco XML configuration
        cfg_content = f"""
<device>
  <deviceProtocol>SIP</deviceProtocol>
  <devicePool>
      <dateTimeSetting>
          <ntpServer1>{local_ip}</ntpServer1>
          <timeZone>GMT</timeZone>
      </dateTimeSetting>
  </devicePool>
  <sipProfile>
      <sipProxies>
"""
        
        # Add the first extension's domain as the primary outbound proxy
        if extension_data_list:
            domain = extension_data_list[0]["domain"]
            cfg_content += f"""            <outboundProxy>{domain}</outboundProxy>
          <outboundProxyPort>5060</outboundProxyPort>
          <registerWithProxy>true</registerWithProxy>
"""
        
        # Continue with the rest of the configuration
        cfg_content += f"""        </sipProxies>
      <sipCallFeatures>
          <cnfJoinEnabled>true</cnfJoinEnabled>
          <callForwardURI>x-serviceuri-cfwdall</callForwardURI>
          <callPickupURI>x-cisco-serviceuri-pickup</callPickupURI>
          <callPickupListURI>x-cisco-serviceuri-opickup</callPickupListURI>
          <callPickupGroupURI>x-cisco-serviceuri-gpickup</callPickupGroupURI>
          <meetMeServiceURI>x-cisco-serviceuri-meetme</meetMeServiceURI>
          <abbreviatedDialURI>x-cisco-serviceuri-abbrdial</abbreviatedDialURI>
      </sipCallFeatures>
  </sipProfile>
  
  <!-- Line configurations -->
"""
        
        # Add line configurations for each extension
        for i, extension_data in enumerate(extension_data_list, 1):
            extension = extension_data["extension"]
            username = extension_data["username"]
            password = extension_data["password"]
            domain = extension_data["domain"]
            
            cfg_content += f"""    <line{i}>
      <featureID>9</featureID>
      <featureLabel>{extension}</featureLabel>
      <proxy>{domain}</proxy>
      <port>5060</port>
      <name>{username}</name>
      <displayName>{extension}</displayName>
      <authName>{username}</authName>
      <authPassword>{password}</authPassword>
      <contact>{username}</contact>
      <registerWithProxy>true</registerWithProxy>
  </line{i}>
"""
        
        # Complete the configuration
        cfg_content += f"""
  <commonProfile>
      <phonePassword>password123</phonePassword>
      <backgroundImageAccess>true</backgroundImageAccess>
      <callLogBlfEnabled>true</callLogBlfEnabled>
  </commonProfile>
  <loadInformation>{mac}</loadInformation>
  <vendorConfig>
      <disableSpeaker>false</disableSpeaker>
      <disableSpeakerAndHeadset>false</disableSpeakerAndHeadset>
      <pcPort>enabled</pcPort>
      <settingsAccess>enabled</settingsAccess>
      <garp>enabled</garp>
      <voiceVlanAccess>enabled</voiceVlanAccess>
      <autoSelectLineEnable>disabled</autoSelectLineEnable>
      <webAccess>1</webAccess>
      <daysDisplayNotActive>1,2,3,4,5,6,7</daysDisplayNotActive>
      <displayOnTime>08:30</displayOnTime>
      <displayOnDuration>11:30</displayOnDuration>
      <displayIdleTimeout>01:00</displayIdleTimeout>
  </vendorConfig>
  <networkLocale>United_States</networkLocale>
  <networkLocaleInfo>
      <name>United_States</name>
      <uid>64</uid>
      <version>1.0.0.0-1</version>
  </networkLocaleInfo>
  <deviceSecurityMode>1</deviceSecurityMode>
  <authenticationURL>http://{local_ip}:{port}/config</authenticationURL>
  <directoryURL>http://{local_ip}:{port}/directory</directoryURL>
  <servicesURL>http://{local_ip}:{port}/services</servicesURL>
  <idleURL>http://{local_ip}:{port}/idle</idleURL>
  <informationURL>http://{local_ip}:{port}/info</informationURL>
  <messagesURL>http://{local_ip}:{port}/messages</messagesURL>
  <proxyServerURL>http://{local_ip}:{port}/proxy</proxyServerURL>
</device>
"""
        
        # Save the configuration file in Cisco format
        cisco_file = os.path.join(cisco_config_dir, f"CP_{mac.upper()}_MPP.cfg")
        with open(cisco_file, "w") as f:
            f.write(cfg_content)
        config_files.append(cisco_file)
        
        return config_files
