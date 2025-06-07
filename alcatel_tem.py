import os
import datetime

class AlcatelTemplateGenerator:
    """Template generator for Alcatel devices (config.xml format)"""
    
    def generate_xml_file(self, mac, local_ip, port):
        """Generate Alcatel XML configuration file (config.xml format)"""
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<alcatel_config>
    <device>
        <mac>{mac}</mac>
        <provision>
            <server>http://{local_ip}:{port}/configs</server>
            <username>admin</username>
            <password>admin</password>
        </provision>
        <account>
            <index>1</index>
            <active>1</active>
            <label>{mac}</label>
            <display_name>{mac}</display_name>
            <auth_name>{mac}</auth_name>
            <user_name>{mac}</user_name>
            <password>password123</password>
            <sip_server>sip.example.com</sip_server>
            <sip_port>5060</sip_port>
        </account>
    </device>
</alcatel_config>
"""
        return xml_content
    
    def generate_xml_file_with_extensions(self, mac, local_ip, port, extension_data_list):
        """Generate Alcatel XML configuration file with multiple extensions (config.xml format)"""
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<alcatel_config>
    <device>
        <mac>{mac}</mac>
        <provision>
            <server>http://{local_ip}:{port}/configs</server>
            <username>admin</username>
            <password>admin</password>
        </provision>
"""
        
        # Add extension configurations
        for i, extension_data in enumerate(extension_data_list, 1):
            extension = extension_data["extension"]
            username = extension_data["username"]
            password = extension_data["password"]
            domain = extension_data["domain"]
            
            xml_content += f"""        <account>
            <index>{i}</index>
            <active>1</active>
            <label>{extension}</label>
            <display_name>{extension}</display_name>
            <auth_name>{username}</auth_name>
            <user_name>{username}</user_name>
            <password>{password}</password>
            <sip_server>{domain}</sip_server>
            <sip_port>5060</sip_port>
        </account>
"""
        
        xml_content += """    </device>
</alcatel_config>
"""
        return xml_content
    
    def generate_all_config_files(self, mac, configs_dir, local_ip, port):
        """Generate all configuration files for an Alcatel device (config.xml format)"""
        config_files = []
        
        # Generate and save the XML configuration file
        xml_file = os.path.join(configs_dir, f"{mac}.xml")
        with open(xml_file, "w") as f:
            f.write(self.generate_xml_file(mac, local_ip, port))
        config_files.append(xml_file)
        
        return config_files
    
    def generate_all_config_files_with_extensions(self, mac, configs_dir, local_ip, port, extension_data_list):
        """Generate all configuration files for an Alcatel device with multiple extensions (config.xml format)"""
        config_files = []
        
        # Generate and save the XML configuration file
        xml_file = os.path.join(configs_dir, f"{mac}.xml")
        with open(xml_file, "w") as f:
            f.write(self.generate_xml_file_with_extensions(mac, local_ip, port, extension_data_list))
        config_files.append(xml_file)
        
        return config_files
