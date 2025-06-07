import os
import datetime

class NeronTemplateGenerator:
    """Template generator for Neron devices (.cfg only)"""

    def generate_config_file(self, mac, local_ip, port, extension_data_list=None):
        """Generate the content of the .cfg file for a Neron device"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cfg_content = f"""# Auto-generated Neron configuration file for {mac}.cfg
# Generated on {now}

# Network Settings
network.dhcp_enable = 1
network.static_dns_enable = 0

# Audio Settings
voice.tone.country = Custom
voice.ring_vol = 6

# Time Settings
local_time.time_format = 1
local_time.date_format = 0
local_time.ntp_server1 = pool.ntp.org
"""

        # Add account(s)
        if extension_data_list:
            for i, ext in enumerate(extension_data_list, 1):
                extension = ext["extension"]
                username = ext["username"]
                password = ext["password"]
                domain = ext["domain"]

                cfg_content += f"""
# Account {i} Settings
account.{i}.enable = 1
account.{i}.label = {extension}
account.{i}.display_name = {extension}
account.{i}.auth_name = {username}
account.{i}.user_name = {username}
account.{i}.password = {password}
account.{i}.sip_server.1.address = {domain}
account.{i}.sip_server.1.port = 5060
account.{i}.sip_server.1.transport_type = 0
"""
        else:
            # Default single account using MAC as identity
            cfg_content += f"""
# Account 1 Settings
account.1.enable = 1
account.1.label = {mac}
account.1.display_name = {mac}
account.1.auth_name = {mac}
account.1.user_name = {mac}
account.1.password = password123
account.1.sip_server.1.address = sip.example.com
account.1.sip_server.1.port = 5060
account.1.sip_server.1.transport_type = 0
"""

        # Neron provisioning
        cfg_content += f"""
# Neron-specific settings
neron.auto_provision.server.url = http://{local_ip}:{port}/configs
neron.auto_provision.server.username = admin
neron.auto_provision.server.password = admin
"""

        return cfg_content.strip()
    
    def generate_all_config_files(self, mac, configs_dir, local_ip, port):
        """Generate all configuration files for a Neron device (only .cfg)"""
        config_files = []
        
        # Generate and save the configuration file
        cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
        with open(cfg_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port))
        config_files.append(cfg_file)
        
        return config_files
    
    def generate_all_config_files_with_extensions(self, mac, configs_dir, local_ip, port, extension_data_list):
        """Generate all configuration files for a Neron device with multiple extensions (only .cfg)"""
        config_files = []
        
        # Generate and save the configuration file
        cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
        with open(cfg_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port, extension_data_list))
        config_files.append(cfg_file)
        
        return config_files
