import os
import datetime

class GenericTemplateGenerator:
    """Template generator for generic/unknown devices"""
    
    def generate_config_file(self, mac, local_ip, port, extension_data_list=None):
        """Generate generic configuration file"""
        cfg_content = f"""
# Auto-generated generic configuration file for {mac}
# Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

# Network Settings
network.dhcp_enable = 1
network.static_dns_enable = 0

# Time Settings
time.ntp_server = pool.ntp.org

"""
        
        # Add account(s)
        if extension_data_list:
            for i, extension_data in enumerate(extension_data_list, 1):
                extension = extension_data["extension"]
                username = extension_data["username"]
                password = extension_data["password"]
                domain = extension_data["domain"]
                
                cfg_content += f"""
# Account {i} Settings
account.{i}.enable = 1
account.{i}.label = {extension}
account.{i}.display_name = {extension}
account.{i}.auth_name = {username}
account.{i}.user_name = {username}
account.{i}.password = {password}
account.{i}.sip_server = {domain}
account.{i}.sip_port = 5060
"""
        else:
            # Default single account
            cfg_content += f"""
# Account 1 Settings
account.1.enable = 1
account.1.label = {mac}
account.1.display_name = {mac}
account.1.auth_name = {mac}
account.1.user_name = {mac}
account.1.password = password123
account.1.sip_server = sip.example.com
account.1.sip_port = 5060
"""
        
        # Add provisioning settings
        cfg_content += f"""
# Provisioning Settings
provisioning.server = http://{local_ip}:{port}/configs
provisioning.username = admin
provisioning.password = admin
"""
        
        return cfg_content
    
    def generate_all_config_files(self, mac, configs_dir, local_ip, port):
        """Generate all configuration files for a generic device"""
        config_files = []
        
        # Generate and save the configuration file
        cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
        with open(cfg_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port))
        config_files.append(cfg_file)
        
        return config_files
    
    def generate_all_config_files_with_extensions(self, mac, configs_dir, local_ip, port, extension_data_list):
        """Generate all configuration files for a generic device with multiple extensions"""
        config_files = []
        
        # Generate and save the configuration file
        cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
        with open(cfg_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port, extension_data_list))
        config_files.append(cfg_file)
        
        return config_files
