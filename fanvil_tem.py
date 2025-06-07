import os
import datetime

class FanvilTemplateGenerator:
    """Template generator for Fanvil devices (.cfg format)"""
    
    def generate_config_file(self, mac, local_ip, port, extension_data_list=None):
        """Generate Fanvil configuration file"""
        cfg_content = f"""
# Auto-generated Fanvil configuration file for {mac}
# Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

# Network Settings
net.dhcp = 1
net.ntp_server = pool.ntp.org

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
        
        # Add Fanvil-specific settings
        cfg_content += f"""
# Fanvil-specific settings
auto_provision.server.url = http://{local_ip}:{port}/configs
auto_provision.server.username = admin
auto_provision.server.password = admin
"""
        
        return cfg_content
    
    def generate_all_config_files(self, mac, configs_dir, local_ip, port):
        """Generate all configuration files for a Fanvil device (.cfg format)"""
        config_files = []
        
        # Generate and save the configuration file
        cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
        with open(cfg_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port))
        config_files.append(cfg_file)
        
        return config_files
    
    def generate_all_config_files_with_extensions(self, mac, configs_dir, local_ip, port, extension_data_list):
        """Generate all configuration files for a Fanvil device with multiple extensions (.cfg format)"""
        config_files = []
        
        # Generate and save the configuration file
        cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
        with open(cfg_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port, extension_data_list))
        config_files.append(cfg_file)
        
        return config_files
