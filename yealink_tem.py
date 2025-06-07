import os
import datetime

class YealinkTemplateGenerator:
    """Template generator for Yealink devices (.boot and .cfg files)"""
    
    def generate_boot_file(self, mac, local_ip, port):
        """Generate Yealink boot file"""
        boot_content = f"""#!version:1.0.0.1
## The header above must appear as-is in the first line

include:config "Common.cfg"
include:config "http://{local_ip}:{port}/configs/{mac}.cfg"

overwrite_mode = 1
"""
        return boot_content
    
    def generate_config_file(self, mac, local_ip, port, extension_data_list=None):
        """Generate Yealink configuration file"""
        cfg_content = f"""#!version:1.0.0.1

##File header "#!version:1.0.0.1" can not be edited or deleted.##

"""
        
        # Add account(s)
        if extension_data_list:
            for i, ext in enumerate(extension_data_list, 1):
                extension = ext["extension"]
                username = ext["username"]
                password = ext["password"]
                domain = ext["domain"]
                
                cfg_content += f"""
#######################################################################################
##                                   Account{i} Settings                             ##                                       
#######################################################################################

#Enable or disable the account {i}; 0-Disabled (default), 1-Enabled;
account.{i}.enable = 1

#Configure the label displayed on the LCD screen for account {i}.
account.{i}.label = {extension}

#Configure the display name of account {i}.
account.{i}.display_name = {extension}

#Configure the username and password for register authentication.
account.{i}.auth_name = {username}
account.{i}.password = {password}

#Configure the register user name.
account.{i}.user_name = {username}

#Enable or disable to use the outbound proxy server; 0-Disabled (default), 1-Enabled; 
account.{i}.outbound_proxy_enable = 1

#Specify the IP address or domain name of the outbound proxy server.
account.{i}.outbound_host = {domain}

#Specify the server port, the default value is 5060.
account.{i}.outbound_port = 5060

account.{i}.sip_server.1.address = {domain}
account.{i}.sip_server.1.port = 5060
account.{i}.sip_server.1.expires = 1800
account.{i}.sip_server.1.retry_counts = 3
account.{i}.sip_server.1.transport_type = UDP
"""
        else:
            # Default single account using MAC as identity
            cfg_content += f"""
#######################################################################################
##                                   Account1 Settings                               ##                                       
#######################################################################################

#Enable or disable the account 1; 0-Disabled (default), 1-Enabled;
account.1.enable = 1

#Configure the label displayed on the LCD screen for account 1.
account.1.label = {mac}

#Configure the display name of account 1.
account.1.display_name = {mac}

#Configure the username and password for register authentication.
account.1.auth_name = {mac}
account.1.password = {mac}

#Configure the register user name.
account.1.user_name = {mac}

#Enable or disable to use the outbound proxy server; 0-Disabled (default), 1-Enabled; 
account.1.outbound_proxy_enable = 1

#Specify the IP address or domain name of the outbound proxy server.
account.1.outbound_host = {local_ip}

#Specify the server port, the default value is 5060.
account.1.outbound_port = 5060

account.1.sip_server.1.address = {local_ip}
account.1.sip_server.1.port = 5060
account.1.sip_server.1.expires = 1800
account.1.sip_server.1.retry_counts = 3
account.1.sip_server.1.transport_type = UDP
"""

        # Add auto provisioning settings
        cfg_content += f"""
#######################################################################################
##                                   Auto Provisioning                               ##      
#######################################################################################

#Enable or disable the Plug and Play feature; 0-Disabled, 1-Enabled(default);
static.auto_provision.pnp_enable = 1

#Enable or disable the phone to check new configuration when powered on; 0-Disabled, 1-Enabled (default);  
static.auto_provision.power_on = 1

#Enable or disable the phone to check the new configuration repeatedly; 0-Disabled (default), 1-Enabled;
static.auto_provision.repeat.enable = 1

#Configure the interval (in minutes) the phone repeatedly checks the new configuration. The default is 1440.
static.auto_provision.repeat.minutes = 5

#Configure the URL of the auto provisioning server.
static.auto_provision.server.url = http://{local_ip}:{port}/configs
"""
        return cfg_content
    
    def generate_all_config_files(self, mac, configs_dir, local_ip, port):
        """Generate all configuration files for a Yealink device (.boot and .cfg)"""
        config_files = []
        
        # Generate and save the boot file
        boot_file = os.path.join(configs_dir, f"{mac}.boot")
        with open(boot_file, "w") as f:
            f.write(self.generate_boot_file(mac, local_ip, port))
        config_files.append(boot_file)
        
        # Generate and save the configuration file
        cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
        with open(cfg_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port))
        config_files.append(cfg_file)
        
        # Also create a Common.cfg file if it doesn't exist
        common_cfg_file = os.path.join(configs_dir, "Common.cfg")
        if not os.path.exists(common_cfg_file):
            common_cfg_content = """#!version:1.0.0.1

##File header "#!version:1.0.0.1" can not be edited or deleted.##

#######################################################################################
##                                   Network                                         ## 
#######################################################################################

# Network Settings
static.network.dhcp_enable = 1
static.network.static_dns_enable = 0

#######################################################################################
##                                   Auto Provisioning                               ##      
#######################################################################################

#Enable or disable the Plug and Play feature; 0-Disabled, 1-Enabled(default);
static.auto_provision.pnp_enable = 1

#Enable or disable the phone to check new configuration when powered on; 0-Disabled, 1-Enabled (default);  
static.auto_provision.power_on = 1

#Enable or disable the phone to check the new configuration repeatedly; 0-Disabled (default), 1-Enabled;
static.auto_provision.repeat.enable = 1

#Configure the interval (in minutes) the phone repeatedly checks the new configuration. The default is 1440.
static.auto_provision.repeat.minutes = 5
"""
            with open(common_cfg_file, "w") as f:
                f.write(common_cfg_content)
        
        return config_files
    
    def generate_all_config_files_with_extensions(self, mac, configs_dir, local_ip, port, extension_data_list):
        """Generate all configuration files for a Yealink device with multiple extensions (.boot and .cfg)"""
        config_files = []
        
        # Generate and save the boot file
        boot_file = os.path.join(configs_dir, f"{mac}.boot")
        with open(boot_file, "w") as f:
            f.write(self.generate_boot_file(mac, local_ip, port))
        config_files.append(boot_file)
        
        # Generate and save the configuration file
        cfg_file = os.path.join(configs_dir, f"{mac}.cfg")
        with open(cfg_file, "w") as f:
            f.write(self.generate_config_file(mac, local_ip, port, extension_data_list))
        config_files.append(cfg_file)
        
        # Also create a Common.cfg file if it doesn't exist
        common_cfg_file = os.path.join(configs_dir, "Common.cfg")
        if not os.path.exists(common_cfg_file):
            common_cfg_content = """#!version:1.0.0.1

##File header "#!version:1.0.0.1" can not be edited or deleted.##

#######################################################################################
##                                   Network                                         ## 
#######################################################################################

# Network Settings
static.network.dhcp_enable = 1
static.network.static_dns_enable = 0

#######################################################################################
##                                   Auto Provisioning                               ##      
#######################################################################################

#Enable or disable the Plug and Play feature; 0-Disabled, 1-Enabled(default);
static.auto_provision.pnp_enable = 1

#Enable or disable the phone to check new configuration when powered on; 0-Disabled, 1-Enabled (default);  
static.auto_provision.power_on = 1

#Enable or disable the phone to check the new configuration repeatedly; 0-Disabled (default), 1-Enabled;
static.auto_provision.repeat.enable = 1

#Configure the interval (in minutes) the phone repeatedly checks the new configuration. The default is 1440.
static.auto_provision.repeat.minutes = 5
"""
            with open(common_cfg_file, "w") as f:
                f.write(common_cfg_content)
        
        return config_files
