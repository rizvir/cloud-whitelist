#!/usr/bin/env python


from urllib.request import urlopen
import socket
import os
import sys
import logging
import logging.handlers
import traceback
import yaml
import argparse


# Returns current IP address
def get_ip():
    response = urlopen('http://checkip.amazonaws.com')
    ip = response.read().splitlines()[0].decode("ascii") 
    
    # This would throw an exception if the IP was invalid:
    socket.inet_aton(ip)

    return ip


def run(config_filename, current_ip):
    # Open configuration file
    try:
        config_file = open(os.path.join(sys.path[0], config_filename), "r")
    except IOError:
        logging.error("Could not open config file {0}".format(config_filename))
        sys.exit(2)
     
    # Load configuration file as a python dict
    try:   
        config = yaml.load(config_file)
        config_file.close()
    except yaml.parser.ParserError as e:
        logging.error("YAML configuration {0} is not a proper YAML file".format(config_filename))
        logging.error(e)
        sys.exit(3)

    for mandatory_config in ['my_name', 'accounts']:
        if mandatory_config not in config:
            logging.error('Missing required configuration: "{0}", which is the description to use in the security group'.format(
                mandatory_config))
            sys.exit(4)

    user_name = config['my_name']
    accounts = config['accounts']

    for account_name, account_config in accounts.items():
        try:
            cloud = account_config['cloud']
            if cloud == 'aws':
                from cloudrules.AWSRules import AWSRules
                cloud_rules = AWSRules(user_name, account_name, account_config,
                                        current_ip)
            elif cloud == 'azure':
                from cloudrules.AzureRules import AzureRules
                cloud_rules = AzureRules(user_name, account_name, account_config,
                                        current_ip)
            else:
                logging.error('[{0}] Skipping unknown cloud {1}'.format(
                        account_name, cloud ))
                continue

            cloud_rules.sync()
        except Exception as e:
            exception = traceback.format_exc()
            logging.error("[{0}] Error: {1}".format(
                            account_name, exception))


def main():

    # Default config.yml is in the same directory containing the script
    default_config_filepath = os.path.realpath(
        os.path.join(os.getcwd(), os.path.dirname(__file__), 'config.yml')
    )

    parser = argparse.ArgumentParser(description="Whitelist your IP in \
                                        security groups defined in config.yml")
    
    parser.add_argument('--config', required=False, 
        default=default_config_filepath,
        help="Configuration YAML, defaults to config.yml")

    parser.add_argument('--debug', required=False, action='store_const',
        const=True, default=False,
        help="Enable debug logs")

    parser.add_argument('--syslog', required=False, action='store_const',
        const=True, default=False,
        help="Write logs to syslog")

    parser.add_argument('--logfile', required=False,
        help="Write logs to given file path")


    args = parser.parse_args()
    config_filename = args.config
    enable_debug = args.debug
    enable_syslog = args.syslog
    log_filename = args.logfile

    # Handle logging
    logger = logging.getLogger()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    
    if enable_debug:
        logger.setLevel(logging.DEBUG)
    if enable_syslog:
        if sys.platform.startswith('linux'):
            dev_log = '/dev/log'
        elif sys.platform.startswith('darwin'):
            dev_log = '/var/run/syslog'
        syslog_handler = logging.handlers.SysLogHandler(address = dev_log)
        syslog_handler.setFormatter(formatter)
        logger.addHandler( syslog_handler )
    if log_filename:
        file_handler = logging.FileHandler(log_filename)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    
    # Finally run it:
    run(config_filename, get_ip())
    


if __name__ == "__main__":
    main()
    



