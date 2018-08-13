from cloudrules.cloudRules import cloudRules
from cloudrules.SecurityRule import SecurityRule
import logging

from azure.common.client_factory import get_client_from_cli_profile
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.v2018_02_01.models import SecurityRule as AzureSecurityRule
from azure.mgmt.network.v2018_02_01.models import ApplicationSecurityGroup
#from azure.mgmt.network.v2018_02_01.operations import ApplicationSecurityGroupsOperations

class AzureConfigException(Exception):
    pass


class AzureRules(cloudRules):
    """Inherits from cloudRules, and sets up Azure specific stuff

    The main logic is in the parent class cloudRules; this class only
    overrides functions with Azure specific code
    """

    def __init__(self, user_name, account_name, config, ip):
        super(AzureRules, self).__init__(user_name, account_name, config, ip)
        # Name of config var with all the rules:
        self.rule_groups_name = "security_groups"

        # Authenticate with Azure
        self.network_client = None
        if 'use_cli_profile' in config:
            use_cli_profile = config['use_cli_profile']
            if use_cli_profile:
                logging.debug(
                    "[{0}] Using CLI login (az login)".format(account_name)
                )

                self.network_client = get_client_from_cli_profile(NetworkManagementClient)
        if 'key' in config:
            tenant_id = config['tenant_id']
            client_id = config['app_id']
            subscription_id = config['subscription_id']
            key = config['key']
            credentials = ServicePrincipalCredentials(
                client_id = client_id,
                tenant = tenant_id,
                secret = key,
            )
            self.network_client = NetworkManagementClient(credentials, subscription_id)
        else:
            raise AzureConfigException(
                "[{0}] Error, no config definied. Easiest way to get started is to \
                use use_cli_profile: true, and then run az login".format(account_name)
            )


    def get_security_group_names(self, rule_group):
        """Gets a list of tuples (resource_group, security_group) from given rule_group

        Args:
            rule_group (dict): A config dict with something like:
                                    type: resource
                                    resource_group: my-rg
                                    network_security_group: my-nsg
                               or:
                                    type: tag
                                    tag_name: SomeTagName
                                    tag_value: SomeValue
        Returns:
            List of tuples of (str_resource_group_name, str_security_group_name)
        """

        sg_type = rule_group['type']
        security_group_names = []

        if sg_type == 'resource':
            resource_group = rule_group['resource_group']
            network_security_group = rule_group['network_security_group']
            security_group_names.append( (resource_group,network_security_group)  )
        else:
            logging.warning("[{0}] Unrecognized type: {1}".format(self.account_name, sg_type))

        return security_group_names


    # Implements parent method:
    def get_current_relevant_rules(self, rule_group):
        """Return current security group rules as a set of SecurityRules

        See the parent docstring for more info
        """

        security_group_names = self.get_security_group_names(rule_group)
        rules = set()
        for resource_group_name, security_group_name in security_group_names:
            rule_list = self.network_client.security_rules.list( 
                resource_group_name, security_group_name)
            for rule in rule_list:
                name = rule.name
                if name.startswith(self.user_name):
                    ip_cidr = rule.source_address_prefix
                    if '/' in ip_cidr:
                        ip = ip_cidr.split('/')[0]
                        cidr = ip_cidr.split('/')[1]
                    else:
                        ip = ip_cidr
                        cidr = '32'
                    protocol = str(rule.protocol).lower()
                    destination_port_range = rule.destination_port_range
                    if '-' in destination_port_range:
                        from_port = int(destination_port_range.split('-')[0])
                        to_port = int(destination_port_range.split('-')[1])
                    else:
                        from_port = int(destination_port_range)
                        to_port = int(destination_port_range)
                    # Add this SecurityRule
                    security_rule = SecurityRule (
                        ip = ip,
                        cidr = cidr,
                        from_port = from_port,
                        to_port = to_port,
                        protocol = protocol,
                        description = name
                    )
                    rules.add(security_rule)

        return rules
                    

    def apply_rule(self, action, rule, rule_group):

#        for resource_group_name, security_group_name in security_group_names:
#            rule_list = self.network_client.security_rules.list( 
#                resource_group_name, security_group_name)
#            for rule in rule_list:


        pass

    def add_rule(self, rule, rule_group):
        """Adds given rule to security groups mentioned in rule_group

        Args:
            rule (SecurityRule): Single rule to add
            rule_group (dict): A dict that looks like:
                type: resource
                resource_group: my-rg
                network_security_group: my-nsg
                priority: 1234
                rules:
                    - tcp/22  

        Returns:
            None
        """
        # Go through all the security group names mentioned:
        security_group_names = self.get_security_group_names(rule_group)
        for resource_group_name, security_group_name in security_group_names:
            logging.warn(
                '[{0}] Making change: Adding rule {1} to {2}'.format(
                    self.account_name,
                    rule.description,
                    security_group_name
                )
            )
            priority = rule_group['priority']
            security_rule_append_parameters = {}

            if 'destination_ip' in rule_group:
                security_rule_append_parameters['destination_address_prefix'] = rule_group['destination_ip']
            elif 'destination_asgs' in rule_group:
                # Keep list of ApplicationSecurityGroup objects to pass later:
                asgs = []

                # Get the config of list of ASG names:
                config_asgs = rule_group['destination_asgs']

                for asg_name in config_asgs:
                    # Look up ASG
                    asg = self.network_client.application_security_groups.get(resource_group_name, asg_name)
                    asgs.append(asg)
                security_rule_append_parameters['destination_application_security_groups'] = asgs

            azure_rule = AzureSecurityRule(
                protocol = rule.protocol,
                destination_port_range = '{0}-{1}'.format(
                    rule.from_port, 
                    rule.to_port,
                ),
                source_address_prefix = '{0}/32'.format(rule.ip),
                access = 'Allow',
                direction = 'Inbound',
                source_port_range = '*',
                priority = int(priority),
                name = rule.description,
                **security_rule_append_parameters
            )

            self.network_client.security_rules.create_or_update(
                resource_group_name,
                security_group_name,
                rule.description,
                azure_rule
            )
            


    def remove_rule(self, remove_rule, rule_group):
        """Removes given rule to security groups mentioned in rule_group

        Args:
            remove_rule (SecurityRule): Single rule to remove
            rule_group (dict): A dict that looks like:
                type: resource
                resource_group: my-rg
                network_security_group: my-nsg
                priority: 1234
                rules:
                    - tcp/22  

        Returns:
            None
        """
        return
        # Have to find the Azure rule in the NSG that matches the rule.description
        # Go through all the relevant security group names
        security_group_names = self.get_security_group_names(rule_group)
        for resource_group_name, security_group_name in security_group_names:
            # Get list of rules in that NSG
            rule_list = self.network_client.security_rules.list( 
                resource_group_name, security_group_name)
            for azure_rule in rule_list:
                if azure_rule.name == remove_rule.description:
                    logging.warn(
                        '[{0}] Making change: Deleting rule {1} from {2}'.format(
                            self.account_name,
                            remove_rule.description,
                            security_group_name
                        )
                    )
                    self.network_client.security_rules.delete(
                        resource_group_name = resource_group_name,
                        network_security_group_name = security_group_name,
                        security_rule_name = remove_rule.description
                    )

