# This is the abstract class that other cloud modules inherit
# To make best use of this module, the cloud provider needs to 
# support having a description or comment in every rule.

from abc import ABC, abstractmethod
from cloudrules.SecurityRule import SecurityRule
import logging


class cloudRules(ABC):
    """Abstract class containing logic for whitelisting

    This is what other classes representing Cloud providers, like AWS & Azure,
    should inherit. The other classes just need to provide methods to get the
    current rules, add a rule, and remove a rule.

    Args:
        user_name (str): String used for each rule description
        account_name (str): The name of the account, used in logs only
        config (dict): A dict of the config.yml snippet for an account
        ip (str): IP address to whitelist
    """

    def __init__(self, user_name, account_name, config, ip):
        self.config = config
        self.account_name = account_name
        self.user_name = user_name
        self.ip = ip
        self.rule_groups_name = "security_group"


    @abstractmethod
    def get_current_relevant_rules(self, rule_group):
        """Returns a set of SecurityRules with the given rule_group

        This should return a "set" of SecurityRules based on the given 
        rule_group, with the rule_group being a Dict in the config.yml.
        It's important that this should ONLY return RELEVANT rules 
        based on the user_name (i.e. only rules that mention the username)

        Args:
            rule_group (dict): A dict that looks like:
                some_setting: some_value
                rules:
                    - tcp/22
        
        Returns:
            A "set" of "SecurityRule"s
        """

        pass


    @abstractmethod
    def add_rule(self, rule, rule_group):
        """Adds this SecurityRule

        This should be overridden by subclasses, and add the specified rule.

        Args:
            rule (SecurityRule): Single rule to add
            rule_group (dict): A dict that looks like:
                some_setting: some_value
                rules:
                    - tcp/22            
        
        Returns:
            None
        """
        pass


    @abstractmethod
    def remove_rule(self, rule, rule_group):
        """Remove this SecurityRule

        This should be overridden by subclasses, and add the specified rule.

        Args:
            rule (SecurityRule): Single rule to remove
            rule_group (dict): A dict that looks like:
                some_setting: some_value
                rules:
                    - tcp/22            
        
        Returns:
            None
        """
        pass


    def get_desired_rules(self, rule_group):
        """Returns a set of SecurityRules based on the rule_group

        This outputs the set of SecurityRules that contains the desired
        security group/firewall configuration based on the ip address.

        Args:
            rule_group (dict): A dict that looks like:
                some_setting: some_value
                rules:
                    - tcp/22

        Returns:
            A "set" of "SecurityRule" with the desired rules
        """

        security_rules = set()

        rule_group_rules = rule_group['rules']
        for rule in rule_group_rules:
            # In the formats:
            # tcp/22
            # tcp/8000-9000
            # icmp/-1
            protocol = rule.split('/')[0]
            ports = rule.split('/')[1]
            # If the port starts with -, allow everything:
            if ports.startswith('-'):
                from_port = -1
                to_port = -1
            # Else if it's a range:
            elif '-' in ports:
                from_port = int(ports.split('-')[0])
                to_port = int(ports.split('-')[1])
            else:
                from_port = int(ports)
                to_port = int(ports)

            # Use a unique description (for Azure):
            description = "{username}_{proto}_{from_port}_{to_port}".format(
                username=self.user_name,
                proto=protocol,
                from_port=from_port,
                to_port=to_port
            )
            
            security_rule = SecurityRule(
                ip = self.ip,
                cidr = '32',
                from_port = from_port,
                to_port = to_port,
                protocol = protocol,
                description = description
            )

            security_rules.add(security_rule)
        
        return security_rules


    def get_rule_groups(self):
        """Returns a List of rule_groups in the config
        """
        return self.config[self.rule_groups_name]




    def sync(self):
        """Applies the security groups with the current IP

        This is the main function that applies any security group
        changes. The logic is shared among different clouds, and just
        involves getting the current rules, then the desired rules, and then
        those sets to know what rules to add and remove.
        
        Returns:
            Nothing
        """

        for rule_group in self.get_rule_groups():
            desired_rules = self.get_desired_rules(rule_group)
            logging.debug("Desired rules are: {0}".format(desired_rules))

            current_rules = self.get_current_relevant_rules(rule_group)
            logging.debug("Current rules are: {0}".format(current_rules))

            remove_rules = current_rules - desired_rules
            for rule in remove_rules:
                self.remove_rule(rule, rule_group)

            add_rules = desired_rules - current_rules
            for rule in add_rules:
                self.add_rule(rule, rule_group)



        

