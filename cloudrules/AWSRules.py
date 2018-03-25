from cloudrules.cloudRules import cloudRules
from cloudrules.SecurityRule import SecurityRule
import logging
import boto3

class AWSConfigException(Exception):
    pass


class AWSRules(cloudRules):
    """Inherits from cloudRules, and sets up AWS specific stuff

    The main logic is in the parent class cloudRules; this class only
    overrides functions with AWS specific code
    """

    def __init__(self, user_name, account_name, config, ip):
        super(AWSRules, self).__init__(user_name, account_name, config, ip)
        # Name of config var with all the rules:
        self.rule_groups_name = "security_groups"

        # Initialize boto3
        # Check if it has the optional access key:
        boto3_session = None
        if 'access_key' in config:
            access_key = config['access_key']
            logging.debug(
                "[{0}] Using access key {1}".format(account_name, access_key )
            )
            
            for mandatory_config in ['secret_key','region']:
                if mandatory_config not in config:
                    raise AWSConfigException(
                        '[{0}] Missing {1} in config'.format(
                            account_name, mandatory_config
                        )
                    )
            secret_key = config['secret_key']
            region = config['region']

            boto3_session = boto3.session.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )

        # Or check if there was an AWS profile mentioned:
        elif 'profile' in config:
            aws_profile = config['profile']
            logging.debug(
                '[{0}] Using AWS profile {1}'.format(account_name, aws_profile)
            )
            boto_options = {}
            boto_options['profile_name'] = aws_profile
            # Region is optional:
            if 'region' in config:
                boto_options['region_name'] = config['region']
            boto3_session = boto3.session.Session(**boto_options)

        # Else just use the default boto3 creds
        else:
            boto3_session = boto3.session.Session()

        self.ec2_client = boto3_session.client('ec2')
        self.ec2_resource = boto3_session.resource('ec2')
    

    def get_security_group_ids(self, rule_group):
        """Gets a list of security group ID strings from given rule_group

        Args:
            rule_group (dict): A config dict with something like:
                                    type: id
                                    id: sg-1234566
                               or:
                                    type: tag
                                    tag_name: SomeTagName
                                    tag_value: SomeValue
        Returns:
            List of strings, each string being an AWS security group id
        """

        sg_type = rule_group['type']
        security_group_ids = []

        if sg_type == 'id':
            # Pretty simple, already know the ID:
            sg_id = rule_group['id']
            security_group_ids.append(sg_id)

        return security_group_ids


    def get_current_relevant_rules(self, rule_group):
        """Return current security group rules as a set of SecurityRules

        See the parent docstring for more info
        """

        security_group_ids = self.get_security_group_ids(rule_group)

        rules = set()
        for sg_id in security_group_ids:
            sg = self.ec2_resource.SecurityGroup(sg_id)
            for entry in sg.ip_permissions:
                # The ip_permissions looks a bit strange, it's like:
                # {'FromPort': 8080, 'IpRanges': [
                #     {'Description': 'something1', u'CidrIp': '127.0.0.1/32'}, 
                #     {'Description': 'something2', u'CidrIp': '127.0.0.2/32'}
                # ], 'ToPort': 8080, 'IpProtocol': 'tcp' }

                from_port = entry['FromPort']
                to_port = entry['ToPort']
                protocol = entry['IpProtocol']
                for ip_range in entry['IpRanges']:
                    # Skip rules without a description:
                    if not 'Description' in ip_range:
                        continue
                    description = ip_range['Description']
                    cidr_ip = ip_range['CidrIp']
                    ip = cidr_ip.split('/')[0]
                    cidr = cidr_ip.split('/')[1]

                    # Only relevant if the description contains the username
                    if not description.startswith(self.user_name):
                        continue

                    # Add this SecurityRule:
                    security_rule = SecurityRule(
                        ip = ip,
                        cidr = cidr,
                        from_port = int(from_port),
                        to_port = int(to_port),
                        protocol = protocol,
                        description = description
                    )
                    rules.add(security_rule)
        return rules
                    

    def apply_rule(self, action, rule, rule_group):
        """Applies given rule to security groups mentioned in rule_group

        Args:
            action (str): add|remove
            rule (SecurityRule): Single rule to add
            rule_group (dict): A dict that looks like:
                type: id
                id: sg-1234567
                rules:
                    - tcp/22  

        Returns:
            None
        """

        security_group_ids = self.get_security_group_ids(rule_group)
        for sg_id in security_group_ids:
            sg = self.ec2_resource.SecurityGroup( sg_id )

            logging.warn(
                '[{0}] Making change: {1} rule {2} to {3}'.format(
                    self.account_name,
                    action,
                    rule,
                    sg_id
                )
            )

            # Both of boto3's authorize_ingress() & revoke_ingress() have
            # the same arguments:
            if action == "add":
                sg_function = sg.authorize_ingress
            elif action == "remove":
                sg_function = sg.revoke_ingress
            sg_function(
                IpPermissions = [{
                    'IpProtocol': rule.protocol,
                    'FromPort': int(rule.from_port),
                    'ToPort': int(rule.to_port),
                    'IpRanges': [{
                        'CidrIp': '{0}/{1}'.format(rule.ip, rule.cidr),
                        'Description': rule.description
                    }]
                }]
            )






    def add_rule(self, rule, rule_group):
        self.apply_rule("add", rule, rule_group)

    def remove_rule(self, rule, rule_group):
        self.apply_rule("remove", rule, rule_group)

