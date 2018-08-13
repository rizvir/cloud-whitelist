## cloud-whitelist

Work in progress; right now only has basic functionality in AWS & Azure.

Simple python 3 script to whitelist your public/external IP in Amazon and/or Azure Security Groups.


### Installation

#### From source:

```
install_dir="~/scripts/"
virtualenv-3 venv
source venv/bin/activate
pip install -r requirements.txt
cp config.yml.sample config.yml
# Edit config.yml, see below
./whitelist.py

```


### Usage - AWS

You first need to have a `config.yml` file:
```
my_name: "rizvir" # Used for the security group description
accounts:
    your-account-name:  # Used for logging only
        cloud: aws
        access_key: ABFDU832423490
        secret_key: abcd1234567890123456789
        region: ap-southeast-2
        security_groups:
            - type: id
              id: sg-12345678
              rules:
                - tcp/22
                - icmp/-1
                - tcp/8000-9000
    another-example-with-aws-profiles:
        cloud: aws
        profile: myprofile-dev
        security_groups:
            - type: id
              id: sg-2345677
              rules:
                - tcp/22
```

Then run it:
```
./whitelist.py
```


# Azure

### Authentication with "az login"

If you plan to exclusively use "az login" before running this script, you can get started with this config.yml:

```
my_name: "rizvir"  # Used for SG name
accounts:
    test:  # this is only used for logging:
        cloud: azure
        use_cli_profile: true  # <----- this means you need to use "az login" before running the command
        security_groups:
            - type: resource
              resource_group: my-resource-group
              network_security_group: my-nsg
              priority: 1234
              destination_ip: 192.168.1.1/32 # Destination IP to whitelist, or use an "*" for all IPs
              # Alternatively, instead of an IP, you can put in a list of Application Security Groups:
              # destination_asgs:
              #   - my-asg
              rules:
                - tcp/22
```

### Authentication with service principal

This method is useful to run this script without human intervention. The service principal's permissions can be restricted to just have access to one (or more) specific security groups.

Create a service principal:

```
az ad sp create-for-rbac --name cloud-whitelist-dev
```

Keep a copy of the details it generates:
- appId: The Application ID
- password: The principal secret
- tenant: The Tenant ID

Set it as an environment variable temporarily:

```
appId="$01234abcd-123-456"
```

Create a `/tmp/rbac.json` file, change the Name & subscription ID as required and keep track of it for later steps; note that the AssignableScopes here doesn't define what resources the role should be limited to, that will be done in a later step:
```
{
  "Name":  "Cloud Whitelist - Dev",
  "IsCustom":  true,
  "Description":  "Ability to modify a particular security group on the dev environment to whitelist their IP",
  "Actions":  [
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Network/networkSecurityGroups/securityRules/read",
      "Microsoft.Network/networkSecurityGroups/securityRules/write",
      "Microsoft.Network/networkSecurityGroups/securityRules/delete",
      "Microsoft.Network/applicationSecurityGroups/read"
  ],
  "AssignableScopes": [
       "/subscriptions/abcde-12345-0000"
  ]
}

```

Create a role:
```
az role definition create --role-definition /tmp/rbac.json
```

By default, service principals are given Contributor access as of writing (!), so remove it:
```
az role assignment list --assignee $appId
az role assignment delete --assignee $appId --role Contributor
```

Find out the ID of the network security group you want to modify:
```
az network nsg list --query "[].[name,id]" --output table
```
Get the NSG ID you want above, eg. /subscriptions/1123-abcd-123/resourceGroups/some-resource-group/providers/Microsoft.Network/networkSecurityGroups/thewhitelist-nsg
```
az role assignment create --assignee $appId --role "Cloud Whitelist - Dev" --scope "/subscriptions/1123-abcd-123/resourceGroups/some-resource-group/providers/Microsoft.Network/networkSecurityGroups/thewhitelist-nsg"
```

If your destination isn't an IP address but a Application Security Group, repeat the above command with the scope including the application security group:
```
az role assignment create --assignee $appId --role "Cloud Whitelist - Dev" --scope /subscriptions/1123-abcd-123/resourceGroups/some-resource-group/providers/Microsoft.Network/applicationSecurityGroups/my-asg
```

Create a `config.yml` file:
```
my_name: "rizvir" # Used for the security group description
accounts:
    myazure:  # Used for logging only
        cloud: azure
        subscription_id: <put in your subscription ID here>
        tenant_id: <put in the value for tenant here>
        app_id: <put in the value for appId here>
        key: <put in the value for password here>
        security_groups:
            - type: resource
              resource_group: my-resource-group
              network_security_group: my-nsg
              priority: 1234
              destination_ip: 192.168.1.1/32 # Destination IP to whitelist, or use an "*" for all IPs
              # Alternatively, instead of an IP, you can put in a list of Application Security Groups:
              # destination_asgs:
              #   - my-asg
              rules:
                - tcp/22
```

Then run it:
```
./whitelist.py
```

