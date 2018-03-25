## cloud-whitelist

Work in progress; right now only has basic functionality in AWS.

Simple python 3 script to whitelist your public/external IP in an Amazon Security Group. Azure support is planned.


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


### Usage

You first need to have a `config.yml` file:
```
my_name: "rizvir"
accounts:
    your-account-name:  # <-- this is only used for logging
        cloud: aws
        access_key: ABFDU832423490
        secret_key: sifoudhsfgsfu89dsug7dysgyg
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

