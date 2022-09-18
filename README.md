# SRv6-PI (Policy Injector)

Inject SRv6 Policy with goBGP

## Requirements

 - golang >= 1.19
 - goBGP = 2.3.4

 ## Build
 
    $ go build

## Usage

### Inject a SRv6 policy

    $ ./SRv6-PI create -u <goBGP_IP> -p <goBGP_port> --policyFile ~/policyFile.yaml

### List SRv6 policies

    $ ./SRv6-PI list -u <goBGP_IP> -p <goBGP_port>



