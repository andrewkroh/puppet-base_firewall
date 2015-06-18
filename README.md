# base_firewall

[![Build Status](https://travis-ci.org/andrewkroh/puppet-base_firewall.svg?branch=master)](https://travis-ci.org/andrewkroh/puppet-base_firewall)

#### Table of Contents

1. [Overview](#overview)
3. [Setup - The basics of getting started with base_firewall](#setup)
    * [What base_firewall affects](#what-base_firewall-affects)
    * [Beginning with base_firewall](#beginning-with-base_firewall)
4. [Usage](#usage)
5. [Reference](#reference)
5. [Examples](#examples)
    * [Hiera Example](#hiera-example)
    * [Docker Example](#docker-example)

## Overview

The base_firewall module establishes a basic firewall setup the allows
incoming SSH and ping requests. It enables you to create additional firewall
rules from Hiera or by directly using the puppetlabs/firewall types.


## Setup

### What base_firewall affects

* IPv4 firewall rules
* IPv6 firewall rules
* Default chain policies (i.e. DROP, ACCEPT)
* Rsyslog and logrotate configuration (optionally)


### Beginning with base_firewall

The simplist way to get started with this module is to just include the
module. Then declare any custom firewall rules by directly using
puppetlabs/firewall.

```
include base_firewall

firewall { '150 open tcp port 585':
  dport  => 585,
  action => accept,
}
```

Each rule name must be unique. By convention each rule should start with a
three digit number to assist in ordering. 000-099 and 900-999 should be
reserved for the base_firewall's rulesets.

The default set of INPUT rules created by this module are as follows.

* allow all on loopback
* drop packets with bogus tcp flags (FIN-SYN and SYN-RST)
* allow all established, related
* allow ICMP echo-requests
* allow SSH
* log and drop

The default set of OUTPUT rules created by this module are as follows.
(Note that all new outgoing traffic will be blocked by default.)

* allow all on loopback
* allow all established, related
* log and drop

The default set of FORWARD rules created by this module are as follows.

* log and drop

## Usage

The only class you should need to interact with is the main base_firewall
class. See the reference section for the parameter details.

## Reference

Class: `base_firewall`

Parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| allow_new_outgoing_ipv4 | false | Boolean parameter that determines if the firewall should allow all new outgoing IPv4 connections. The parameter defaults to false which means that new outgoing connections will be dropped unless there is a rule that explicitly allows the traffic. |
| allow_new_outgoing_ipv6 | false | Boolean parameter that determines if the firewall should allow all new outgoing IPv6 connections. The parameter defaults to false which means that new outgoing connections will be dropped unless there is a rule that explicitly allows the traffic. |
| sshd_port | 22 | SSH server port that access should be granted to. Defaults to 22. |
| purge | true | Boolean parameter that determines if all unmanaged firewall rules and chains are purged. Defaults to true. Requires puppetlabs/firewall 1.2.0+ in order,for IPv6 resources to be purged. |
| chain_policy | DROP | Policy (drop, accept) to apply to each chain (INPUT, FORWARD, OUTPUT). Defaults to drop. The last rules in each chain are always "log then drop" so the policy has minimal effect. |
| chain_purge | false | An alternative method of purging unmanaged firewall rules that operates only on the INPUT, OUTPUT, and FORWARD chains. This method of purging unmanaged rules allows you to specify an array of regular expressions that match against firewall rules that should be ignored when purging (see the `ignores` variable. The default value is false and its usage with `purge` is mutually exclusive. An example use case would be to ignore firewall rules that are managed by another application like docker. |
| manage_logging | false | Boolean parameter specifying whether this module should manage logger config for iptables. Defaults to false. If true then rsyslog will be configured to write all iptables events to /var/log/iptables.log and logrotate will manage the file. |                                                                                                                                                                                                                                                                                                                                                                                                                      

Variables (set through Hiera config):

| Variable | Default | Description |
|----------|---------|-------------|
| base_firewall::rules | empty | Hash containing firewall rule data that is used to create firewall resources. The parameter is optional. This parameter can be used to pass in firewall rules through hiera configuration. |
| base_firewall::ignores | empty | An array of regular expressions that match against firewall rules that should be ignored when purging. Defaults to undefined and is only used when `chain_purge` is set to true. |

## Examples


### Hiera Example

This examples shows how to configure the module and add firewall rules entirely
through Hiera YAML file configuration.

```
classes:
  - base_firewall

# Disable new outgoing connections.
base_firewall::allow_new_outgoing_ipv4: no

# Explicitly declare all allowed outgoing connections:
base_firewall::rules:
  '100 allow outgoing icmp echo-requests':
    proto:  icmp
    icmp:   'echo-request'
    action: accept
    chain:  OUTPUT
  '101 allow outgoing ssh':
    dport:  22
    action: accept
    chain:  OUTPUT
  '102 allow outgoing dns':
    dport:  53
    proto:  udp
    action: accept
    chain:  OUTPUT
  '103 allow outgoing ntp':
    dport:  123
    proto:  udp
    action: accept
    chain:  OUTPUT
```

### Docker Example

This example shows how to configure Puppet to not purge firewall rules
managed by Docker.

```
classes:
  - base_firewall

# Customize the purge config so that docker rules are not
# purged by puppet.
base_firewall::purge: no
base_firewall::chain_purge: yes
base_firewall::ignores:
  - '-o docker0'
  - '-i docker0'
```
