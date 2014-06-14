# == Class: base_firewall
#
# Install and configure a firewall on the machine. A base set of firewall
# rules are added which include an allowance for incoming SSH on port 22.
# All outgoing traffic is allowed.
#
# Applications that want to add additional rules in the firewall can
# define their own firewall rules by including configuration like this.
#
# firewall { '150 open tcp port 585':
#   dport => 585,
#   action => accept,
# }
#
# Each rule name must be unique. The rules are added to each individual
# firewall chain in ascending order based on their names. Each rule name
# should start with a three digit number to assist in ordering. 000-099
# and 900-999 are reserved for the "pre" and "post" rulesets that are
# defined by this module.
#
# For additional information see the Puppet Labs firewall module documenation
# at https://forge.puppetlabs.com/puppetlabs/firewall.
#
# === Variables
#
# [*rules*]
#   Hash containing firewall rule data that is used to create firewall
#   resources. The parameter is optional.
#
#   This parameter can be used to pass in firewall rules through hiera
#   configuration.
#
# === Examples
#
#  class { 'base_firewall': }
#
# === Authors
#
# Andrew Kroh <andy@crowbird.com>
#
# === Copyright
#
# Copyright 2014, Andrew Kroh
#
class base_firewall(
  $rules = undef,
) {
  include base_firewall::logging
  include base_firewall::pre
  include base_firewall::post

  # Include the pre/post rules and ensure that the pre
  # rules always run before the post rules to prevent
  # us from being locked out of the system.
  Firewall {
    require => Class['base_firewall::pre'],
    before  => Class['base_firewall::post'],
  }

  # Purge any firewall rules not managed by Puppet.
  resources { 'firewall':
    purge => true,
  }

  # Create rules from the given hash.
  if $rules {
    validate_hash($rules)
    create_resources(firewall, $rules)
  }
}
