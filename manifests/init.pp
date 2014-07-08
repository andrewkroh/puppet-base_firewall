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
# === Parameters
#
# [*allow_new_outgoing*]
#   Boolean parameter that determines if the firewall should allow all new
#   outgoing connections. The parameter defaults to false which means that
#   new outgoing connections will be dropped unless there is a rule that
#   explicitly allows the traffic.
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
  $allow_new_outgoing = false,
) {
  include base_firewall::logging
  include base_firewall::post

  class { 'base_firewall::pre':
    allow_new_outgoing => $allow_new_outgoing,
  }

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

  # Lookup hash in hiera. Note: This is using the hiera_hash function
  # directly because it wants all the base_firewall::rules hashes defined
  # in hiera configuration files to be merged together. Using automatic
  # parameter lookup would have only returned the highest priority hash.
  $rules = hiera_hash('base_firewall::rules', undef)

  # Create rules from the given hash.
  if $rules {
    create_resources(firewall, $rules)
  }
}
