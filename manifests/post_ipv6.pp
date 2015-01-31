# == Class: base_firewall::post_ipv6
#
# Defines a set of base firewall rules that are applied after any other
# rules.
#
# === Parameters
#
# [*chain_policy*]
#   Policy (drop, accept) to apply to each chain (INPUT, FORWARD, OUTPUT).
#   Defaults to drop. The last rules in each chain are always log then drop
#   so the policy has minimal effect.
#
# === Authors
#
# Andrew Kroh <andy@crowbird.com>
#
# === Copyright
#
# Copyright 2014-2015, Andrew Kroh
#
class base_firewall::post_ipv6 (
  $chain_policy = 'drop',
) {

  # Break dependency cycle
  Firewall { before => undef }

# ---------- Set policy for each chain -----------------

  firewallchain { 'INPUT:filter:IPv6':
    ensure => 'present',
    policy => 'drop',
  }

  firewallchain { 'OUTPUT:filter:IPv6':
    ensure => 'present',
    policy => 'drop',
  }

  firewallchain { 'FORWARD:filter:IPv6':
    ensure => 'present',
    policy => 'drop',
  }

# ------------------------------------------------------

  firewall { '999 drop all incoming ipv6':
    proto    => 'all',
    jump     => 'LOG_DROP_IPv6',
    provider => 'ip6tables',
  }->

  firewall { '999 drop all outgoing ipv6':
    proto    => 'all',
    jump     => 'LOG_DROP_IPv6',
    chain    => 'OUTPUT',
    provider => 'ip6tables',
  }->

  firewall { '999 drop all forwarding ipv6':
    proto    => 'all',
    jump     => 'LOG_DROP_IPv6',
    chain    => 'FORWARD',
    provider => 'ip6tables',
  }
}
