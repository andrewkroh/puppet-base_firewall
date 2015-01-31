# == Class: base_firewall::post
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
class base_firewall::post (
  $chain_policy = 'drop',
) {

  # Break dependency cycle
  Firewall { before => undef }

# ---------- Set policy for each chain -----------------

  firewallchain { 'INPUT:filter:IPv4':
    ensure => 'present',
    policy => 'drop',
  }

  firewallchain { 'OUTPUT:filter:IPv4':
    ensure => 'present',
    policy => 'drop',
  }

  firewallchain { 'FORWARD:filter:IPv4':
    ensure => 'present',
    policy => 'drop',
  }

# ------------------------------------------------------

  firewall { '999 drop all incoming':
    proto => 'all',
    jump  => 'LOG_DROP',
  }->

  firewall { '999 drop all outgoing':
    proto => 'all',
    jump  => 'LOG_DROP',
    chain => 'OUTPUT',
  }->

  firewall { '999 drop all forwarding':
    proto => 'all',
    jump  => 'LOG_DROP',
    chain => 'FORWARD',
  }
}
