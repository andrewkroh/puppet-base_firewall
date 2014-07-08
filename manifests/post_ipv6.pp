# == Class: base_firewall::post_ipv6
#
# Defines a set of base firewall rules that are applied after any other
# rules.
#
# === Authors
#
# Andrew Kroh <andy@crowbird.com>
#
# === Copyright
#
# Copyright 2014, Andrew Kroh
#
class base_firewall::post_ipv6 {

  # Break dependency cycle
  Firewall { before => undef }

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
