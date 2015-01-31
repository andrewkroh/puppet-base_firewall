# == Class: base_firewall::pre_ipv6
#
# Defines a set of base firewall rules that are applied before any other
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
class base_firewall::pre_ipv6 () {

  # Break dependency cycle
  Firewall {
    require => undef,
  }

# ---------------- Log and Drop IPv6 Chain ------------------

  firewallchain { 'LOG_DROP_IPv6:filter:IPv6':
    ensure => present,
  }

  firewall { '000 log dropped ipv6':
    proto      => 'all',
    jump       => 'LOG',
    limit      => '10/min',
    log_prefix => 'LOG_DROP_IPv6: ',
    log_level  => 7,
    chain      => 'LOG_DROP_IPv6',
    provider   => 'ip6tables',
  }->

  firewall { '001 drop ipv6':
    proto    => 'all',
    action   => 'drop',
    chain    => 'LOG_DROP_IPv6',
    provider => 'ip6tables',
  }

# ---------------- Input Chain Rules ------------------

  firewall { '000 allow incoming on loopback ipv6':
    action   => 'accept',
    proto    => 'all',
    iniface  => 'lo',
    provider => 'ip6tables',
  }->

# -------------- Output Chain Rules ----------------

  firewall { '000 allow outgoing on loopback ipv6':
    chain    => 'OUTPUT',
    action   => 'accept',
    proto    => 'all',
    outiface => 'lo',
    provider => 'ip6tables',
  }

}
