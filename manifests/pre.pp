# == Class: base_firewall::pre
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
class base_firewall::pre {

  # Break dependency cycle
  Firewall {
    require => undef,
  }

# ---------------- Log and Drop Chain ------------------

  firewallchain { 'LOG_DROP:filter:IPv4':
    ensure => present,
  }

  firewall { '000 log dropped':
    proto      => 'all',
    jump       => 'LOG',
    limit      => '10/min',
    log_prefix => 'LOG_DROP: ',
    log_level  => 7,
    chain      => 'LOG_DROP',
  }->

  firewall { '001 drop':
    proto  => 'all',
    action => 'drop',
    chain  => 'LOG_DROP',
  }

# ---------------- Input Chain Rules ------------------

  firewall { '000 accept all input on loopback':
    action    => 'accept',
    proto     => 'all',
    iniface   => 'lo',
  }->

  firewall { '002 drop bogus syn,fin':
    tcp_flags => 'SYN,FIN SYN,FIN',
    jump      => 'LOG_DROP',
  }->

  firewall { '003 drop bogus syn,rst':
    tcp_flags => 'SYN,RST SYN,RST',
    jump      => 'LOG_DROP',
  }->

  firewall { '004 accept established, related':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }->

  firewall { '005 accept all icmp':
    proto  => 'icmp',
    action => 'accept',
  }->

  firewall { '010 accept ssh':
    dport  => 22,
    proto  => 'tcp',
    action => 'accept',
  }->

# -------------- Output Chain Rules ----------------

  firewall { '000 accept all output on loopback':
    chain     => 'OUTPUT',
    action    => 'accept',
    proto     => 'all',
    outiface  => 'lo',
  }->

  firewall { '001 allow all outbound':
    chain  => 'OUTPUT',
    proto  => 'all',
    state  => ['NEW', 'ESTABLISHED', 'RELATED'],
    action => 'accept',
  }
}
