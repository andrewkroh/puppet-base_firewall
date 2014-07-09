# == Class: base_firewall::pre
#
# Defines a set of base firewall rules that are applied before any other
# rules.
#
# === Parameters
# 
# [*allow_new_outgoing*]
#   Boolean parameter that determines if the firewall should allow all new
#   outgoing connections. The parameter defaults to false which means that
#   new outgoing connections will be dropped unless there is a rule that
#   explicitly allows the traffic.
#
# [*sshd_port*]
#   SSH server port that access should be granted to. Defaults to 22.
#
# === Authors
#
# Andrew Kroh <andy@crowbird.com>
#
# === Copyright
#
# Copyright 2014, Andrew Kroh
#
class base_firewall::pre (
  $allow_new_outgoing = false,
  $sshd_port          = 22,
) {

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

  firewall { '000 allow incoming on loopback':
    action    => 'accept',
    proto     => 'all',
    iniface   => 'lo',
  }->

  # FIN and SYN are mutually exclusive TCP flags. Attackers
  # set them to do OS fingerprinting.
  firewall { '005 drop bogus fin,syn':
    tcp_flags => 'FIN,SYN FIN,SYN',
    jump      => 'LOG_DROP',
  }->

  # SYN and RST are not used together.
  firewall { '006 drop bogus syn,rst':
    tcp_flags => 'SYN,RST SYN,RST',
    jump      => 'LOG_DROP',
  }->

  firewall { '007 allow incoming established, related':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }->

  firewall { '008 allow incoming icmp echo-requests':
    proto  => 'icmp',
    icmp   => 'echo-request',
    action => 'accept',
  }->

  firewall { '020 allow incoming ssh':
    dport  => $sshd_port,
    proto  => 'tcp',
    action => 'accept',
  }->

# -------------- Output Chain Rules ----------------

  firewall { '000 allow outgoing on loopback':
    chain     => 'OUTPUT',
    action    => 'accept',
    proto     => 'all',
    outiface  => 'lo',
  }->

  firewall { '005 allow outgoing established, related':
    chain  => 'OUTPUT',
    proto  => 'all',
    state  => ['ESTABLISHED', 'RELATED'],
    action => 'accept',
  }

  if ($allow_new_outgoing) {
    firewall { '006 allow new outgoing':
      chain   => 'OUTPUT',
      proto   => 'all',
      state   => 'NEW',
      action  => 'accept',
      require => Firewall['001 allow outgoing established, related'],
    }
  }
}
