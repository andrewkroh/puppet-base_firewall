# == Class: base_firewall::post
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
class base_firewall::post {

  # Break dependency cycle
  Firewall { before => undef }

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
