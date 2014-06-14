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

  firewall { '999 drop all input':
    proto => 'all',
    jump  => 'LOG_DROP',
  }->

  firewall { '999 drop all output':
    proto => 'all',
    jump  => 'LOG_DROP',
    chain => 'OUTPUT',
  }->

  firewall { '999 drop all forward':
    proto => 'all',
    jump  => 'LOG_DROP',
    chain => 'FORWARD',
  }
}
