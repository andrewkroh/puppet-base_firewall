# == Class: base_firewall::post_ipv6
#
# Defines a set of base firewall rules that are applied after any other
# rules.
#
# === Parameters
#
# See base_firewall for a definition of the parameters.
#
# === Authors
#
# Andrew Kroh
#
class base_firewall::post_ipv6 (
  $chain_policy,
) {

  # Break dependency cycle and set default provider
  # for rules defined in this scope.
  Firewall {
    before   => undef,
    provider => 'ip6tables',
  }

# ------------------------------------------------------

  firewall { '999 drop all incoming IPv6':
    proto => 'all',
    jump  => 'DROP_INPUT',
    chain => 'INPUT',
  }->

  firewall { '999 drop all outgoing IPv6':
    proto => 'all',
    jump  => 'DROP_OUTPUT',
    chain => 'OUTPUT',
  }->

  firewall { '999 drop all forwarding IPv6':
    proto => 'all',
    jump  => 'DROP_FORWARD',
    chain => 'FORWARD',
  }

# ------------------------------------------------------

  if $chain_policy == 'drop' and $::ip6tables_input_policy != 'drop' {
    exec { 'IPv6 INPUT policy is DROP':
      command => 'ip6tables -P INPUT DROP',
      user    => root,
      path    => $::path,
      require => Firewall['999 drop all incoming IPv6'],
    }
  }

  if $chain_policy == 'drop' and $::ip6tables_output_policy != 'drop' {
    exec { 'IPv6 OUTPUT policy is DROP':
      command => 'ip6tables -P OUTPUT DROP',
      user    => root,
      path    => $::path,
      require => Firewall['999 drop all outgoing IPv6'],
    }
  }

  if $chain_policy == 'drop' and $::ip6tables_forward_policy != 'drop' {
    exec { 'IPv6 FORWARD policy is DROP':
      command => 'ip6tables -P FORWARD DROP',
      user    => root,
      path    => $::path,
      require => Firewall['999 drop all forwarding IPv6'],
    }
  }

}
