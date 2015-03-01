# == Class: base_firewall::post_ipv4
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
class base_firewall::post_ipv4 (
  $chain_policy,
) {

  # Break dependency cycle and set default provider
  # for rules defined in this scope.
  Firewall {
    before   => undef,
    provider => 'iptables',
  }

# ------------------------------------------------------

  firewall { '999 drop all incoming':
    proto => 'all',
    jump  => 'DROP_INPUT',
  }->

  firewall { '999 drop all outgoing':
    proto => 'all',
    jump  => 'DROP_OUTPUT',
    chain => 'OUTPUT',
  }->

  firewall { '999 drop all forwarding':
    proto => 'all',
    jump  => 'DROP_FORWARD',
    chain => 'FORWARD',
  }

# ------------------------------------------------------

  if $chain_policy == 'drop' and $::iptables_input_policy != 'drop' {
    exec { 'IPv4 INPUT policy is DROP':
      command => 'iptables -P INPUT DROP',
      user    => root,
      path    => $::path,
      require => Firewall['999 drop all incoming'],
    }
  }

  if $chain_policy == 'drop' and $::iptables_output_policy != 'drop' {
    exec { 'IPv4 OUTPUT policy is DROP':
      command => 'iptables -P OUTPUT DROP',
      user    => root,
      path    => $::path,
      require => Firewall['999 drop all outgoing'],
    }
  }

  if $chain_policy == 'drop' and $::iptables_forward_policy != 'drop' {
    exec { 'IPv4 FORWARD policy is DROP':
      command => 'iptables -P FORWARD DROP',
      user    => root,
      path    => $::path,
      require => Firewall['999 drop all forwarding'],
    }
  }

}
