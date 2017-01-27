# == Class: base_firewall::pre_ipv4
#
# Defines a set of base firewall rules that are applied before any other
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
class base_firewall::pre_ipv4 (
  $allow_new_outgoing,
  $manage_sshd_firewall,
  $sshd_port,
  $chain_policy,
  $chain_purge,
  $chain_purge_ignore,
) {

  # Break dependency cycle and set default provider
  # for rules defined in this scope.
  Firewall {
    require  => undef,
    provider => 'iptables',
  }

# ---------- Set policy for each chain -----------------

  firewallchain { 'INPUT:filter:IPv4':
    ensure => 'present',
    purge  => $chain_purge,
    ignore => $chain_purge_ignore,
  }

  firewallchain { 'OUTPUT:filter:IPv4':
    ensure => 'present',
    purge  => $chain_purge,
    ignore => $chain_purge_ignore,
  }

  firewallchain { 'FORWARD:filter:IPv4':
    ensure => 'present',
    purge  => $chain_purge,
    ignore => $chain_purge_ignore,
  }

  # The chains' policies should only be changed to drop after all "accept"
  # rules have been added. The following is a workaround to achieve idepotency.
  # If the desired policy is drop and the chain is already set to drop then
  # do not change the policy to accept (the default). If the policy needs to
  # change this will be done in the post_ipv4 class.
  if $chain_policy == 'drop' and $::iptables_input_policy == 'drop' {
    Firewallchain['INPUT:filter:IPv4'] {
      policy => 'drop',
    }
  }

  if $chain_policy == 'drop' and $::iptables_output_policy == 'drop' {
    Firewallchain['OUTPUT:filter:IPv4'] {
      policy => 'drop',
    }
  }

  if $chain_policy == 'drop' and $::iptables_forward_policy == 'drop' {
    Firewallchain['FORWARD:filter:IPv4'] {
      policy => 'drop',
    }
  }

# ------------- Create Log and Drop IPv6 Chains ---------------

  base_firewall::log_drop_chain { 'INPUT:filter:IPv4': }
  base_firewall::log_drop_chain { 'OUTPUT:filter:IPv4': }
  base_firewall::log_drop_chain { 'FORWARD:filter:IPv4': }

# ---------------- Input Chain Rules ------------------

  firewall { '000 allow incoming on loopback':
    action  => 'accept',
    proto   => 'all',
    iniface => 'lo',
  }->

  # FIN and SYN are mutually exclusive TCP flags. Attackers
  # set them to do OS fingerprinting.
  firewall { '005 drop bogus fin,syn':
    tcp_flags => 'FIN,SYN FIN,SYN',
    jump      => 'DROP_INPUT',
  }->

  # SYN and RST are not used together.
  firewall { '006 drop bogus syn,rst':
    tcp_flags => 'SYN,RST SYN,RST',
    jump      => 'DROP_INPUT',
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
  }

  if $manage_sshd_firewall {
    firewall { '020 allow incoming ssh':
      dport  => $sshd_port,
      proto  => 'tcp',
      action => 'accept',
    }
  }

# -------------- Output Chain Rules ----------------

  firewall { '000 allow outgoing on loopback':
    chain    => 'OUTPUT',
    action   => 'accept',
    proto    => 'all',
    outiface => 'lo',
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
      require => Firewall['005 allow outgoing established, related'],
    }
  }
}
