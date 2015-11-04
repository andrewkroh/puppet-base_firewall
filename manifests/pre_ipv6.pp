# == Class: base_firewall::pre_ipv6
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
class base_firewall::pre_ipv6 (
  $allow_new_outgoing,
  $sshd_port,
  $chain_policy,
  $chain_purge,
  $chain_purge_ignore,
) {

  # Break dependency cycle and set default provider
  # for rules defined in this scope.
  Firewall {
    require  => undef,
    provider => 'ip6tables',
  }

# ---------- Set policy for each chain -----------------

  firewallchain { 'INPUT:filter:IPv6':
    ensure => 'present',
    purge  => $chain_purge,
    ignore => $chain_purge_ignore,
  }

  firewallchain { 'OUTPUT:filter:IPv6':
    ensure => 'present',
    purge  => $chain_purge,
    ignore => $chain_purge_ignore,
  }

  firewallchain { 'FORWARD:filter:IPv6':
    ensure => 'present',
    purge  => $chain_purge,
    ignore => $chain_purge_ignore,
  }

  # The chains' policies should only be changed to drop after all "accept"
  # rules have been added. The following is a workaround to achieve idepotency.
  # If the desired policy is drop and the chain is already set to drop then
  # do not change the policy to accept (the default). If the policy needs to
  # change this will be done in the post_ipv6 class.
  if $chain_policy == 'drop' and $::iptables_input_policy == 'drop' {
    Firewallchain['INPUT:filter:IPv6'] {
      policy => 'drop',
    }
  }

  if $chain_policy == 'drop' and $::iptables_output_policy == 'drop' {
    Firewallchain['OUTPUT:filter:IPv6'] {
      policy => 'drop',
    }
  }

  if $chain_policy == 'drop' and $::iptables_forward_policy == 'drop' {
    Firewallchain['FORWARD:filter:IPv6'] {
      policy => 'drop',
    }
  }

# ------------- Create Log and Drop IPv6 Chains ---------------

  base_firewall::log_drop_chain { 'INPUT:filter:IPv6': }
  base_firewall::log_drop_chain { 'OUTPUT:filter:IPv6': }
  base_firewall::log_drop_chain { 'FORWARD:filter:IPv6': }

# ---------------- Input Chain Rules ------------------

  firewall { '000 allow incoming on loopback IPv6':
    action  => 'accept',
    proto   => 'all',
    iniface => 'lo',
  }->

  firewall { '007 allow incoming established, related IPv6':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
  }->

  firewall { '008 allow incoming icmp6':
    proto  => 'ipv6-icmp',
    action => 'accept',
  }->

  firewall { '020 allow incoming ssh IPv6':
    dport  => $sshd_port,
    proto  => 'tcp',
    action => 'accept',
  }->

# -------------- Output Chain Rules ----------------

  firewall { '000 allow outgoing on loopback IPv6':
    chain    => 'OUTPUT',
    action   => 'accept',
    proto    => 'all',
    outiface => 'lo',
  }->

  firewall { '005 allow outgoing established, related IPv6':
    chain  => 'OUTPUT',
    proto  => 'all',
    state  => ['ESTABLISHED', 'RELATED'],
    action => 'accept',
  }

  firewall { '007 allow outgoing icmp6':
    chain  => 'OUTPUT',
    proto  => 'ipv6-icmp',
    action => 'accept',
  }

  if ($allow_new_outgoing) {
    firewall { '006 allow new outgoing IPv6':
      chain   => 'OUTPUT',
      proto   => 'all',
      state   => 'NEW',
      action  => 'accept',
      require => Firewall['005 allow outgoing established, related IPv6'],
    }
  }
}
