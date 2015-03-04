# == Define: base_firewall::log_drop_chain
#
# Creates an iptables filter chain that logs traffic and then drops it. This
# does not install any jumps that point to the chain created by this type.
#
# The title must of the form chain:table:protocol like INPUT:filter:IPv4. The
# previous example would create a new IPv4 chain titled DROP_INPUT.
#
define base_firewall::log_drop_chain () {

  $name_parts = split($name, ':')
  $chain = $name_parts[0]
  $filter = $name_parts[1]
  $protocol = $name_parts[2]
  $drop_chain = "DROP_${chain}"

  validate_re($protocol, ['^IPv4$', '^IPv6$'])

  $provider = $protocol ? {
    'IPv4' => 'iptables',
    'IPv6' => 'ip6tables',
  }

  firewallchain { "DROP_${name}":
    ensure => present,
  }

  firewall { "000 log dropped ${chain} ${protocol}":
    proto      => 'all',
    jump       => 'LOG',
    limit      => '10/min',
    log_prefix => "iptables ${drop_chain}: ",
    log_level  => 7,
    chain      => $drop_chain,
    provider   => $provider,
  }->

  firewall { "001 drop ${chain} ${protocol}":
    proto    => 'all',
    action   => 'drop',
    chain    => $drop_chain,
    provider => $provider,
  }
}
