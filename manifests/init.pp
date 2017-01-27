# == Class: base_firewall
#
# Install and configure a firewall on the machine. A base set of firewall
# rules are added which include an allowance for incoming SSH on port 22.
# All outgoing traffic is allowed.
#
# Applications that want to add additional rules in the firewall can
# define their own firewall rules by including configuration like this.
#
# firewall { '150 open tcp port 585':
#   dport => 585,
#   action => accept,
# }
#
# Each rule name must be unique. The rules are added to each individual
# firewall chain in ascending order based on their names. Each rule name
# should start with a three digit number to assist in ordering. 000-099
# and 900-999 are reserved for the "pre" and "post" rulesets that are
# defined by this module.
#
# For additional information see the Puppet Labs firewall module documenation
# at https://forge.puppetlabs.com/puppetlabs/firewall.
#
# === Parameters
#
# [*allow_new_outgoing_ipv4*]
#   Boolean parameter that determines if the firewall should allow all new
#   outgoing IPv4 connections. The parameter defaults to false which means that
#   new outgoing connections will be dropped unless there is a rule that
#   explicitly allows the traffic.
#
# [*allow_new_outgoing_ipv6*]
#   Boolean parameter that determines if the firewall should allow all new
#   outgoing IPv6 connections. The parameter defaults to false which means that
#   new outgoing connections will be dropped unless there is a rule that
#   explicitly allows the traffic.
#
# [*manage_sshd_firewall*]
#   Boolean parameter that determines if a firewall rule should be added to allow
#   SSH access on the given port (see the 'sshd_port' parameter). The parameter
#   defaults to true. If you set it to false, make sure you open up the SSH port
#   yourself, else you will be locked out!
#
# [*sshd_port*]
#   SSH server port that access should be granted to. Defaults to 22.
#
# [*purge*]
#   Boolean parameter that determines if all unmanaged firewall rules and chains
#   are purged. Defaults to true.  Requires puppetlabs/firewall 1.2.0+ in order
#   for IPv6 resources to be purged.
#
# [*chain_policy*]
#   Policy (drop, accept) to apply to each chain (INPUT, FORWARD, OUTPUT).
#   Defaults to drop. The last rules in each chain are always "log then drop"
#   so the policy has minimal effect.
#
# [*chain_purge*]
#   An alternative method of purging unmanaged firewall rules that operates
#   only on the INPUT, OUTPUT, and FORWARD chains. This method of purging
#   unmanaged rules allows you to specify an array of regular expressions that
#   match against firewall rules that should be ignored when purging (see the
#   'ignores' variable. The default value is false and its usage with
#   'purge' is mutually exclusive.
#
#   An example use case would be to ignore firewall rules that are managed
#   by another application like docker.
#
# [*manage_logging*]
#   Boolean parameter specifying whether this module should manage logger
#   config for iptables. Defaults to false. If true then rsyslog will be
#   configured to write all iptables events to /var/log/iptables.log and
#   logrotate will manage the file.
#
# === Variables
#
# [*rules*]
#   Hash containing firewall rule data that is used to create firewall
#   resources. The parameter is optional.
#
#   This parameter can be used to pass in firewall rules through hiera
#   configuration.
#
# [*ignores*]
#   An array of regular expressions that match against firewall rules that
#   should be ignored when purging. Defaults to undefined and is only used
#   when chain_purge is set to true.
#
# === Examples
#
#  class { 'base_firewall': }
#
# === Authors
#
# Andrew Kroh
#
class base_firewall(
  $allow_new_outgoing_ipv4 = false,
  $allow_new_outgoing_ipv6 = false,
  $manage_sshd_firewall    = true,
  $sshd_port               = 22,
  $purge                   = true,
  $chain_policy            = 'drop',
  $chain_purge             = false,
  $manage_logging          = false,
) {

  #------------------------ Validation ----------------------------------------

  validate_bool($allow_new_outgoing_ipv4)
  validate_bool($allow_new_outgoing_ipv6)
  validate_bool($manage_sshd_firewall)

  if !is_integer($sshd_port) or $sshd_port < 1 or $sshd_port > 65535 {
    fail('sshd_port must be an integer between [1, 65535].')
  }

  validate_bool($purge)
  validate_re($chain_policy, ['^accept$', '^drop$'])
  validate_bool($chain_purge)
  validate_bool($manage_logging)

  if $purge and $chain_purge {
    fail('purge and chain_purge and mutually exclusive. Set only one to true.')
  }

  #----------------------------------------------------------------------------

  # Lookup array using hiera so that arrays defined in different files are
  # automatically merged.
  $ignores = hiera_array('base_firewall::ignores', [])

  class { 'base_firewall::pre_ipv4':
    allow_new_outgoing   => $allow_new_outgoing_ipv4,
    manage_sshd_firewall => $manage_sshd_firewall,
    sshd_port            => $sshd_port,
    chain_policy         => $chain_policy,
    chain_purge          => $chain_purge,
    chain_purge_ignore   => $ignores,
  }

  class { 'base_firewall::post_ipv4':
    chain_policy => $chain_policy,
  }

  class { 'base_firewall::pre_ipv6':
    allow_new_outgoing   => $allow_new_outgoing_ipv6,
    manage_sshd_firewall => $manage_sshd_firewall,
    sshd_port            => $sshd_port,
    chain_policy         => $chain_policy,
    chain_purge          => $chain_purge,
    chain_purge_ignore   => $ignores,
  }

  class { 'base_firewall::post_ipv6':
    chain_policy => $chain_policy,
  }

  # Include the pre/post rules and ensure that the pre
  # rules always run before the post rules to prevent
  # us from being locked out of the system.
  Firewall {
    require => [Class['base_firewall::pre_ipv4'],
                Class['base_firewall::pre_ipv6']],
    before  => [Class['base_firewall::post_ipv4'],
                Class['base_firewall::post_ipv6']],
  }

  # Purge any firewall rules not managed by Puppet.
  if $purge {
    resources { 'firewall':
      purge => true,
    }
  }

  # Lookup hash in hiera. Note: This is using the hiera_hash function
  # directly because it wants all the base_firewall::rules hashes defined
  # in hiera configuration files to be merged together. Using automatic
  # parameter lookup would have only returned the highest priority hash.
  $rules = hiera_hash('base_firewall::rules', {})

  # Create rules from the given hash.
  if $rules {
    create_resources(firewall, $rules)
  }

  if $manage_logging {
    include base_firewall::logging
  }
}
