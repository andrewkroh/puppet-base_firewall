# == Class: base_firewall::logging
#
# Configures rsyslog and logrotate for iptables. Rsyslog is configured
# to write iptables messages to their own file. Logrotate is configured
# to manage this iptables log file.
#
# This class only supports RedHat/Centos because it makes assumptions on
# service names and configuration directory locations. It may work on
# other operating systems but has not been tested.
#
# === Authors
#
# Andrew Kroh <andy@crowbird.com>
#
# === Copyright
#
# Copyright 2014, Andrew Kroh
#
class base_firewall::logging () {

  if !defined(Service['rsyslog']) {
      service { 'rsyslog':
        hasrestart => true,
        hasstatus  => true,
      }
  }

  file { '/etc/rsyslog.d/iptables.conf':
    ensure  => file,
    source  => 'puppet:///modules/base_firewall/rsyslog-iptables.conf',
    mode    => '0755',
    owner   => 'root',
    group   => 'root',
    notify  => Service['rsyslog'],
  }

  file { '/etc/logrotate.d/iptables':
    ensure  => file,
    source  => 'puppet:///modules/base_firewall/logrotate-iptables',
    mode    => '0755',
    owner   => 'root',
    group   => 'root',
  }
}
