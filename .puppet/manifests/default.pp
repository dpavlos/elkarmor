define iptables_allow_tcp_in() {
  exec { "iptables-allow-tcp-${name}":
    unless => "/bin/grep -qFxe '-A INPUT -p tcp -m tcp --dport ${name} -j ACCEPT' /etc/sysconfig/iptables",
    command => "/sbin/iptables -I INPUT -p tcp -m tcp --dport ${name} -j ACCEPT && /sbin/iptables-save >/etc/sysconfig/iptables",
  }
}


# Java

package { 'java':
  name => 'java-1.7.0-openjdk',
}


# Logstash

yumrepo { 'logstash-1.5':
  descr => 'logstash 1.5.x repository',
  target => 'logstash.repo',
  ensure => present,
  baseurl => 'http://packages.elasticsearch.org/logstash/1.5/centos',
  enabled => 1,
  gpgkey => 'http://packages.elasticsearch.org/GPG-KEY-elasticsearch',
  repo_gpgcheck => 1,
}
-> package { 'logstash':
  require => Package['java'],
}
-> service { 'logstash':
  ensure => running,
  enable => true,
}

file { 'logstash-io.conf':
  path => '/etc/logstash/conf.d/io.conf',
  ensure => file,
  source => '/vagrant/.puppet/files/logstash-io.conf',
  require => [
    Package['logstash'], Service['elasticsearch']
  ],
  notify => Service['logstash'],
}


# Elasticsearch

yumrepo { 'elasticsearch-1.7':
  descr => 'Elasticsearch 1.7.x repository',
  target => 'elasticsearch.repo',
  ensure => present,
  baseurl => 'http://packages.elastic.co/elasticsearch/1.7/centos',
  enabled => 1,
  gpgkey => 'http://packages.elastic.co/GPG-KEY-elasticsearch',
  repo_gpgcheck => 1,
}
-> package { 'elasticsearch':
  require => Package['java'],
}
-> service { 'elasticsearch':
  ensure => running,
  enable => true,
}


# ELK Proxy

file { 'elkarmor-pid':
  path => '/var/run/elkarmor.pid',
  ensure => file,
}

file { '/etc/elkarmor':
  ensure => directory,
}
-> file { 'elkarmor-cfg':
  path => '/etc/elkarmor/config.ini',
  ensure => file,
  source => '/vagrant/.puppet/files/elkarmor.ini',
  replace => false,
  links => follow,
}

file { 'elkarmor-cfg-restrictions':
  path => '/etc/elkarmor/restrictions.ini',
  ensure => file,
  source => '/vagrant/.puppet/files/elkarmor-restrictions.ini',
  replace => false,
  links => follow,
  require => File['/etc/elkarmor'],
}

exec { 'epel':
  unless => '/bin/rpm --quiet -q epel-release',
  command => '/usr/bin/yum -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm"',
  timeout => 0,
}
-> package { [ 'python-netifaces', 'python-ldap' ]: }
-> file { '/usr/lib/python2.6/site-packages/libelkarmor':
  ensure => link,
  target => '/vagrant/libelkarmor',
}
-> file { '/etc/rc.d/init.d/elkarmor':
  ensure => file,
  source => '/vagrant/.puppet/files/init.d-elkarmor',
  mode => '0744',
  require => File[['elkarmor-pid', 'elkarmor-cfg', 'elkarmor-cfg-restrictions']],
}
-> service { 'elkarmor':
  ensure => running,
  enable => true,
}

iptables_allow_tcp_in { '59200': }


# Kibana

file { 'kibana-dir':
  path => '/opt/kibana',
  ensure => directory,
}
-> exec { 'fetch-kibana':
  cwd => '/opt/kibana',
  unless => '/usr/bin/test -d bin',
  command => '/usr/bin/wget -nv -O - "https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x64.tar.gz" | /bin/tar -zx --strip-components=1',
  timeout => 0,
}
-> exec { 'kibana-chcfg':
  cwd => '/opt/kibana',
  provider => shell,
  command => '/usr/bin/perl -pi -e \'s/(?<=\bhttp:\/\/localhost:)9200\b/59200/g;\' config/kibana.yml',
  timeout => 0,
}

file { 'init.d-kibana':
  path => '/etc/rc.d/init.d/kibana',
  ensure => file,
  source => '/vagrant/.puppet/files/init.d-kibana',
  mode => '0744',
}
-> service { 'kibana':
  ensure => running,
  enable => true,
  require => [ Exec['kibana-chcfg'], Service['elkarmor'] ],
}


# HTTPd reverse proxy for Kibana

package { 'httpd': }
-> service { 'httpd':
  ensure => running,
  enable => true,
}

file { 'httpd-htpasswds':
  path => '/etc/httpd/htpasswds',
  ensure => file,
  source => '/vagrant/.puppet/files/httpd-htpasswds',
  replace => false,
  links => follow,
}

package { 'mod_ssl': }
-> file { 'kibana-revproxy.conf':
  path => '/etc/httpd/conf.d/kibana-revproxy.conf',
  ensure => file,
  source => '/vagrant/.puppet/files/httpd-kibana-revproxy.conf',
  require => [ Package['httpd'], File['httpd-htpasswds'] ],
  notify => Service['httpd'],
}

iptables_allow_tcp_in { '58080': }
