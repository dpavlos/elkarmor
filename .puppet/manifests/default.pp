package { 'java':
  name => 'java-1.7.0-openjdk',
}

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

yumrepo { 'elasticsearch-1.6':
  descr => 'Elasticsearch 1.6.x repository',
  target => 'elasticsearch.repo',
  ensure => present,
  baseurl => 'http://packages.elastic.co/elasticsearch/1.6/centos',
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

file { 'init.d-kibana':
  path => '/etc/rc.d/init.d/kibana',
  ensure => file,
  source => '/vagrant/.puppet/files/init.d-kibana',
  mode => '0744',
}
-> service { 'kibana':
  ensure => running,
  enable => true,
  require => Exec['fetch-kibana'],
}

exec { 'iptables-allow-kibana':
  unless => '/bin/grep -qFxe "-A INPUT -p tcp -m tcp --dport 5601 -j ACCEPT" /etc/sysconfig/iptables',
  command => '/sbin/iptables -I INPUT -p tcp -m tcp --dport 5601 -j ACCEPT && /sbin/iptables-save >/etc/sysconfig/iptables',
}
