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


# ELK Proxy

file { 'elkproxyd-pid':
  path => '/var/run/elkproxyd.pid',
  ensure => file,
}

file { '/etc/elkproxyd':
  ensure => directory,
}
-> file { 'elkproxyd-cfg':
  path => '/etc/elkproxyd/config.ini',
  ensure => file,
  source => '/vagrant/.puppet/files/elkproxyd.ini',
}

file { 'python-daemon':
  path => '/usr/lib/python2.6/site-packages/daemon.py',
  ensure => link,
  target => '/vagrant/lib/daemon.py',
}

exec { 'epel':
  unless => '/bin/rpm --quiet -q epel-release',
  command => '/usr/bin/yum -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm"',
  timeout => 0,
}
-> package { 'python-netifaces': }
-> file { '/usr/lib/python2.6/site-packages/elkproxy':
  ensure => link,
  target => '/vagrant/lib/elkproxy',
}
-> file { '/usr/local/bin/elkproxyd':
  ensure => link,
  target => '/vagrant/bin/elkproxyd.py',
  require => File['python-daemon'],
}
-> file { '/etc/rc.d/init.d/elkproxy':
  ensure => file,
  source => '/vagrant/.puppet/files/init.d-elkproxy',
  mode => '0744',
  require => File[['elkproxyd-pid', 'elkproxyd-cfg']],
}
-> service { 'elkproxy':
  ensure => running,
  enable => true,
}


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
  require => [ Exec['kibana-chcfg'], Service['elkproxy'] ],
}


# HTTPd reverse proxy for Kibana

package { 'httpd': }
-> service { 'httpd':
  ensure => running,
  enable => true,
}

package { 'mod_ssl': }
-> file { 'kibana-revproxy.conf':
  path => '/etc/httpd/conf.d/kibana-revproxy.conf',
  ensure => file,
  source => '/vagrant/.puppet/files/httpd-kibana-revproxy.conf',
  require => Package['httpd'],
  notify => Service['httpd'],
}

exec { 'iptables-allow-httpd':
  unless => '/bin/grep -qFxe "-A INPUT -p tcp -m tcp --dport 58080 -j ACCEPT" /etc/sysconfig/iptables',
  command => '/sbin/iptables -I INPUT -p tcp -m tcp --dport 58080 -j ACCEPT && /sbin/iptables-save >/etc/sysconfig/iptables',
}
