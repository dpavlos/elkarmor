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
