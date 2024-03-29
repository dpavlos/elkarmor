# <a id="kibana"></a> Using the ELK Armor with Kibana

The ELK Armor is designed to work with Kibana, but several things must be taken
care of.

## Proxy chain

There shall be some non-bypassable reverse proxies between the user and
Elasticsearch.

### A web server, e.g. Apache or nginx

This must be the only proxy (of the chain) a user can access directly.
It shall authenticate the user and forward their requests to Kibana.
It must not forward anonymous requests!

### Kibana

Since version 4 Kibana provides its own web server and reverse proxy.
Depending on the URL it either processes the request itself or forwards it to
Elasticsearch. It shall be configured to forward requests to the ELK Armor,
not to Elasticsearch.

### ELK Armor

The ELK Armor restricts users/groups as configured and forwards non-restricted
requests to Elasticsearch.

## Restrictions

All users must have at least read access to the .kibana index.
All users must have access to the following URLs:

* /
* /_nodes
* /_cluster

### Configuration

```
[kibana]
users=*
read=.kibana
url_begin_0=(?:\?|\Z)
url_begin_1=_(?:nodes|cluster)(?:/|\?|\Z)
```

## Initialization of the .kibana index

Before users with only read access to the .kibana index can use Kibana,
a user with full access to the .kibana index has to access the Kibana interface
once.

## Requests from Kibana to Elasticsearch

GET /
GET /_cluster
Gets some basic info about the Elasticsearch cluster.

GET /_nodes
Gets some info about the cluster's nodes.

### .kibana index

Kibana stores all interface-related stuff here. E.g.:

  type          | description
  --------------|---------------------------------
  config        | Kibana configuration
  index-pattern | index patterns e.g. "logstash-*"
  search        | saved searches
  visualization | visualizations of saved searches
  dashboard     | dashboards with visualizations
