# <a id="kibana"></a> Using the ELK Proxy with Kibana

The ELK Proxy is designed to work with Kibana, but several things must be taken care of.

## Proxy chain

There shall be some non-bypassable reverse proxies between the user and Elasticsearch.

### A web server, e.g. Apache or nginx

This must be the only proxy (of the chain) a user can access directly.
It shall authenticate the user and forward their requests to Kibana.
It must not forward anonymous requests!

### Kibana

Since version 4 Kibana provides its own web server and reverse proxy.
Depending on the URL it either processes the request itself or forwards it to Elasticsearch.
It shall be configured to forward requests to the ELK Proxy, not to Elasticsearch.

### ELK Proxy

The ELK Proxy restricts users/groups as configured and forwards non-restricted requests to Elasticsearch.

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
a user with full access to the .kibana index has to access the Kibana interface once.
