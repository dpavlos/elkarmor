# <a id="examples"></a> Configuration examples

## Using Elasticsearch with Logstash and Kibana (ELK Stack)

Assume that Logstash is writing all the log messages to Elasticsearch
and the admins must view/analyze the messages via Kibana,
but the admins must not create any dashboards.

### Granting the admin access to Kibana

With the following restriction all members of the group "logstash-admin"
will be able to use Kibana read-only.

```
[logstash-admin]
group=logstash-admin
read=.kibana                    ; Index: .kibana (read-only)
url_begin_0=(\?|$)              ; URL: /
url_begin_1=_nodes(/|\?|$)      ; URL: /_nodes
url_begin_2=_cluster(/|\?|$)    ; URL: /_cluster
```

### Granting the admin access to the Logstash indices

With the following restriction all members of the group "logstash-admin"
will be able to read all the Logstash indices.

```
[logstash-admin]
group=logstash-admin
read=logstash-*
```

## Administrating Kibana

If the admin from the last example has only read access to the .kibana index,
someone has to initialize the index first. Maybe some dashboards have to be
created as well. Assume that there shall be a Kibana-admin who does all these
things.

### Granting the admin full access to Kibana

With the following restriction the user "kibana-admin"
will be able to do everything they want with Kibana.

```
[kibana-admin]
users=kibana-admin
index=.kibana                   ; Index: .kibana (full access)
url_begin_0=(\?|$)              ; URL: /
url_begin_1=_nodes(/|\?|$)      ; URL: /_nodes
url_begin_2=_cluster(/|\?|$)    ; URL: /_cluster
```
