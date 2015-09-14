# <a id="general-configuration"></a> General Configuration

## Logging

It is possible to log messages to syslog or a local file. The section is called
`log` and accepts the following options:

````
[log]
type = syslog       ; "file" or "syslog"
level = error       ; "crit", "err", "warn", "info" or "debug"
prefix = elkproxy
;path = /var/log/elkproxy/elkproxy.log
````

## Network

To configure how the proxy will listen for incoming requests, define a section
called `netio` which accepts the following options:

````
[netio]
inet = <ipv4-address-or-interface>:<port>
;inet6 = <ipv6-address-or-interface>:<port>
;inet-ssl = <ipv4-address-or-interface>:<SSL-enabled-port>
;inet6-ssl = <ipv6-address-or-interface>:<SSL-enabled-port>
;keyfile = <path-to-the-SSL-private-key>
;certfile = <path-to-the-SSL-certificate>
````

The options `keyfile` and `certfile` are only required if the option `inet-ssl`
or `inet6-ssl` is given.

## Elasticsearch

To configure how the proxy should access Elasticsearch, define a section called
`elasticsearch` which accepts the following options:

````
[elasticsearch]
host = <host>               ; Default is "localhost"
port = <port>               ; Default is 9200
protocol = https            ; Default is "http"
baseurl = /elasticsearch    ; Default is "/"
````

## LDAP

The proxy requires a ActiveDirectory server to fetch a user's groups from. To
configure this, define a section called `ldap` which accepts the following
options:

````
[ldap]
url = <url> ; Default is "ldap://localhost"
bind_dn = <bind-dn>     ; Optional, leave empty for anonymous access
bind_pw = <bind-pw>     ; Optional
group_base_dn = <dn>    ; The DN where to look for groups
user_base_dn = <dn>     ; The DN where to look for users
````

=== Utilizing a Encrypted Connection

To establish a encrypted connection to the server the `ldaps` protocol
identifier can be used in the URL. The given port defines whether to use SSL
or STARTTLS. (636 == SSL, 389 == STARTTLS)

Example for a SSL encrypted connection:

````
[ldap]
url = "ldaps://localhost:636"
...
````
