# <a id="restriction-configuration"></a> Restriction configuration

Each restriction is configured as INI section and defines which user or group
is permitted to access which Elasticsearch index or URL. It is possible to also
define whether full or read only access is permitted.

To configure a new restriction, create a new section and give it at least one
of the following two options:

````
[new_restriction]
users = user1,user2                 ; Comma separated list of usernames
group = <group-dn-1>|<group-dn-2>   ; Pipe separated list of group DNs
````

A username is equal to the one a user will utilize to login. Groups for which
this restriction should apply need to be defined with their DN.

## Restricting Indexes

Indexes are defined using their name or a partially matching pattern using
the `*` (asterisk) wildcard.

=== Read Only Access

To only permit read access for a particular index you can define the option
`read` and give it one or more index names or wildcards:

````
[new_restriciton]
...
read = <index-1>,<index-2>  ; Comma separated list of index names/wildcards
````

=== Full Access

Full access to particular indexes can be granted with any other option:

````
[new_restriction]
...
index1 = <index-1>
index2and3 = <index-2>,<index-3>
````

== Granting Access By URL

You can also grant users or groups access to specific URLs. Note that by doing
this you'll circumvent all restriction checks for this particular URL or URLs.

URLs are defined using regular expressions. There are four ways to define a URL
by using one of the following option prefixes:

  * url (Match at any position)
  * url_begin (Match at the start)
  * url_end (Match at the end)
  * url_full (Attempt a full match)

An example how this might look like is provided below:

````
[new_restriction]
...
url_foo = foo
url_begin_bar = bar
url_end_foobar = foo/bar
url_full_foobar = /foo/bar/1234
````
