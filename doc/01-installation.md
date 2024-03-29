# Installation

The preferred way of installing ELK Armor is to use packages depending on which operating
system and distribution you are running. But it is also possible to install ELK Armor directly from source.

## <a id="installing-requirements"></a> Installing Requirements

* A web server, e.g. Apache or nginx
* Python2 >= 2.6
* python-netifaces and python-ldap libraries
* python-setuptools if you're installing ELK Armor from source

## Installing ELK Armor from Package

> Please note that there is no official package repository yet.
> RPMs for ELK Armor are provided by [NETWAYS](https://www.netways.de/).

Example for RPM-based Linux distributions:
````
rpm -Uvh elkarmor.rpm
````

## Installing ELK Armor from Source

Although the preferred way of installing ELK Armor is to use packages,
it is also possible to install ELK Armor directly from source.

All of the steps bellow assume that you are root.

First of all, you need to extract the source tarball and change into the extracted directory.

````
tar xzf elkarmor.tar.gz
cd elkarmor
````

After that you have to call the Python `setup.py` script for installing ELK Armor into Python's standard directory for
modules.

````
python setup.py install
````

The next step is to install the System V init script.

````
install -m 0744 elkarmor.init /etc/rc.d/init.d/elkarmor
chkconfig --add elkarmor
````

Finally install the example configuration.

````
install -d -m 0700 /etc/elkarmor
install -m 0600 etc/elkarmor.ini /etc/elkarmor/config.ini
````

