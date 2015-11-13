from setuptools import setup

setup(
    name='elkarmor',
    version='0.0',
    author='NETWAYS GmbH',
    author_email='info@netways.de',
    description='a transparent proxy for securing Elasticsearch',
    license='GPLv2+',
    url='https://www.netways.org/projects/elkarmor',
    long_description='The ELK Armor is a transparent HTTP proxy for securing '
                     'Elasticsearch by permitting specific users to access only '
                     'specific data.',
    packages=['libelkarmor'],
    zip_safe=False
)
