from setuptools import setup

setup(
    name='elkarmor',
    version='0.0',
    author='NETWAYS GmbH',
    author_email='info@netways.de',
    description='a transparent proxy for securing Elasticsearch',
    license='GPLv2+',
    url='https://project.netways.de/projects/elk-proxy',
    long_description='The ELK Proxy is a transparent HTTP proxy for securing '
                     'Elasticsearch by permitting specific users to access only '
                     'specific data.',
    packages=['libelkproxy'],
    zip_safe=False
)
