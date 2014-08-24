from setuptools import setup

from heartbeat import __version__

setup(
    name='heartbeat',
    version=__version__,
    url='https://github.com/Storj/heartbeat',
    license='The MIT License',
    author='Storj Labs',
    author_email='info@storj.io',
    description='Python library for verifying existence of a file',
    packages=['heartbeat'],
)
