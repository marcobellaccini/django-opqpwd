import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-opqpwd',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    license='Apache License 2.0',
    description='A Django-based password manager REST service with client-side encryption',
    long_description=README,
    url='https://github.com/marcobellaccini/django-opqpwd',
    author='Marco Bellaccini',
    author_email='marco.bellaccini[at!]gmail.com',
    scripts=['bin/opqpwdcliclient'],
    install_requires=[
        'Django',
        'djangorestframework',
        'pycrypto',
        'scrypt',
        'requests'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.10',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)