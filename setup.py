from setuptools import setup


longdesc='''
This is a daemon to download CloudFlare access logs via
SFTP and upload them to Loggly using their HTTP bulk API.

Required packages:
  paramiko
  requests
'''

setup(
    name='cloudflare2loggly',
    description='Helper for pushing CloudFlare access logs to Loggly',
    long_description=longdesc,
    version='0.0.4',
    author='Rene Fragoso',
    author_email='ctrlrsf@gmail.com',
    url='https://github.com/ctrlrsf/cloudflare2loggly',
    py_modules=['cloudflare2loggly', 'sftplib'],
    entry_points={
        'console_scripts': [
            'cloudflare2loggly = cloudflare2loggly:main',
        ],
    },
    install_requires=[
        'paramiko',
        'requests',
    ],
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
)
