"""
Simple SFTP client using Paramiko
"""

from __future__ import print_function
import logging
import paramiko

LOG = logging.getLogger('sftplib')

class SFTPClient(object):
    """
    Simple SFTP client using Paramiko
    """
    def __init__(self, hostname, port, username, key_file):
        """
        Create the SFTPLib object for connection
        """
        self.sftp = None
        self.transport = None
        self.hostname = hostname
        self.port = port
        self.username = username
        self.key_file = key_file

    def login(self):
        """
        Log into SFTP server and establish the connection
        """
        try:
            rsa_key = paramiko.RSAKey.from_private_key_file(self.key_file)

            self.transport = paramiko.Transport((self.hostname, self.port))
            self.transport.connect(username=self.username, pkey=rsa_key)

            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
        except Exception as exception:
            print('Caught exception: {}'.format(exception))
            LOG.error('Caught exception: %s', exception)
            self.transport.close()

    def list_files(self):
        """
        Get list of files on SFTP server
        """
        file_list = self.sftp.listdir('.')
        return file_list

    def get_file(self, remotename, dst_dir):
        """
        Download file from SFTP server
        """
        try:
            self.sftp.get(remotename, dst_dir)
            return True
        except Exception as exception:
            LOG.error("Exception raised: %s", exception)
            return False

    def remove_file(self, remotename):
        """
        Delete a file on the remote server
        """
        try:
            self.sftp.remove(remotename)
            return True
        except Exception as exception:
            LOG.error("Exception raised: %s", exception)
            return False

    def close(self):
        """
        Close the SFTP connection
        """
        self.sftp.close()
        self.transport.close()
