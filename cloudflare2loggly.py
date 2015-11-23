"""
Download CloudFlare logs via SFTP and send them to Loggly via HTTP bulk
API.
"""

from __future__ import print_function
import argparse
import csv
import gzip
import json
import logging
import logging.handlers
import os
import re
import requests
import sys
import time
import sftplib

log = logging.getLogger(__name__)

def gunzip_file(input_file_name, output_file_name):
    """
    Decompress gzip file into output file
    """
    with gzip.open(input_file_name, 'rb') as gzip_input:
        input_file_content = gzip_input.read()
        with open(output_file_name, 'w') as output:
            output.write(input_file_content)

def loggly_upload_records(token, tag, json_string):
    """
    Use the Loggly HTTPS bulk API to send JSON log records
    https://www.loggly.com/docs/http-bulk-endpoint/

    Parameters:
    token: Loggly auth token
    tag: tag to add to these records
    json_string: String of JSON records, each separated by a new line

    Returns tuple of status_code and and response text

    """
    bulk_base_url = 'https://logs-01.loggly.com/bulk'

    # final_url should look like: http://logs-01.loggly.com/bulk/TOKEN/tag/TAG
    final_url = '{}/{}/tag/{}'.format(bulk_base_url, token, tag)

    log.info("Sending %d bytes to loggly URL: %s",
             len(json_string),
             final_url.replace(token, "<OBFUSCATED_TOKEN>"))

    headers = dict()
    headers['content-type'] = 'text/plain'

    post_request = requests.post(final_url, headers=headers, data=json_string)

    log.info('Loggly upload status_code: %d', post_request.status_code)
    log.info('Loggly response text: %s', post_request.text)

    if post_request.status_code != 200:
        log.warn('Loggly upload did not complete successfully!')

    return post_request.status_code, post_request.text


def parse_cloudflare_log_file(filename):
    """
    Read a CloudFlare log file and convert it to JSON
    """
    with open(filename) as csvfile:
        cloudflare_csv_reader = csv.reader(csvfile, delimiter=' ', quotechar='"')
        for row in cloudflare_csv_reader:
            yield convert_row_to_dict(row)

def convert_row_to_dict(row):
    """
    Convert a list of fields in the CloudFlare CSV file
    into a dict with field names.
    """

    cf_dict = dict()
    cf_dict['hostname'] = row[0]
    cf_dict['clientIp'] = row[1]
    # CloudFlare Placeholder, always a hyphen
    cf_dict['col3'] = row[2]
    # CloudFlare Placeholder, always a hyphen
    cf_dict['col4'] = row[3]
    # CloudFlare timestamp is RFC 3339 and Loggly wants
    # ISO 8601. Should be compatible as RFC3339 is stricter
    # version of ISO 8601.
    cf_dict['timestamp'] = row[4]
    cf_dict['request'] = row[5]
    cf_dict['status'] = row[6]
    cf_dict['content-length'] = row[7]
    cf_dict['referer'] = row[8]
    cf_dict['user-agent'] = row[9]
    cf_dict['ray-id'] = row[10]

    return cf_dict

def convert_log_dict_to_json(cf_dict):
    """ Convert a parsed log dictionary to JSON """
    return json.dumps(cf_dict, sort_keys=True)

def process_cloudflare_log_file(loggly_token, loggly_tag, filename):
    """
    Parse a log file and ship it to Loggly
    """
    log.debug('Processing file: %s', filename)

    all_json_records = list()
    for log_dict in parse_cloudflare_log_file(filename):
        #log.debug('Record: %s', log_dict)
        try:
            json_record = convert_log_dict_to_json(log_dict)
            all_json_records.append(json_record)
        except Exception as exception:
            log.error('Skipping record that could not be converted to JSON')
            log.error('Record that could not be converted: %s', log_dict)
            log.exception(exception)

    log.debug('Number of records: %d', len(all_json_records))

    process_log_batch(loggly_token, loggly_tag, all_json_records)

def process_log_batch(loggly_token, loggly_tag, record_list):
    """
    Process a batch of log entries
    """

    # Loggly limit for HTTP PUT is 5MB
    loggly_limit = 5*1024*1024

    string_buffer = ''

    for record in record_list:
        # If the new record would go over the loggly limit, send what we
        # have collected in buffer so far, and clear out buffer
        if len(string_buffer) + len(record) >= loggly_limit:
            loggly_upload_records(loggly_token,
                                  loggly_tag,
                                  string_buffer)
            # Clear string buffer and add current record which hasn't been added yet
            string_buffer = record
        # We're still under the buffer limit, keep adding records to it
        else:
            string_buffer = string_buffer + '\n' + record

    # Send any remaining data in buffer
    if len(string_buffer) > 0:
        loggly_upload_records(loggly_token,
                              loggly_tag,
                              string_buffer)

def process_cloudflare_logs(loggly_token,
                            sftp_hostname,
                            sftp_port,
                            sftp_username,
                            sftp_private_key_file,
                            tmp_dir,
                            loggly_tag):
    """
    Process CloudFlare logs
    - Gets list of files
    - Downloads each at a time
    - Gunzips them
    - Parses them
    - Send logs to Loggly via HTTP bulk API
    """
    sftp = sftplib.SFTPClient(sftp_hostname,
                              sftp_port,
                              sftp_username,
                              sftp_private_key_file)

    # Log in
    try:
        sftp.login()
    except Exception as exception:
        log.error('Exception occurred logging into SFTP server: %s', exception)
        log.exception(exception)
        sftp.close()
        return False

    # List files on SFTP server
    try:
        sftp_files = sftp.list_files()
    except Exception as exception:
        log.error('Exception occurred getting list of files on SFTP server: %s', exception)
        log.exception(exception)
        sftp.close()
        return False

    # Keep only files that match expected log file name format
    # Sample log file name: logs-2015_08_19-20_46_00.log.gz
    log_file_re = re.compile(r'^logs.*\.gz$')
    sftp_files = [s for s in sftp_files if log_file_re.match(s)]

    log.info('Log files on SFTP server: %d', len(sftp_files))

    for sftp_file in sftp_files:
        try:
            log.info('Processing file: %s', sftp_file)

            local_file_name = tmp_dir + os.path.basename(sftp_file)
            uncompressed_file_name = local_file_name.replace('.gz', '')

            log.debug('Downloading log file: %s', sftp_file)
            sftp.get_file(sftp_file, local_file_name)

            log.debug('Uncompressing to: %s', uncompressed_file_name)
            gunzip_file(local_file_name, uncompressed_file_name)

            process_cloudflare_log_file(loggly_token, loggly_tag, uncompressed_file_name)

            log.debug('Deleting downloaded and uncompressed files.')
            os.unlink(local_file_name)
            os.unlink(uncompressed_file_name)
            sftp.remove_file(sftp_file)
        except Exception as exception:
            log.error('Exception processing file %s: %s', sftp_file, exception)
            log.exception(exception)

    log.info('Finished processing CloudFlare logs')

    sftp.close()

def change_to_cwd_of_script():
    """
    Change CWD to script's location
    """
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    log.debug('Changing CWD to: %d', dname)
    os.chdir(dname)

def make_temp_dir(tmp_dir):
    """
    Make directory for temporary files relative to
    script's location if doesn't already exist.
    """
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

def handle_script_args():
    """
    Parse arguments from command line
    """
    parser = argparse.ArgumentParser(description='Loggly importer for CloudFlare logs')
    parser.add_argument('--syslog', required=False,
                        action='store_true',
                        help='Log to local syslog')
    parser.add_argument('--daemon', required=False,
                        action='store_true',
                        help='Run as daemon processing logs every interval')
    parser.add_argument('--config', required=True,
                        help='Config file')
    parser.add_argument('--debug', required=False,
                        action='store_true',
                        help='Enable debug mode')
    args = parser.parse_args()

    return args

def set_debug_level(enable_debug):
    """
    Set log levels to debug
    """
    if enable_debug == True:
        log.setLevel(logging.DEBUG)
        sftplib.LOG.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        sftplib.LOG.setLevel(logging.INFO)

def set_log_to_syslog(enable_syslog):
    """
    Set log library to use syslog
    """
    if enable_syslog == True:
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
        formatter = logging.Formatter('[%(levelname)s] %(module)s.%(funcName)s: %(message)s')
        syslog_handler.setFormatter(formatter)
        log.addHandler(syslog_handler)
        sftplib.LOG.addHandler(syslog_handler)
    else:
        logging.basicConfig()

def load_config(config_file):
    """
    Load JSON config file into global config dictionary
    """
    global config
    config=json.load(open(config_file))

def main():
    """
    Main entry point for script.
    Log into SFTP server, get list of files, download file, parse it,
    upload JSON to Loggly, delete file
    """
    change_to_cwd_of_script()


    args = handle_script_args()

    set_debug_level(args.debug)

    set_log_to_syslog(args.syslog)

    load_config(args.config)

    loggly_token = config['loggly_token']

    config_check_interval = config.get('check_interval', '5')
    sleep_interval = int(config_check_interval) * 60

    make_temp_dir(config['tmp_dir'])

    if args.daemon == True:
        log.info('Running in daemon mode')
        while True:
            log.info('Starting log processing run')
            try:
                process_cloudflare_logs(loggly_token,
                                        config['sftp_hostname'],
                                        config['sftp_port'],
                                        config['sftp_username'],
                                        config['sftp_private_key_file'],
                                        config['tmp_dir'],
                                        config['loggly_tag'])
            except Exception as exception:
                log.error('Exception occurred processing logs: %s', exception)
                log.exception(exception)

            log.info('Finished log processing run')
            time.sleep(sleep_interval)
    else:
        process_cloudflare_logs(loggly_token,
                                config['sftp_hostname'],
                                config['sftp_port'],
                                config['sftp_username'],
                                config['sftp_private_key_file'],
                                config['tmp_dir'],
                                config['loggly_tag'])

if __name__ == '__main__':
    main()
