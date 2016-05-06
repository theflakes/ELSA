#!/usr/bin/env python
"""
    Author: Brian Kellogg
    Elsa API query

    elsa_query.ini format:
        [MAIN]
        user = elsa
        ip =
        apikey =
"""

from __future__ import print_function
import optparse
import time
import hashlib
from requests import Request, Session
import json
import datetime
from configparser import ConfigParser


def query_elsa(user, apikey, ip, query):
    url = 'https://' + ip + '/elsa-query/API/query'
    epoch = int(time.time())
    hash_it = hashlib.sha512()
    hash_it.update(str(epoch) + apikey)
    header = {}
    header['Authorization'] = 'ApiKey ' + user + ':' + str(epoch) + ':' + hash_it.hexdigest()
    s = Session()
    payload = '{"class_id":{"0": 1},"program_id":{"0": 1},"node_id":{"0": 1},"host_id":{"0": 1}}'
    elsa_post = Request('POST', url,
                        data=[('permissions', payload), ('query_string', query)],
                        headers=header)
    data = elsa_post.prepare()
    results = s.send(data, verify=False)
    return results


def read_conf():
    config = ConfigParser()
    config.read('./elsa_query.ini')
    user = config.get('MAIN', 'user')
    apikey = config.get('MAIN', 'apikey')
    ip = config.get('MAIN', 'ip')
    return user, apikey, ip


def print_results(output):
    output = json.loads(output)
    if 'groupby' in output:
        col_headers = "{:^35} {:<20}".format('Group', 'Value')
        print(col_headers)
        for row in output['results'].values()[0]:
            aligned_row = "{:>35} {:<20}".format(row['_groupby'], row['_count'])
            print(aligned_row)
    else:
        for msg in output['results']:
            log = json.dumps(msg['msg'], ensure_ascii=True)
            log = log.replace("\\\\\\\\", "\\")
            print(log)


if __name__ == "__main__":
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    temp = datetime.date.today() - datetime.timedelta(1)
    yesterday = temp.strftime("%Y-%m-%d %H:%M:00")
    parser = optparse.OptionParser(usage='''
        Usage: elsa_query.py --query "127.0.0.1 dstport:80 groupby:dstip" --print -l 1000 -p

        -a, --apikey  : Elsa API key
                        If not specified then read it from the elsa_query.ini file
                        If this option is used then specify options -i and -u or accept the their defaults.
        -e, --end     : End date in the form of '2016-04-30 16:47:53'
                        Default is now
        -i, --ip      : Elsa server IP
                        Default is '127.0.0.1'
        -l, --limit   : The number of records to return
                        Do not use the limit directive in the search string
                        Default is 100
        -p, --print   : Print search results to stdout
        -q, --query   : Elsa query string
        -s, --start   : Start date in the form of '2016-04-30 16:47:53'
                        Default is yesterday at midnight
        -u, --user    : Elsa user
                        Default is 'elsa'
        -v, --verbose : Print verbose results

        When running this on Windows you will need to escape quotes in the Elsa search string with a quote.
            |_> For example: "127.0.0.1 BRO_HTTP.uri=""/test/testing/"""
        Note that an Elsa API search will search the entire available time range by default.
            \_> Therefore use the start and end options to specify the query window.
            \_> If no start is specified, a start date of now minus 1 day is assumed.
            \_> If no end date is set, then an end date of now is assumed.
        ''')
    parser.add_option('-a', '--apikey',
                      dest='elsa_apikey', action='store', type='string', )
    parser.add_option('-e', '--end',
                      dest='elsa_end', action='store', type='string',
                      default=now)
    parser.add_option('-i', '--ip',
                      dest='elsa_ip', action='store', type='string',
                      default='127.0.0.1')
    parser.add_option('-l', '--limit',
                      dest='elsa_limit', action='store', type='string',
                      default='100')
    parser.add_option('-p', '--print',
                      dest='print', action='store_true')
    parser.add_option('-q', '--query',
                      dest='elsa_query', action='store', type='string')
    parser.add_option('-s', '--start',
                      dest='elsa_start', action='store', type='string',
                      default=yesterday)
    parser.add_option('-u', '--user',
                      dest='elsa_user', action='store', type='string',
                      default='elsa')
    parser.add_option('-v', '--verbose',
                      dest='verbose', action='store_true')
    (options, args) = parser.parse_args()
    if not options.elsa_query:
        parser.error('No query was specified!')
    if not options.elsa_apikey:
        elsa_user, elsa_apikey, elsa_ip = read_conf()
    else:
        elsa_user = options.elsa_user
        elsa_ip = options.elsa_ip
        elsa_apikey = options.elsa_apikey
    elsa_query = options.elsa_query + \
                 ' start:' + '"' + options.elsa_start + '"' + \
                 ' end:' + '"' + options.elsa_end + '"' + \
                 ' limit:' + options.elsa_limit
    query_results = query_elsa(elsa_user, elsa_apikey, elsa_ip, elsa_query)
    print('Query submitted to Elsa: ', elsa_query)
    if options.verbose:
        print(json.dumps(query_results.json(), indent=2))
        print('HTTP Status Code: ', query_results.status_code)
    if options.print:
        print_results(query_results.text)
    query_results = None
