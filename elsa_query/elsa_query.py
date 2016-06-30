#!/usr/bin/python
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
from yattag import Doc
import optparse
import time
import hashlib
from requests import Request, Session
import json
import datetime
from configparser import ConfigParser


# Global variables
data = []
doc, tag, text = Doc().tagtext()
doc.asis('<!DOCTYPE html>')
doc.asis('<html>')
with tag('head'):
    doc.asis('<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/2.2.2/jquery.min.js"></script>')
    doc.asis('<script type="text/javascript" src="https://code.jquery.com/ui/1.11.4/jquery-ui.min.js" integrity="sha256-xNjb53/rY+WmG+4L6tTl9m6PpqknWZvRt0rO1SRnJzw=" crossorigin="anonymous"></script>')
    doc.asis('<link rel="stylesheet" type="text/css" href="style.css">')


def query_elsa(user, apikey, ip, query):
    url = 'https://' + ip + '/elsa-query/API/query'
    epoch = int(time.time())
    hash_it = hashlib.sha512()
    hash_it.update(str(epoch) + apikey)
    header = {}
    header['Authorization'] = 'ApiKey ' + user + ':' + str(epoch) + ':' + hash_it.hexdigest()
    s = Session()
    payload = '{"class_id":{"0": 1},"program_id":{"0": 1},"node_id":{"0": 1},"host_id":{"0": 1}}'
    elsa_post = Request('POST',
                        url,
                        data=[('permissions', payload), ('query_string', query)],
                        headers=header)
    data = elsa_post.prepare()
    results = s.send(data, verify=False)
    return results


def print_url(child, depth, url, mtype):
    mime = str(mtype)
    if mime not in ['-']:
        mime = mime.split('/')[1]
    with tag('div', klass=mime):
        if child:
            doc.asis('&nbsp;' * depth * 5)
            text('|' + '_' + '> ')
        text(url)


def build_table(child, depth, timestamp, site, uri, socket, method,
                status_code, mime_type, user_agent, length, msg, elsa_server):
    cid = msg.split('|')[1]
    url = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(float(timestamp))) + ':  ' + site + uri
    with tag('button', klass='accordion'):
        print_url(child, depth, url, mime_type)
    with tag('div', klass='panel'):
        with tag('table'):
            with tag('tr'):
                with tag('th'):
                    text('Socket')
                with tag('th'):
                    text('Method')
                with tag('th'):
                    text('Status Code')
                with tag('th'):
                    text('Mime Type')
                with tag('th'):
                    text('User Agent')
                with tag('th'):
                    text('Content Length')
                with tag('th'):
                    text('CID')
            with tag('tr'):
                with tag('td'):
                    text(socket)
                with tag('td'):
                    text(method)
                with tag('td'):
                    text(status_code)
                with tag('td'):
                    text(mime_type)
                with tag('td'):
                    with tag('div', klass='left'):
                        text(user_agent)
                with tag('td'):
                    text(length)
                with tag('td'):
                    with tag('a', href='https://' + elsa_server + '/elsa-query/?query_string=' + cid, target='_blank'):
                        text(cid)


# Recursive procedure to sift through a list of all BRO_HTTP logs to associate
# referers to the sites that did the refering.
def find_referers(site, site_date, depth, elsa_server):
    global data
    depth += 1
    for refered in data:
        if site in refered['referer'] and site_date <= refered['timestamp']:
            data.remove(refered)
            build_table(True,
                        depth,
                        refered['timestamp'],
                        refered['site'],
                        refered['uri'],
                        refered['srcip'] + ':' + refered['srcport'] + ' <> ' + refered['dstip'] + ':' + refered['dstport'],
                        refered['method'],
                        refered['status_code'],
                        refered['mime_type'],
                        refered['user_agent'],
                        refered['content_length'],
                        refered['msg'],
                        elsa_server)
            if not (refered['site'] == "-"):
                find_referers(refered['site'] + refered['uri'], refered['timestamp'], depth, elsa_server)


def build_referer_view(elsa_server):
    global data
    doc.asis('<body>')
    for site in data:
        data.remove(site)
        build_table(False,
                    0,
                    site['timestamp'],
                    site['site'],
                    site['uri'],
                    site['srcip'] + ':' + site['srcport'] + ' <-> ' + site['dstip'] + ':' + site['dstport'],
                    site['method'],
                    site['status_code'],
                    site['mime_type'],
                    site['user_agent'],
                    site['content_length'],
                    site['msg'],
                    elsa_server)
        if not (site['site'] == "-"):
            find_referers(site['site'] + site['uri'], site['timestamp'], 0, elsa_server)
        doc.stag('br')
        doc.stag('br')
    doc.asis("""
    <script type="text/javascript">
    var acc = document.getElementsByClassName("accordion");
    var i;

    for (i = 0; i < acc.length; i++) {
        acc[i].onclick = function(){
            this.classList.toggle("active");
            this.nextElementSibling.classList.toggle("show");
        }
    }
    </script>
    """)
    doc.asis('</body>')
    doc.asis('</html>')


def save_referer_report():
    sec = datetime.datetime.now()
    filename = str(sec.microsecond) + '-ref_view.html'
    with open(filename, 'w') as f:
        f.write(doc.getvalue())
        print('\nResults saved to file: ', filename, '\n')


def sift_logs(q_results):
    global data
    x = 1
    strings = ['srcip', 'srcport', 'dstip',
              'dstport', 'referer', 'mime_type',
              'method', 'status_code', 'site',
              'uri', 'user_agent', 'content_length']
    json_results = q_results.json()
    for result in json_results['results']:
        site = dict()
        site['index'] = x
        x += 1
        site['timestamp'] = result['timestamp']
        site['node'] = result['node']
        site['msg'] = result['msg']
        for fields in result['_fields']:
            found = False
            for key, value in fields.iteritems():
                if found and ('value' in key):
                    site[val] = value
                    found = False
                if any(string in value for string in strings):
                    val = value
                    found = True
        data += [site]


def read_conf():
    config = ConfigParser()
    config.read('./elsa_query.ini')
    user = config.get('MAIN', 'user')
    apikey = config.get('MAIN', 'apikey')
    ip = config.get('MAIN', 'ip')
    return user, apikey, ip


def print_results(output):
    output = json.loads(output)
    if output.get('results'):
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
    else:
        print('\nThe search did not return any records.')


def build_query(query, start, end, limit, http):
    query += ' start:' + '"' + start + '"' + \
             ' end:' + '"' + end + '"' + \
             ' limit:' + limit
    if http:
        if not ('class:BRO_HTTP' in query or 'class=BRO_HTTP' in query):
            query += ' class:BRO_HTTP '
        query += ' orderby:timestamp'
        print('\n\nQuery submitted to ELSA: ', query, '\n\n')
    return query


def handle_output(query, results, verbose, print_it):
    if verbose:
        print(json.dumps(results.json(), indent=2))
        print('HTTP Status Code: ', results.status_code)
    if print_it:
        print_results(results.text)
    return


if __name__ == "__main__":
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    yesterday = (datetime.datetime.utcnow() - datetime.timedelta(1)).strftime("%Y-%m-%d %H:%M:%S")
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
                        Default is 24 hours ago
        -u, --user    : Elsa user
                        Default is 'elsa'
        -v, --verbose : Print verbose results
        -w, --http    : Analyze BRO_HTTP logs
                        No need to include class:BRO_HTTP as it will be added by this script

        When running this on Windows you will need to escape quotes in the Elsa search string with a quote.
            \_> For example: "127.0.0.1 BRO_HTTP.uri=""/test/testing/"""
        Note that an Elsa API search will search the entire available time range by default.
            \_> Therefore use the start and end options to specify the query window.
            \_> If no start is specified, a start date of 24 hours ago is assumed.
            \_> If no end date is set, then an end date of now is assumed.
        ''')
    parser.add_option('-a', '--apikey',
                      dest='elsa_apikey', action='store', type='string')
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
                      dest='print_it', action='store_true')
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
    parser.add_option('-w', '--http',
                      dest='elsa_http', action='store_true')
    (options, args) = parser.parse_args()
    if not options.elsa_query:
        parser.error('No query was specified!')
    if not options.elsa_apikey:
        elsa_user, elsa_apikey, elsa_ip = read_conf()
    else:
        elsa_user = options.elsa_user
        elsa_ip = options.elsa_ip
        elsa_apikey = options.elsa_apikey
    elsa_query = build_query(options.elsa_query, options.elsa_start,
                             options.elsa_end, options.elsa_limit, options.elsa_http)
    query_results = query_elsa(elsa_user, elsa_apikey, elsa_ip, elsa_query)
    if options.elsa_http:
        sift_logs(query_results)
        build_referer_view(elsa_ip)
        save_referer_report()
    else:
        handle_output(elsa_query, query_results, options.verbose, options.print_it)
    query_results = None
