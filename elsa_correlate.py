#!/usr/bin/env python
'''
    Author: Brian Kellogg

    Query ELSA to build daily report of possible suspicious correlated DST and SRC IPs

    Uses external shell script elsa_query.sh to perform the ELSA searches

    INI file section configuration
    ===========================================

'''

import os
from subprocess import call
import json
import time
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# number of searches an IP must be seen in in order to report on it
searches_seen_in = 3
# setup all of our date formats we need
now = time.strftime("%Y-%m-%d %H:%M:00")
temp = datetime.date.today()-datetime.timedelta(1)
yesterday = temp.strftime("%Y-%m-%d %H:%M:00")
file_append = time.strftime("%m%d%Y")
elsa_uri = 'https://10.1.2.3:3154/?query_string='
search_elsa = '/home/user/scripts/elsa_query.sh'
temp_json_results = '/home/user/scripts/correlation/temp.json'
search_results_fname = '/home/user/scripts/correlation/' + file_append + '.txt'
correlated_fname = '/home/user/scripts/correlation/' + file_append + '-correlated.txt'
# IPs we do not want to correlate due to services they run that create high false positive rates
ignore_ips = []


# lets perform the ELSA query
def do_search(search_str, search_name, group_by):
    call([search_elsa, search_str, temp_json_results])
    with open(temp_json_results) as json_file:
        results = json.load(json_file)
    with open(search_results_fname, 'a+') as f:
        # if any search returns no results then lets not try and write it
        if group_by in results['results']:
            for result in results['results'][group_by]:
                f.write("%s\t%s\t%s\t%d\n" %  (search_name, group_by, result['_groupby'], result['_count']))


smtp_from = 'suspicious-ips@dresser-rand.com'
# seperate multiple TO addresses with a space
smtp_to = "analyst@company.com"
# Create message container - the correct MIME type is multipart/alternative.
msg = MIMEMultipart('alternative')
msg['Subject'] = "Suspicious IPs"
msg['From'] = smtp_from
msg['To'] = smtp_to
# Create the body of the message (a plain-text and an HTML version).
text = ""
html = """\
<html>
  <head>
  <style>
  body {
    font-size: 12px;
  }
  a, u {
    text-decoration: none;
    color: blue;
    font-weight: bold;
  }
  table {
    border-collapse: collapse;
  }
  td, th {
    border: 1px solid #999;
    padding: 5px;
    text-align: center;
  }
  </style>
  </head>
  <body>
  <p><b>Today's top suspicious IPs</b></p>
  <table bgcolor="#F5F5F0">
"""


do_search('class=BRO_SSH "-" -BRO_SSH.dstport=22 groupby:srcip start:yesterday end:now', 'SSH over non-standard port', 'srcip')
do_search('class=BRO_SSH "-" -BRO_SSH.dstport=22 groupby:dstip start:yesterday end:now', 'SSH over non-standard port', 'dstip')
do_search('class=BRO_CONN +BRO_CONN.dstport=53 -BRO_CONN.service=dns groupby:srcip start:yesterday end:now', 'Port 53 not DNS', 'srcip')
do_search('class=BRO_CONN +BRO_CONN.dstport=53 -BRO_CONN.service=dns groupby:dstip start:yesterday end:now', 'Port 53 not DNS', 'dstip')
do_search('class=BRO_CONN +BRO_CONN.dstport=80 -BRO_CONN.service=http groupby:srcip start:yesterday end:now', 'Port 80 not HTTP', 'srcip')
do_search('class=BRO_CONN +BRO_CONN.dstport=80 -BRO_CONN.service=http groupby:dstip start:yesterday end:now', 'Port 80 not HTTP', 'dstip')
do_search('class=BRO_CONN +BRO_CONN.dstport=443 -BRO_CONN.service=ssl groupby:srcip start:yesterday end:now', 'Port 443 not HTTPS', 'srcip')
do_search('class=BRO_CONN +BRO_CONN.dstport=443 -BRO_CONN.service=ssl groupby:dstip start:yesterday end:now', 'Port 443 not HTTPS', 'dstip')
do_search('class=BRO_INTEL "intel" groupby:srcip start:yesterday end:now', 'Intel hits', 'srcip')
do_search('class=BRO_INTEL "intel" groupby:dstip start:yesterday end:now', 'Intel hits', 'dstip')
do_search('class=BRO_TUNNEL "Tunnel" groupby:srcip start:yesterday end:now', 'IP Tunnels', 'srcip')
do_search('class=BRO_TUNNEL "Tunnel" groupby:dstip start:yesterday end:now', 'IP Tunnels', 'dstip')
do_search('class=BRO_RADIUS "-" groupby:remote_ip -"127.0.0.1" start:yesterday end:now', 'RADIUS remote IP', 'remote_ip')
do_search('class=BRO_NOTICE "-" notice_type="CrlALERTs::Correlated_Alerts" groupby:srcip start:yesterday end:now', 'Correlated alerts', 'srcip')
do_search('class=SNORT "-" groupby:srcip start:yesterday end:now', 'IDS Alerts', 'srcip')
do_search('class=SNORT "-" groupby:dstip start:yesterday end:now', 'IDS Alerts', 'dstip')
do_search('class=BRO_IRC "-" groupby:srcip start:yesterday end:now', 'IRC', 'srcip')
do_search('class=BRO_IRC "-" groupby:dstip start:yesterday end:now', 'IRC', 'dstip')
do_search('class=BRO_NOTICE "-" notice_type="ExploitKit::SuspiciousDownloads" groupby:srcip start:yesterday end:now', 'Exploit Kit', 'srcip')
do_search('class=BRO_NOTICE "-" notice_type="ExploitKit::SuspiciousDownloads" groupby:dstip start:yesterday end:now', 'Exploit Kit', 'dstip')
do_search('class=BRO_NOTICE "-" (notice_type="DRC::Large_Outgoing_Tx" OR notice_type="DRC::Very_Large_Outgoing_Tx") groupby:srcip start:yesterday end:now', 'Large Upload', 'srcip')
do_search('class=BRO_NOTICE "-" (notice_type="DRC::Large_Outgoing_Tx" OR notice_type="DRC::Very_Large_Outgoing_Tx") groupby:dstip start:yesterday end:now', 'Large Upload', 'dstip')


# track IPs we are correlating so we do not correlate them more than once
IPs = []
# store correations so we can later determine if we want to report on them
crls = []
with open(search_results_fname, 'r') as f:
    lines = f.readlines()
with open(search_results_fname, 'r') as f:
    lines_copy = f.readlines()
with open(correlated_fname, 'w') as correlated:
    for line in lines:
        IP = line.split('\t')
        if IP[2] in IPs:
            continue
        IPs.append(IP[2])
        hits = 0
        # lets compare the file with itself to find correlations
        for line_copy in lines_copy:
            temp = '\t' + IP[2] + '\t'
            if temp in line_copy:
                crls.append(line_copy)
                hits += 1
        # did we exceed the number of correlations to write to the correlations file?
        if hits >= searches_seen_in:
            for crl in crls:
                correlated.write(crl)
        # clear correlation list
        del crls[:]

# create email table rows
with open(correlated_fname, 'r') as f:
    lines = f.readlines()
# keep track of the current IP we are working on so that we can build our email heirarchy
temp = ''
for line in lines:
    IP = line.split('\t')
    if IP[2] not in ignore_ips:
        # lets build our ELSA email search links depending on search the IP was found in
        if IP[2] != temp:
            html += '<tr><td bgcolor="#B8B8B8" colspan="3"><a href="' + elsa_uri + 'groupby=program ' + IP[2] + '">' + IP[2] + '</a></td></tr>'
        if IP[0] == 'SSH over non-standard port' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_SSH %22-%22 -BRO_SSH.dstport=22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'SSH over non-standard port' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_SSH %22-%22 -BRO_SSH.dstport=22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Port 53 not DNS' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_CONN +BRO_CONN.dstport=53 -BRO_CONN.service=dns ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Port 53 not DNS' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_CONN +BRO_CONN.dstport=53 -BRO_CONN.service=dns ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Port 80 not HTTP' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_CONN +BRO_CONN.dstport=80 -BRO_CONN.service=http ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Port 80 not HTTP' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_CONN +BRO_CONN.dstport=80 -BRO_CONN.service=http ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Port 443 not HTTPS' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_CONN +BRO_CONN.dstport=443 -BRO_CONN.service=ssl ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Port 443 not HTTPS' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_CONN +BRO_CONN.dstport=443 -BRO_CONN.service=ssl ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Intel hits' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_INTEL %22intel%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Intel hits' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_INTEL %22intel%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'IP Tunnels' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_TUNNEL %22Tunnel%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'IP Tunnels' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_TUNNEL %22Tunnel%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'RADIUS remote IP' and IP[1] == 'remote_ip':
            html += '<tr><td><a href="' + elsa_uri + 'class=BRO_RADIUS %22-%22 groupby:remote_ip -%22127.0.0.1%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Correlated alerts' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=sub_msg class=BRO_NOTICE %22-%22 notice_type=%22CrlALERTs::Correlated_Alerts%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'IDS Alerts' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=sig_msg class=SNORT %22-%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'IDS Alerts' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=sig_msg class=SNORT %22-%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'IRC' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_IRC %22-%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'IRC' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_IRC %22-%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Exploit Kit' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_NOTICE %22-%22 notice_type=%22ExploitKit::SuspiciousDownloads%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Exploit Kit' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_NOTICE %22-%22 notice_type=%22ExploitKit::SuspiciousDownloads%22 ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Large Upload' and IP[1] == 'srcip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=dstip class=BRO_NOTICE %22-%22 (notice_type=%22DRC::Large_Outgoing_Tx%22 OR notice_type=%22DRC::Very_Large_Outgoing_Tx%22) ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        elif IP[0] == 'Large Upload' and IP[1] == 'dstip':
            html += '<tr><td><a href="' + elsa_uri + 'groupby=srcip class=BRO_NOTICE %22-%22 (notice_type=%22DRC::Large_Outgoing_Tx%22 OR notice_type=%22DRC::Very_Large_Outgoing_Tx%22) ' + IP[2] + '">' + IP[0] + '</a></td><td>' + IP[1] + '</td><td>' + IP[3] + '</td></tr>'
        else:
            html += '<tr><td>' + IP[0] + '</td><td>' + IP[1] + '</td><td>' + IP[3] + '</td>'
    temp = IP[2]


html += """\
  </table>
  </body>
</html>
"""
# Record the MIME types of both parts - text/plain and text/html.
#part1 = MIMEText(text, 'plain')
part2 = MIMEText(html, 'html')
# Attach parts into message container.
# According to RFC 2046, the last part of a multipart message, in this case
# the HTML message, is best and preferred.
#msg.attach(part1)
msg.attach(part2)
# Send the message via local SMTP server.
s = smtplib.SMTP('smtp.company.com')
s.ehlo()
# sendmail function takes 3 arguments: sender's address, recipient's address
# and message to send - here it is sent as one string.
s.sendmail(smtp_from, smtp_to.split(), msg.as_string())
s.quit()
