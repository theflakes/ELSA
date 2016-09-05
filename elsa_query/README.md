**EXAMPLE:**
elsa_query.py -q "1.1.1.1" -w -l 1000
- query ELSA for all BRO_HTTP logs with 1.1.1.1 as the src or dst, return 1000 logs.  Then analyze the BRO_HTTP logs and build a html report.


**Required for SecurityOnion analysis VM:**
- sudo apt-get install python-pip
- sudo pip install yattag
- sudo pip install configparser

**Usage:**
        elsa_query.py --query "127.0.0.1 dstport:80 groupby:dstip" --print -l 1000

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
        -w, --http    : Analyze BRO_HTTP logs
                        No need to include class:BRO_HTTP as it will be added by this script

        When running this on Windows you will need to escape quotes in the Elsa search string with a quote.
            \_> For example: "127.0.0.1 BRO_HTTP.uri=""/test/testing/"""
        Note that an Elsa API search will search the entire available time range by default.
            \_> Therefore use the start and end options to specify the query window.
            \_> If no start is specified, a start date of yesterday at midnight is assumed.
            \_> If no end date is set, then an end date of now is assumed.


**Print the search results to standard out and data stack:**

./elsa_query.py -p -q "class=BRO_HTTP" -l 9999 | cut -d'|' -f3,5,8,9,12,15,27 | sort | uniq -c | sort -r -t'|' -k1 | column -s'|' -t

   1 192.168.1.101   208.78.69.70     -     -                              -                                                             200
   1 192.168.1.101   66.114.124.141   -     -                              -                                                             200
   1 192.168.1.101   75.126.138.202   -     -                              -                                                             400
   1 192.168.10.125  217.146.179.200  GET   bc.us.yahoo.com                Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   1 192.168.10.125  65.61.151.116    GET   www.genevalab.com              Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       304
   1 192.168.10.125  68.142.205.142   GET   redirect1.vip.store.yahoo.com  Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   1 192.168.10.125  74.125.19.96     GET   www.googleadservices.com       Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       302
   1 192.168.10.125  80.157.169.195   GET   us.js2.yimg.com                Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   1 192.168.10.128  74.125.19.113    GET   clients1.google.com            Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       -
   1 192.168.10.128  74.125.19.113    GET   clients1.google.com            Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       204
   1 192.168.10.128  74.125.45.100    GET   google.com                     Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       301
   1 192.168.3.35    188.124.5.107    GET   kloretukap.net                 Mozilla/4.0 (compatible; MSIE 6.0; Win32)                     200
   1 192.168.3.35    66.96.224.213    GET   66.96.224.213                  -                                                             200
   1 192.168.3.35    96.0.203.90      POST  go-thailand-now.com            Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)            200
   1 192.168.3.65    188.72.243.72    GET   www.hostme.name                Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   2 192.168.10.125  82.199.80.141    GET   bs.serving-sys.com             Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   2 192.168.10.128  74.125.19.103    GET   www.google.com                 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       204
   2 192.168.3.25    89.187.51.0      GET   pipiskin.hk                    Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   2 192.168.3.35    188.124.5.100    POST  homesitetoo.com                Mozilla/4.0 (compatible; MSIE 6.0; Win32)                     200
   2 192.168.3.65    188.72.243.72    GET   ishi-bati.com                  Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   3 192.168.3.25    89.187.51.0      POST  pipiskin.hk                    Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   3 192.168.3.35    96.0.203.122     POST  go-thailand-now.com            Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)            200
   4 192.168.1.10    8.18.65.32       GET   ax.search.itunes.apple.com     AppleTV/2.4                                                   200
   4 192.168.3.65    188.72.243.72    POST  ishi-bati.com                  Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   5 192.168.1.10    8.18.65.67       GET   ax.itunes.apple.com            AppleTV/2.4                                                   200
   5 192.168.10.125  65.61.151.116    GET   www.genevalab.com              Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       -
   5 192.168.10.128  208.80.152.2     GET   en.wikipedia.org               Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   5 192.168.3.35    195.2.253.92     GET   acxerox.com                    Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)ver49  200
   7 192.168.1.10    8.18.65.27       GET   ax.search.itunes.apple.com     AppleTV/2.4                                                   200
   8 192.168.10.128  74.125.19.103    GET   www.google.com                 Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
   9 192.168.1.10    8.18.65.89       GET   ax.search.itunes.apple.com     AppleTV/2.4                                                   200
   9 192.168.10.128  74.125.19.113    GET   clients1.google.com            Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200
  10 192.168.1.10    8.18.65.58       GET   a1.phobos.apple.com            AppleTV/2.4                                                   200
  10 192.168.1.10    8.18.65.88       GET   ax.search.itunes.apple.com     AppleTV/2.4                                                   200
  16 192.168.1.10    8.18.65.10       GET   a1.phobos.apple.com            AppleTV/2.4                                                   200
  22 192.168.1.10    8.18.65.82       GET   a1.phobos.apple.com            AppleTV/2.4                                                   200
  33 192.168.1.10    66.235.132.121   GET   metrics.apple.com              AppleTV/2.4                                                   200
  36 192.168.10.125  65.61.151.116    GET   www.genevalab.com              Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       403
  43 192.168.10.125  65.61.151.116    GET   www.genevalab.com              Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)       200

