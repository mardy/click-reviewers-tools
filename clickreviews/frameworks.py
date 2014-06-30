"""
This file defines all known frameworks and their current status.
Frameworks are currenly tracked in: http://goo.gl/z9ohJ3
"""

import json
import os

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 
                                        '../data/'))
FRAMEWORKS_FILE = os.path.join(DATA_DIR, 'frameworks.json')
FRAMEWORKS = json.loads(open(FRAMEWORKS_FILE, 'r').read())

DEPRECATED_FRAMEWORKS = []
OBSOLETE_FRAMEWORKS = []
AVAILABLE_FRAMEWORKS = []

from urllib import request, parse
import sys
import re
import os

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                        "../data"))
FRAMEWORKS_FILE_VIEW_URL = \
        "http://bazaar.launchpad.net/~dholbach/+junk/frameworks/view/head:/frameworks.json"
LOCAL_DATA_FILE = os.path.join(DATA_DIR, 'frameworks.json')

def abort():
    print('Aborted.', file=sys.stderr)
    sys.exit(1)

def get_frameworks_file():
    f = request.urlopen(FRAMEWORKS_FILE_VIEW_URL)
    if not f:
        abort()
    html = f.read()
    link = re.findall(b'<a href="(\S+?)">download file</a>', html)
    if not link:
        abort()
    download_link = '{}://{}/{}'.format(\
            parse.urlparse(FRAMEWORKS_FILE_VIEW_URL).scheme,
            parse.urlparse(FRAMEWORKS_FILE_VIEW_URL).netloc,
            link[0].decode("utf-8"))
    f = request.urlopen(download_link)
    if not f:
        abort()
    if os.path.exists(LOCAL_DATA_FILE):
        os.remove(LOCAL_DATA_FILE)
    with open(LOCAL_DATA_FILE, 'bw') as local_file:
        local_file.write(f.read())


for k, v in FRAMEWORKS.items():
    if v == 'deprecated':
        DEPRECATED_FRAMEWORKS.append(k)
    elif v == 'obsolete':
        OBSOLETE_FRAMEWORKS.append(k)
    elif v == 'available':
        AVAILABLE_FRAMEWORKS.append(k)

