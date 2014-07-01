"""
This file defines all known frameworks and their current status.
Frameworks are currenly tracked in: http://goo.gl/z9ohJ3
"""

from urllib.error import HTTPError, URLError
from urllib import request, parse
from socket import timeout
import json
import time
import sys
import re
import os

DATA_DIR = os.path.join(os.path.expanduser('~/.cache/ubuntu-frameworks/'))
FRAMEWORKS_FILE = os.path.join(DATA_DIR, 'frameworks.json')

FRAMEWORKS_FILE_VIEW_URL = \
        "http://bazaar.launchpad.net/~dholbach/+junk/frameworks/view/head:/frameworks.json"
LOCAL_DATA_FILE = os.path.join(DATA_DIR, 'frameworks.json')

UPDATE_INTERVAL = 60*60*24*7

def update_is_necessary():
    return (not os.path.exists(FRAMEWORKS_FILE)) or \
            (time.time()-os.path.getctime(FRAMEWORKS_FILE) >= UPDATE_INTERVAL)

def update_is_possible():
    update = True
    try:
        f = request.urlopen(FRAMEWORKS_FILE_VIEW_URL)
    except (HTTPError, URLError) as error:
        update = False
    except timeout:
        update = False
    return update

def abort(msg=None):
    if msg:
        print(msg, file=sys.stderr)
    print('Aborted.', file=sys.stderr)
    sys.exit(1)

def get_frameworks_file(data_dir=DATA_DIR):
    try:
        f = request.urlopen(FRAMEWORKS_FILE_VIEW_URL)
    except (HTTPError, URLError) as error:
        abort('Data not retrieved because %s.' % error)
    except timeout:
        abort('Socket timed out.')
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

def read_frameworks_file(local_copy=None):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if update_is_necessary():
        if update_is_possible():
            get_frameworks_file()
    if not os.path.exists(FRAMEWORKS_FILE):
        if local_copy:
            return json.loads(open(local_copy, 'r').read())
        return {}
    return json.loads(open(FRAMEWORKS_FILE, 'r').read())

FRAMEWORKS = read_frameworks_file()
DEPRECATED_FRAMEWORKS = []
OBSOLETE_FRAMEWORKS = []
AVAILABLE_FRAMEWORKS = []

for k, v in FRAMEWORKS.items():
    if v == 'deprecated':
        DEPRECATED_FRAMEWORKS.append(k)
    elif v == 'obsolete':
        OBSOLETE_FRAMEWORKS.append(k)
    elif v == 'available':
        AVAILABLE_FRAMEWORKS.append(k)

