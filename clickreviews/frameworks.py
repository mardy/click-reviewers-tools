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
USER_DATA_FILE = os.path.join(DATA_DIR, 'frameworks.json')

# This is a hack and will be gone, as soon as myapps has an API for this.
FRAMEWORKS_DATA_URL = \
        "http://bazaar.launchpad.net/~ubuntu-core-dev/+junk/frameworks/view/head:/frameworks.json"

UPDATE_INTERVAL = 60*60*24*7

def update_is_necessary():
    return (not os.path.exists(USER_DATA_FILE)) or \
            (time.time()-os.path.getctime(USER_DATA_FILE) >= UPDATE_INTERVAL)

def update_is_possible():
    update = True
    try:
        f = request.urlopen(FRAMEWORKS_DATA_URL)
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
        f = request.urlopen(FRAMEWORKS_DATA_URL)
    except (HTTPError, URLError) as error:
        abort('Data not retrieved because %s.' % error)
    except timeout:
        abort('Socket timed out.')
    html = f.read()
    # This is a hack and will be gone, as soon as myapps has an API for this.
    link = re.findall(b'<a href="(\S+?)">download file</a>', html)
    if not link:
        abort()
    download_link = '{}://{}/{}'.format(\
            parse.urlparse(FRAMEWORKS_DATA_URL).scheme,
            parse.urlparse(FRAMEWORKS_DATA_URL).netloc,
            link[0].decode("utf-8"))
    f = request.urlopen(download_link)
    if not f:
        abort()
    if os.path.exists(USER_DATA_FILE):
        os.remove(USER_DATA_FILE)
    with open(USER_DATA_FILE, 'bw') as local_file:
        local_file.write(f.read())

def read_frameworks_file(local_copy=None):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if update_is_necessary() and update_is_possible():
        get_frameworks_file()
    if not os.path.exists(USER_DATA_FILE):
        if local_copy:
            return json.loads(open(local_copy, 'r').read())
        return {}
    return json.loads(open(USER_DATA_FILE, 'r').read())

class Frameworks(object):
    DEPRECATED_FRAMEWORKS = []
    OBSOLETE_FRAMEWORKS = []
    AVAILABLE_FRAMEWORKS = []

    def __init__(self, local_copy=None):
        self.FRAMEWORKS = read_frameworks_file(local_copy)

        for k, v in self.FRAMEWORKS.items():
            if v == 'deprecated':
                self.DEPRECATED_FRAMEWORKS.append(k)
            elif v == 'obsolete':
                self.OBSOLETE_FRAMEWORKS.append(k)
            elif v == 'available':
                self.AVAILABLE_FRAMEWORKS.append(k)
