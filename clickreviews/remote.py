"""
This file defines all known frameworks and their current status.
Frameworks are currenly tracked in: http://goo.gl/z9ohJ3
"""

import json
import os
import re
from socket import timeout
import sys
import time
from urllib import request, parse
from urllib.error import HTTPError, URLError

DATA_DIR = os.path.join(os.path.expanduser('~/.cache/click-reviewers-tools/'))
UPDATE_INTERVAL = 60 * 60 * 24 * 7


def _update_is_necessary(fn):
    return (not os.path.exists(fn)) or \
        (time.time() - os.path.getctime(fn) >= UPDATE_INTERVAL)


def _update_is_possible(url):
    update = True
    try:
        request.urlopen(url)
    except (HTTPError, URLError):
        update = False
    except timeout:
        update = False
    return update


def abort(msg=None):
    if msg:
        print(msg, file=sys.stderr)
    print('Aborted.', file=sys.stderr)
    sys.exit(1)


#
# Public
#
def get_remote_file(fn, url, data_dir=DATA_DIR):
    try:
        f = request.urlopen(url)
    except (HTTPError, URLError) as error:
        abort('Data not retrieved because %s.' % error)
    except timeout:
        abort('Socket timed out.')
    html = f.read()
    # XXX: This is a hack and will be gone, as soon as myapps has an API for this.
    link = re.findall(b'<a href="(\S+?)">download file</a>', html)
    if not link:
        abort()
    download_link = '{}://{}/{}'.format(
        parse.urlparse(url).scheme,
        parse.urlparse(url).netloc,
        link[0].decode("utf-8"))
    f = request.urlopen(download_link)
    if not f:
        abort()
    if os.path.exists(fn):
        os.remove(fn)
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    with open(fn, 'bw') as local_file:
        local_file.write(f.read())


def read_cr_file(fn, url, local_copy_fn=None):
    '''read click reviews file from remote or local copy:
       - fn: where to store the cached file
       - url: url to fetch
       - local_copy_fn: force use of local copy
    '''
    j = {}
    if local_copy_fn and os.path.exists(local_copy_fn):
        j = json.loads(open(local_copy_fn, 'r').read())
    else:
        if _update_is_necessary(fn) and _update_is_possible(url):
            get_remote_file(fn, url)
        if os.path.exists(fn):
            j = json.loads(open(fn, 'r').read())
    return j
