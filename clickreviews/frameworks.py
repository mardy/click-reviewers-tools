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

for k, v in FRAMEWORKS.items():
    if v == 'deprecated':
        DEPRECATED_FRAMEWORKS.append(k)
    elif v == 'obsolete':
        OBSOLETE_FRAMEWORKS.append(k)
    elif v == 'available':
        AVAILABLE_FRAMEWORKS.append(k)

