"""
This file defines all known frameworks and their current status.
Frameworks are currenly tracked in: http://goo.gl/z9ohJ3
"""

FRAMEWORKS = {
    'ubuntu-sdk-13.10': 'deprecated',
    'ubuntu-sdk-14.04-dev1': 'deprecated',
    'ubuntu-sdk-14.04-html-dev1': 'deprecated',
    'ubuntu-sdk-14.04-papi-dev1': 'deprecated',
    'ubuntu-sdk-14.04-qml-dev1': 'deprecated',
    'ubuntu-sdk-14.04': 'available',
    'ubuntu-sdk-14.04-html': 'available',
    'ubuntu-sdk-14.04-papi': 'available',
    'ubuntu-sdk-14.04-qml': 'available',
    'ubuntu-sdk-14.10-dev1': 'obsolete',
    'ubuntu-sdk-14.10-html-dev1': 'obsolete',
    'ubuntu-sdk-14.10-papi-dev1': 'obsolete',
    'ubuntu-sdk-14.10-qml-dev1': 'obsolete',
    'ubuntu-sdk-14.10-dev2': 'available',
    'ubuntu-sdk-14.10-html-dev2': 'available',
    'ubuntu-sdk-14.10-papi-dev2': 'available',
    'ubuntu-sdk-14.10-qml-dev2': 'available',
}


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

