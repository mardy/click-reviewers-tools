#! /usr/bin/env python3

from setuptools import setup, find_packages
import glob
import os
import re

# look/set what version we have
changelog = 'debian/changelog'
if os.path.exists(changelog):
    head = open(changelog).readline()
    match = re.compile('.*\((.*)\).*').match(head)
    if match:
        version = match.group(1)

scripts = glob.glob('bin/click-*')
scripts.remove('bin/click-check-skeleton')
setup(name='click-reviewers-tools',
      version=version,
      scripts=scripts,
      packages=find_packages(),
      test_suite='clickreviews.tests'
)
