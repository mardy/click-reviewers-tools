'''common.py: common classes and functions'''
#
# Copyright (C) 2013 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function
import os
import subprocess
import sys

DEBUGGING = False

#
# Utility classes
#
class ClickReviewException(Exception):
    '''This class represents ClickReview exceptions'''
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ClickReview(object):
    '''This class represents click reviews'''
    def __init__(self, fn, review_type):
        if not os.path.exists(fn):
            error("Could not find '%s'" % fn)
        self.click_package = fn

        self.click_pkgname = ""
        self.click_version = ""

        self.review_type = review_type
        self.click_report = dict()

        self.result_types = ['info', 'warn', 'error']
        for r in self.result_types:
            self.click_report[r] = dict()

        self.click_report_output = "console"

    def set_review_type(self, name):
        '''Set review name'''
        self.review_type = name

    #
    # click_report[<result_type>][<review_name>] = <review>
    #   result_type: info, warn, error
    #   review_name: name of the check (prefixed with self.review_type)
    #   review: contents of the review
    def _add_result(self, result_type, review_name, result):
        '''Add result to report'''
        if result_type not in self.result_types:
            error("Invalid result type '%s'" % result_type)

        name = "%s_%s" % (self.review_type, review_name)
        if name not in self.click_report[result_type]:
            self.click_report[result_type][name] = dict()

        self.click_report[result_type][name] = result

    def print_report(self):
        '''Print report'''
        if self.click_report_output == "console":
            # TODO: format better
            import pprint
            pprint.pprint(self.click_report)
        elif self.click_report_output == "json":
            import json
            msg(json.dumps(self.click_report))

    def do_checks(self):
        '''Perform checks'''
        error("Must override do_checks()")

#
# Utility functions
#
def error(out, exit_code=1, do_exit=True):
    '''Print error message and exit'''
    try:
        print("ERROR: %s" % (out), file=sys.stderr)
    except IOError:
        pass

    if do_exit:
        sys.exit(exit_code)

def warn(out):
    '''Print warning message'''
    try:
        print("WARN: %s" % (out), file=sys.stderr)
    except IOError:
        pass

def msg(out, output=sys.stdout):
    '''Print message'''
    try:
        print("%s" % (out), file=output)
    except IOError:
        pass

def debug(out):
    '''Print debug message'''
    global DEBUGGING
    if DEBUGGING:
        try:
            print("DEBUG: %s" % (out), file=sys.stderr)
        except IOError:
            pass

def cmd(command):
    '''Try to execute the given command.'''
    debug(command)
    try:
        sp = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    except OSError as ex:
        return [127, str(ex)]

    if sys.version_info[0] >= 3:
        out = sp.communicate()[0].decode('ascii', 'ignore')
    else:
        out = sp.communicate()[0]

    return [sp.returncode, out]


def cmd_pipe(command1, command2):
    '''Try to pipe command1 into command2.'''
    try:
        sp1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
        sp2 = subprocess.Popen(command2, stdin=sp1.stdout)
    except OSError as ex:
        return [127, str(ex)]

    if sys.version_info[0] >= 3:
        out = sp2.communicate()[0].decode('ascii', 'ignore')
    else:
        out = sp2.communicate()[0]

    return [sp2.returncode, out]


