#
#  Copyright (C) 2014 Canonical Ltd.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 3 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

FRAMEWORKS = {
    "ubuntu-sdk-13.10": "deprecated",
    "ubuntu-sdk-14.04": "deprecated",
    "ubuntu-sdk-14.04-dev1": "obsolete",
    "ubuntu-sdk-14.04-html-dev1": "obsolete",
    "ubuntu-sdk-14.04-html": "deprecated",
    "ubuntu-sdk-14.04-papi-dev1": "obsolete",
    "ubuntu-sdk-14.04-papi": "deprecated",
    "ubuntu-sdk-14.04-qml-dev1": "obsolete",
    "ubuntu-sdk-14.04-qml": "deprecated",
    "ubuntu-sdk-14.10": "deprecated",
    "ubuntu-sdk-14.10-dev1": "obsolete",
    "ubuntu-sdk-14.10-dev2": "obsolete",
    "ubuntu-sdk-14.10-dev3": "deprecated",
    "ubuntu-sdk-14.10-html-dev1": "obsolete",
    "ubuntu-sdk-14.10-html-dev2": "obsolete",
    "ubuntu-sdk-14.10-html-dev3": "deprecated",
    "ubuntu-sdk-14.10-html": "deprecated",
    "ubuntu-sdk-14.10-papi-dev1": "obsolete",
    "ubuntu-sdk-14.10-papi-dev2": "obsolete",
    "ubuntu-sdk-14.10-papi-dev3": "deprecated",
    "ubuntu-sdk-14.10-papi": "deprecated",
    "ubuntu-sdk-14.10-qml-dev1": "obsolete",
    "ubuntu-sdk-14.10-qml-dev2": "obsolete",
    "ubuntu-sdk-14.10-qml-dev3": "deprecated",
    "ubuntu-sdk-14.10-qml": "deprecated",
    "ubuntu-sdk-15.04": "available",
    "ubuntu-sdk-15.04-html": "available",
    "ubuntu-sdk-15.04-papi": "available",
    "ubuntu-sdk-15.04-qml": "available",
    "ubuntu-sdk-15.04.1-html": "available",
    "ubuntu-sdk-15.04.1-papi": "available",
    "ubuntu-sdk-15.04.1-qml": "available",
    "ubuntu-sdk-15.04.1": "available",
    "ubuntu-sdk-15.04.2-html": "available",
    "ubuntu-sdk-15.04.2-papi": "available",
    "ubuntu-sdk-15.04.2-qml": "available",
    "ubuntu-sdk-15.04.2": "available",
    "ubuntu-sdk-15.04.3-html": "available",
    "ubuntu-sdk-15.04.3-papi": "available",
    "ubuntu-sdk-15.04.3-qml": "available",
    "ubuntu-sdk-15.04.3": "available",
    "ubuntu-sdk-15.04.4-html": "available",
    "ubuntu-sdk-15.04.4-papi": "available",
    "ubuntu-sdk-15.04.4-qml": "available",
    "ubuntu-sdk-15.04.4": "available",
    "ubuntu-sdk-15.04.5-html": "available",
    "ubuntu-sdk-15.04.5-papi": "available",
    "ubuntu-sdk-15.04.5-qml": "available",
    "ubuntu-sdk-15.04.5": "available",
    "ubuntu-sdk-15.04.6-html": "available",
    "ubuntu-sdk-15.04.6-papi": "available",
    "ubuntu-sdk-15.04.6-qml": "available",
    "ubuntu-sdk-15.04.6": "available",
    "ubuntu-sdk-15.04.7-html": "available",
    "ubuntu-sdk-15.04.7-papi": "available",
    "ubuntu-sdk-15.04.7-qml": "available",
    "ubuntu-sdk-15.04.7": "available",
}


class Frameworks(object):
    DEPRECATED_FRAMEWORKS = []
    OBSOLETE_FRAMEWORKS = []
    AVAILABLE_FRAMEWORKS = []

    def __init__(self, overrides=None):
        self.FRAMEWORKS = FRAMEWORKS
        if overrides is not None:
            self.FRAMEWORKS.update(overrides)

        for name, data in self.FRAMEWORKS.items():
            if type(data) is dict:
                state = data.get('state')
            else:
                state = data

            if state == 'deprecated':
                self.DEPRECATED_FRAMEWORKS.append(name)
            elif state == 'obsolete':
                self.OBSOLETE_FRAMEWORKS.append(name)
            elif state == 'available':
                self.AVAILABLE_FRAMEWORKS.append(name)
