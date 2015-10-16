'''utils.py: test utils for click reviewer tools'''
#
# Copyright (C) 2013-2015 Canonical Ltd.
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

import glob
import json
import os
import shutil
import subprocess
import tempfile


def make_package(name='test', package_format='click', package_types=None,
                 version='1.0', title="An application",
                 framework='ubuntu-sdk-15.04', extra_files=None, output_dir=None):
    """Return the path to a click/snap package with the given data.

    Caller is responsible for deleting the output_dir afterwards.
    """
    is_snap = (package_format == "snap")
    build_dir = tempfile.mkdtemp()
    package_types = package_types or []

    try:
        make_dir_structure(build_dir, extra_files=extra_files)
        write_icon(build_dir)
        write_manifest(build_dir, name, version,
                       title, framework, package_types,
                       is_snap)
        if is_snap:
            write_meta_data(build_dir, name, version,
                            title, framework)
        write_control(build_dir, name, version, title)
        write_preinst(build_dir)
        write_apparmor_profile(build_dir, name)
        write_other_files(build_dir)
        pkg_path = build_package(build_dir, name, version, package_format,
                                 output_dir=output_dir)
    finally:
        shutil.rmtree(build_dir)

    return pkg_path


def make_dir_structure(path, extra_files=None):
    extra_files = extra_files or []
    directories = ['DEBIAN', 'meta']
    directories.extend(
        [os.path.dirname(extra_file) for extra_file in extra_files])

    for directory in directories:
        directory = os.path.join(path, directory)
        if not os.path.exists(directory):
            os.makedirs(directory)

    for extra_file in extra_files:
        dirname, basename = os.path.split(extra_file)
        if basename != '':
            with open(os.path.join(path, extra_file), 'wb'):
                pass


def write_icon(path):
    icons = glob.glob('/usr/share/icons/hicolor/256x256/apps/*.png')
    if len(icons) > 0:
        source_path = icons[0]
    else:
        source_path = 'src/softwarecenteragent/tests/test_data/eg_256x256.png'
    target_path = os.path.join(path, 'meta', 'icon.png')
    shutil.copyfile(source_path, target_path)


def write_manifest(path, name, version, title, framework, types, is_snap):
    manifest_path = os.path.join(path, 'DEBIAN', 'manifest')
    manifest_content = {
        'framework': framework,
        'maintainer': 'Someone <someone@example.com>',
        'name': name,
        'title': title,
        'version': version,
        'icon': 'meta/icon.png',
        'hooks': {
            'app': {
                'apparmor': 'meta/{}.apparmor'.format(name),
                },
            },
        'description': 'This is a test app.',
        }
    if types:
        if is_snap:
            manifest_content.update({'type': types[0]})
        else:
            if "scope" in types:
                manifest_content['hooks']['app'].update({'scope': ""})
            if "application" in types:
                manifest_content['hooks']['app'].update({'desktop': ""})

    with open(manifest_path, 'w') as f:
        json.dump(manifest_content, f)


def write_meta_data(path, name, version, title, framework):
    yaml_path = os.path.join(path, 'meta', 'package.yaml')
    content = """architectures:
icon: meta/icon.png
name: {}
version: "{}",
framework: {},
vendor: 'Someone <someone@example.com>',
""".format(name, version, framework)

    with open(yaml_path, 'w') as f:
        f.write(content)
    with open(os.path.join(path, 'meta', 'readme.md'), 'w') as f:
        f.write(title)


def write_control(path, name, version, title):
    control_path = os.path.join(path, 'DEBIAN', 'control')
    control_content = {
        'Package': name,
        'Version': version,
        'Click-Version': '0.4',
        'Architecture': 'all',
        'Maintainer': 'Someone <someone@example.com>',
        'Installed-Size': '123',
        'Description': title,
        }
    with open(control_path, 'w') as f:
        for key, value in control_content.items():
            f.write(key + ": " + value + "\n")


def write_preinst(path):
    preinst_path = os.path.join(path, 'DEBIAN', 'preinst')
    with open(preinst_path, 'w') as f:
        f.write("""#! /bin/sh
echo "Click packages may not be installed directly using dpkg."
echo "Use 'click install' instead."
exit 1
""")
    os.chmod(preinst_path, 0o775)


def write_apparmor_profile(path, name):
    profile_path = os.path.join(path, 'meta', '{}.apparmor'.format(name))
    profile = {
        'policy_version': 1.3,
        'policy_groups': [],
    }
    with open(profile_path, 'w') as f:
        json.dump(profile, f)


def write_other_files(path):
    def write_empty_file(path, perms=0o664):
        with open(path, 'wb'):
            pass
        os.chmod(path, perms)
    write_empty_file(os.path.join(path, 'DEBIAN', 'md5sums'))


def build_package(path, name, version, format, output_dir=None):
    filename = "{}_{}_all.{}".format(name, version, format)
    output_dir = output_dir or tempfile.mkdtemp()
    output_path = os.path.join(output_dir, filename)
    subprocess.check_call(['dpkg-deb', '-b', path, output_path])
    return output_path
