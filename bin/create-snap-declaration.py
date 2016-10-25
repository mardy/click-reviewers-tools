#!/usr/bin/python3

import argparse
import json
import os
import sys

import clickreviews.snapd_base_declaration as snapd_base_declaration

decl = {}

# If local_copy is None, then this will check the server to see if
# we are up to date. However, if we are working within the development
# tree, use it unconditionally.
local_copy = None
branch_fn = os.path.join(os.path.dirname(__file__),
                         '../data/snapd-base-declaration.yaml')
if os.path.exists(branch_fn):
    local_copy = branch_fn
p = snapd_base_declaration.SnapdBaseDeclaration(local_copy)
# TODO: don't hardcode
base_decl_series = "16"
base_decl = p.decl[base_decl_series]

def _verify_interface(iface):
    found = False
    if "slots" in base_decl and iface in base_decl["slots"]:
        found = True
    elif "plugs" in base_decl and iface in base_decl["plugs"]:
        found = True

    return found

def add_interface(side, iface, key, value):
    if not _verify_interface(iface):
        raise Exception("Invalid interface '%s'" % iface)

    if side not in decl:
        decl[side] = {}

    if iface not in decl[side]:
        decl[side][iface] = {}

    if key not in decl[side][iface]:
        if value is True or value is False:
            if value:
                decl[side][iface][key] = "true"
            else:
                decl[side][iface][key] = "false"
        else:
            decl[side][iface][key] = value
    else:
        raise Exception("'%s' already specified for '%s'" % (key, iface))

def print_decl():
    def _print_key(key):
        print(json.dumps(decl[key], sort_keys=True, indent=2))
    if "slots" in decl:
        print("slots:")
        _print_key("slots")
    if "plugs" in decl:
        print("plugs:")
        _print_key("plugs")

def main():
    parser = argparse.ArgumentParser(
        prog='create-snap-declaration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Output data suitable for adding to snap declaration',
        )
    parser.add_argument('--slot-installation', type=str,
                        help='list of interfaces to allow installation')
    parser.add_argument('--slot-connection', type=str,
                        help='list of interfaces to allow connection')
    parser.add_argument('--slot-auto-connection', type=str,
                        help='list of interfaces to allow auto-connection')
    parser.add_argument('--plug-installation', type=str,
                        help='list of interfaces to allow installation')
    parser.add_argument('--plug-connection', type=str,
                        help='list of interfaces to allow connection')
    parser.add_argument('--plug-auto-connection', type=str,
                        help='list of interfaces to allow auto-connection')
    args = parser.parse_args()

    slots = {}
    plugs = {}

    if args.slot_installation:
        for i in args.slot_installation.split(','):
            add_interface("slots", i, "allow-installation", True)

    if args.slot_connection:
        for i in args.slot_connection.split(','):
            add_interface("slots", i, "allow-connection", True)

    if args.slot_auto_connection:
        for i in args.slot_auto_connection.split(','):
            add_interface("slots", i, "allow-auto-connection", True)

    if args.plug_installation:
        for i in args.plug_installation.split(','):
            add_interface("plugs", i, "allow-installation", True)

    if args.plug_connection:
        for i in args.plug_connection.split(','):
            add_interface("plugs", i, "allow-connection", True)

    if args.plug_auto_connection:
        for i in args.plug_auto_connection.split(','):
            add_interface("plugs", i, "allow-auto-connection", True)

    print_decl()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Aborted.")
        sys.exit(1)
