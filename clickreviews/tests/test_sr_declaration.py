'''test_sr_declaration.py: tests for the sr_declaration module'''
#
# Copyright (C) 2014-2016 Canonical Ltd.
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

from clickreviews.sr_declaration import SnapReviewDeclaration, SnapDeclarationException
import clickreviews.sr_tests as sr_tests


class TestSnapReviewDeclaration(sr_tests.TestSnapReview):
    """Tests for the lint review tool."""

    def test__verify_declaration_valid(self):
        '''Test _verify_declaration - valid'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'inst-on-classic-true': {
                    'allow-installation': {
                        'on-classic': True
                    },
                },
                'inst-on-classic-false': {
                    'deny-installation': {
                        'on-classic': False
                    },
                },
                'inst-slot-snap-type-all': {
                    'allow-installation': {
                        'slot-snap-type': ['core', 'gadget', 'kernel', 'app']
                    },
                },
                'inst-slot-snap-type-app': {
                    'deny-installation': {
                        'slot-snap-type': ['app']
                    },
                },
                'inst-slot-attributes-empty': {
                    'allow-installation': {
                        'slot-attributes': {},
                    },
                },
                'conn-on-classic-true': {
                    'allow-connection': {
                        'on-classic': True
                    },
                },
                'conn-on-classic-false': {
                    'deny-connection': {
                        'on-classic': False
                    },
                },
                'conn-plug-snap-type-all': {
                    'allow-connection': {
                        'plug-snap-type': ['core', 'gadget', 'kernel', 'app']
                    },
                },
                'conn-plug-snap-type-core': {
                    'deny-connection': {
                        'plug-snap-type': ['core']
                    },
                },
                'conn-plug-snap-id-allow': {
                    'allow-connection': {
                        'plug-snap-id': ['something32charslongGgGgGgGgGgGg']
                    },
                },
                'conn-plug-snap-id-deny': {
                    'deny-connection': {
                        'plug-snap-id': ['somethingelse32charslongGgGgGgGg']
                    },
                },
                'conn-plug-publisher-id-allow': {
                    'allow-connection': {
                        'plug-publisher-id': ['$SLOT_PUBLISHER_ID',
                                              'canonical']
                    },
                },
                'conn-plug-publisher-id-deny': {
                    'deny-connection': {
                        'plug-publisher-id': ['badpublisher']
                    },
                },
                'conn-slot-attributes-empty': {
                    'allow-connection': {
                        'slot-attributes': {},
                    },
                },
                'conn-plug-attributes-empty': {
                    'deny-connection': {
                        'plug-attributes': {},
                    },
                },
                'autoconn-on-classic-true': {
                    'allow-connection': {
                        'on-classic': True
                    },
                },
                'autoconn-on-classic-false': {
                    'deny-connection': {
                        'on-classic': False
                    },
                },
                'autoconn-plug-snap-type-all': {
                    'allow-connection': {
                        'plug-snap-type': ['core', 'gadget', 'kernel', 'app']
                    },
                },
                'autoconn-plug-snap-type-core': {
                    'deny-connection': {
                        'plug-snap-type': ['core']
                    },
                },
                'autoconn-plug-snap-id-allow': {
                    'allow-connection': {
                        'plug-snap-id': ['something32charslongGgGgGgGgGgGg']
                    },
                },
                'autoconn-plug-snap-id-deny': {
                    'deny-connection': {
                        'plug-snap-id': ['somethingelse32charslongGgGgGgGg']
                    },
                },
                'autoconn-plug-publisher-id-allow': {
                    'allow-connection': {
                        'plug-publisher-id': ['$SLOT_PUBLISHER_ID',
                                              'canonical']
                    },
                },
                'autoconn-plug-publisher-id-deny': {
                    'deny-connection': {
                        'plug-publisher-id': ['badpublisher']
                    },
                },
                'autoconn-slot-attributes-empty': {
                    'allow-connection': {
                        'slot-attributes': {},
                    },
                },
                'autoconn-plug-attributes-empty': {
                    'deny-connection': {
                        'plug-attributes': {},
                    },
                },
            },
            'plugs': {
                'inst-on-classic-true': {
                    'allow-installation': {
                        'on-classic': True
                    },
                },
                'inst-on-classic-false': {
                    'deny-installation': {
                        'on-classic': False
                    },
                },
                'inst-plug-snap-type-all': {
                    'allow-installation': {
                        'plug-snap-type': ['core', 'gadget', 'kernel', 'app']
                    },
                },
                'inst-plug-snap-type-app': {
                    'deny-installation': {
                        'plug-snap-type': ['app']
                    },
                },
                'inst-plug-attributes-empty': {
                    'allow-installation': {
                        'plug-attributes': {},
                    },
                },
                'conn-on-classic-true': {
                    'allow-connection': {
                        'on-classic': True
                    },
                },
                'conn-on-classic-false': {
                    'deny-connection': {
                        'on-classic': False
                    },
                },
                'conn-slot-snap-type-all': {
                    'allow-connection': {
                        'slot-snap-type': ['core', 'gadget', 'kernel', 'app']
                    },
                },
                'conn-slot-snap-type-core': {
                    'deny-connection': {
                        'slot-snap-type': ['core']
                    },
                },
                'conn-slot-snap-id-allow': {
                    'allow-connection': {
                        'slot-snap-id': ['something32charslongGgGgGgGgGgGg']
                    },
                },
                'conn-slot-snap-id-deny': {
                    'deny-connection': {
                        'slot-snap-id': ['somethingelse32charslongGgGgGgGg']
                    },
                },
                'conn-slot-publisher-id-allow': {
                    'allow-connection': {
                        'slot-publisher-id': ['$PLUG_PUBLISHER_ID',
                                              'canonical']
                    },
                },
                'conn-slot-publisher-id-deny': {
                    'deny-connection': {
                        'slot-publisher-id': ['badpublisher']
                    },
                },
                'conn-plug-attributes-empty': {
                    'allow-connection': {
                        'plug-attributes': {},
                    },
                },
                'conn-slot-attributes-empty': {
                    'deny-connection': {
                        'slot-attributes': {},
                    },
                },
                'autoconn-on-classic-true': {
                    'allow-connection': {
                        'on-classic': True
                    },
                },
                'autoconn-on-classic-false': {
                    'deny-connection': {
                        'on-classic': False
                    },
                },
                'autoconn-slot-snap-type-all': {
                    'allow-connection': {
                        'slot-snap-type': ['core', 'gadget', 'kernel', 'app']
                    },
                },
                'autoconn-slot-snap-type-core': {
                    'deny-connection': {
                        'slot-snap-type': ['core']
                    },
                },
                'autoconn-slot-snap-id-allow': {
                    'allow-connection': {
                        'slot-snap-id': ['something32charslongGgGgGgGgGgGg']
                    },
                },
                'autoconn-slot-snap-id-deny': {
                    'deny-connection': {
                        'slot-snap-id': ['somethingelse32charslongGgGgGgGg']
                    },
                },
                'autoconn-slot-publisher-id-allow': {
                    'allow-connection': {
                        'slot-publisher-id': ['$PLUG_PUBLISHER_ID',
                                              'canonical']
                    },
                },
                'autoconn-slot-publisher-id-deny': {
                    'deny-connection': {
                        'slot-publisher-id': ['badpublisher']
                    },
                },
                'autoconn-plug-attributes-empty': {
                    'allow-connection': {
                        'plug-attributes': {},
                    },
                },
                'autoconn-slot-attributes-empty': {
                    'deny-connection': {
                        'slot-attributes': {},
                    },
                },
            },
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 50, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test__verify_declaration_invalid_empty(self):
        '''Test _verify_declaration - empty'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_dict'
        expected['error'][name] = {"text": "declaration malformed (empty)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_empty_base(self):
        '''Test _verify_declaration - empty'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {}

        try:
            c._verify_declaration(decl=decl, base=True)
        except SnapDeclarationException:
            return
        raise Exception("base declaration should be invalid")

    def test__verify_declaration_invalid_type(self):
        '''Test _verify_declaration - bad type (list)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = []
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_dict'
        expected['error'][name] = {"text": "declaration malformed (not a dict)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_true(self):
        '''Test _verify_declaration - invalid slots - true'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': True}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_dict:slots'
        expected['error'][name] = {"text": "declaration malformed (not a dict)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_plugs_false(self):
        '''Test _verify_declaration - invalid plugs - false'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'plugs': False}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_dict:plugs'
        expected['error'][name] = {"text": "declaration malformed (not a dict)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_bad_key(self):
        '''Test _verify_declaration - bad key'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'non-existent': {'foo': True}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_key'
        expected['error'][name] = {"text": "declaration malformed (unknown key 'non-existent')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_slots_iface_bool(self):
        '''Test _verify_declaration - interface: boolean (slots)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': {'foo': True}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo'
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_plugs_iface_bool(self):
        '''Test _verify_declaration - interface: boolean (plugs)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'plugs': {'foo': True}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_plugs:foo'
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_type(self):
        '''Test _verify_declaration - invalid interface: list'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': {'foo': []}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots_dict:foo'
        expected['error'][name] = {
            "text": "declaration malformed (interface not True, False or dict)"
        }
        self.check_results(r, expected=expected)

    def test__verify_declaration_slots_iface_constraint_bool(self):
        '''Test _verify_declaration - interface constraint: boolean (slots)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': {'foo': {'allow-installation': True}}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-installation'
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_plugs_iface_constraint_bool(self):
        '''Test _verify_declaration - interface constraint: boolean (plugs)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'plugs': {'foo': {'deny-installation': True}}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_plugs:foo:deny-installation'
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_list(self):
        '''Test _verify_declaration - invalid interface constraint: list
           (slots)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': {'foo': {'allow-installation': []}}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-installation'
        expected['error'][name] = {"text": "declaration malformed (allow-installation not True, False or dict)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_unknown(self):
        '''Test _verify_declaration - invalid interface constraint: unknown
           (slots with allow-installation)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': {'foo': {'nonexistent': True}}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:nonexistent'
        expected['error'][name] = {"text": "declaration malformed (unknown constraint 'nonexistent')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_key_unknown(self):
        '''Test _verify_declaration - invalid interface constraint key: unknown
           (slots with allow-installation)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'foo': {
                    'allow-installation': {
                        'nonexistent': True,
                        'nonexistent2': False
                    },
                },
            },
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-installation_nonexistent'
        expected['error'][name] = {"text": "declaration malformed (unknown constraint key 'nonexistent')"}
        name2 = 'declaration-snap-v2:valid_slots:foo:allow-installation_nonexistent2'
        expected['error'][name2] = {"text": "declaration malformed (unknown constraint key 'nonexistent2')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_list2(self):
        '''Test _verify_declaration - invalid interface constraint: list
           (slots with allow-connection)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': {'foo': {'allow-connection': []}}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-connection'
        expected['error'][name] = {"text": "declaration malformed (allow-connection not True, False or dict)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_key_unknown2(self):
        '''Test _verify_declaration - invalid interface constraint key: unknown
           (slots with deny-auto-connection)'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'foo': {
                    'deny-auto-connection': {
                        'nonexistent': True,
                        'nonexistent2': False
                    },
                },
            },
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:deny-auto-connection_nonexistent'
        expected['error'][name] = {"text": "declaration malformed (unknown constraint key 'nonexistent')"}
        name2 = 'declaration-snap-v2:valid_slots:foo:deny-auto-connection_nonexistent2'
        expected['error'][name2] = {"text": "declaration malformed (unknown constraint key 'nonexistent2')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_bool(self):
        '''Test _verify_declaration - invalid interface constraint bool'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': {'foo': {'allow-installation': {'on-classic': []}}}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-installation_on-classic'
        expected['error'][name] = {"text": "declaration malformed ('on-classic' not True or False)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_str(self):
        '''Test _verify_declaration - invalid interface constraint str'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {'slots': {'foo': {'allow-installation': {'plug-snap-id': ""}}}}
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-installation_plug-snap-id'
        expected['error'][name] = {"text": "declaration malformed ('plug-snap-id' not a list)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_list_value(self):
        '''Test _verify_declaration - invalid interface constraint list
           value'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'foo': {
                    'allow-installation': {
                        'plug-snap-id': [{}]
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-installation_plug-snap-id'
        expected['error'][name] = {"text": "declaration malformed ('{}' in 'plug-snap-id' not a string)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_iface_constraint_dict(self):
        '''Test _verify_declaration - invalid interface constraint dict'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'foo': {
                    'allow-connection': {
                        'plug-attributes': []
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-connection_plug-attributes'
        expected['error'][name] = {"text": "declaration malformed ('plug-attributes' not a dict)"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_valid_slots_plug_attribs_browser_support(self):
        '''Test _verify_declaration - valid interface constraint attrib
           value for browser-support
        '''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'browser-support': {
                    'allow-connection': {
                        'plug-attributes': {
                            'allow-sandbox': True
                        }
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:browser-support:allow-connection'
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_plug_attribs_browser_support_bad(self):
        '''Test _verify_declaration - invalid interface constraint attrib
           value'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'browser-support': {
                    'allow-connection': {
                        'plug-attributes': {
                            'allow-sandbox': []
                        }
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:browser-support:allow-connection_plug-attributes'
        expected['error'][name] = {"text": "declaration malformed (wrong type '[]' for attribute 'allow-sandbox')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_plug_attribs_browser_support_nonexistent(self):
        '''Test _verify_declaration - invalid interface constraint attrib
           nonexistent'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'something': {
                    'allow-connection': {
                        'plug-attributes': {
                            'nonexistent': []
                        }
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:something:allow-connection_plug-attributes'
        expected['error'][name] = {"text": "declaration malformed (unknown attribute 'nonexistent')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_valid_slots_plug_attribs_content(self):
        '''Test _verify_declaration - valid interface constraint attrib
           for content'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'content': {
                    'allow-connection': {
                        'slot-attributes': {
                            'read': ["/foo"],
                            'write': ["/bar"]
                        },
                        'plug-attributes': {
                            'target': "/target",
                            'content': "baz"
                        },
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()

        name = 'declaration-snap-v2:valid_slots:content:allow-connection'
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_plug_attribs_content_value(self):
        '''Test _verify_declaration - invalid interface constraint attrib
           value for content'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'content': {
                    'allow-connection': {
                        'slot-attributes': {
                            'read': ""
                        }
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:content:allow-connection_slot-attributes'
        expected['error'][name] = {"text": "declaration malformed (wrong type '' for attribute 'read')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_plug_attribs_content_side(self):
        '''Test _verify_declaration - invalid interface constraint attrib
           side for content'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'content': {
                    'allow-connection': {
                        'slot-attributes': {
                            'target': ""
                        }
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:content:allow-connection_slot-attributes'
        expected['error'][name] = {"text": "declaration malformed (attribute 'target' wrong for 'slots')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_plug_snap_type(self):
        '''Test _verify_declaration - invalid plug-snap-type'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'foo': {
                    'allow-connection': {
                        'plug-snap-type': ['bad-snap-type']
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-connection'
        expected['error'][name] = {"text": "declaration malformed (invalid snap type 'bad-snap-type')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_plugs_slot_snap_type(self):
        '''Test _verify_declaration - invalid slot-snap-type'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'plugs': {
                'foo': {
                    'allow-connection': {
                        'slot-snap-type': ['bad-snap-type']
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_plugs:foo:allow-connection'
        expected['error'][name] = {"text": "declaration malformed (invalid snap type 'bad-snap-type')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_plugs_slot_publisher_id(self):
        '''Test _verify_declaration - invalid slot-publisher-id'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'plugs': {
                'foo': {
                    'allow-connection': {
                        'slot-publisher-id': ['$SLOT_PUBLISHER_ID']
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_plugs:foo:allow-connection'
        expected['error'][name] = {"text": "declaration malformed (invalid publisher id '$SLOT_PUBLISHER_ID')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_plug_publisher_id(self):
        '''Test _verify_declaration - invalid plug-publisher-id'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'foo': {
                    'allow-connection': {
                        'plug-publisher-id': ['$PLUG_PUBLISHER_ID']
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-connection'
        expected['error'][name] = {"text": "declaration malformed (invalid publisher id '$PLUG_PUBLISHER_ID')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_plug_publisher_id_value(self):
        '''Test _verify_declaration - invalid plug-publisher-id'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'foo': {
                    'allow-connection': {
                        'plug-publisher-id': ['b@d']
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-connection'
        expected['error'][name] = {"text": "declaration malformed (invalid format for publisher id 'b@d')"}
        self.check_results(r, expected=expected)

    def test__verify_declaration_invalid_slots_plug_snap_id(self):
        '''Test _verify_declaration - invalid plug-snap-id'''
        c = SnapReviewDeclaration(self.test_name)
        decl = {
            'slots': {
                'foo': {
                    'allow-connection': {
                        'plug-snap-id': ['b@d']
                    }
                }
            }
        }
        c._verify_declaration(decl=decl)
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'declaration-snap-v2:valid_slots:foo:allow-connection'
        expected['error'][name] = {"text": "declaration malformed (invalid format for snap id 'b@d')"}
        self.check_results(r, expected=expected)
