# Copyright 2013 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from ironic.api.controllers.v1 import versions
from ironic.tests.unit.api import base


class TestRoot(base.BaseApiTest):

    def test_get_root(self):
        response = self.get_json('/', path_prefix='')
        # Check fields are not empty
        [self.assertNotIn(f, ['', []]) for f in response]

        self.assertEqual('OpenStack Ironic API', response['name'])
        self.assertTrue(response['description'])
        self.assertEqual([response['default_version']], response['versions'])

        version1 = response['default_version']
        self.assertEqual('v1', version1['id'])
        self.assertEqual('CURRENT', version1['status'])
        self.assertEqual(versions.MIN_VERSION_STRING, version1['min_version'])
        self.assertEqual(versions.MAX_VERSION_STRING, version1['version'])


class TestV1Root(base.BaseApiTest):

    def test_get_v1_root(self):
        data = self.get_json('/')
        self.assertEqual('v1', data['id'])
        # Check fields are not empty
        for f in data:
            self.assertNotIn(f, ['', []])
        # Check if all known resources are present and there are no extra ones.
        not_resources = ('id', 'links', 'media_types')
        actual_resources = tuple(set(data.keys()) - set(not_resources))
        expected_resources = ('chassis', 'drivers', 'nodes', 'ports')
        self.assertEqual(sorted(expected_resources), sorted(actual_resources))

        self.assertIn({'type': 'application/vnd.openstack.ironic.v1+json',
                       'base': 'application/json'}, data['media_types'])
