# Copyright 2016 Intel Corporation

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg

from ironic.common.i18n import _

opts = [
    cfg.BoolOpt('enabled', default=False,
                help=_('whether to enable inspection using ironic-inspector')),
    cfg.StrOpt('service_url',
               help=_('ironic-inspector HTTP endpoint. If this is not set, '
                      'the ironic-inspector client default '
                      '(http://127.0.0.1:5050) will be used.')),
    cfg.IntOpt('status_check_period', default=60,
               help=_('period (in seconds) to check status of nodes '
                      'on inspection')),
]


def register_opts(conf):
    conf.register_opts(opts, group='inspector')
