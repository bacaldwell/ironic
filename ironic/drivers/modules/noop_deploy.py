# Copyright 2013 Hewlett-Packard Development Company, L.P.
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

import os

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils
from oslo_utils import strutils
from six.moves.urllib import parse

from ironic.common import exception
from ironic.common.glance_service import service_utils as glance_service_utils
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LI
from ironic.common.i18n import _LW
from ironic.common import keystone
from ironic.common import states
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers import base
from ironic.drivers.modules import agent
from ironic.drivers.modules import agent_base_vendor
from ironic.drivers.modules import deploy_utils

LOG = logging.getLogger(__name__)

CONF = cfg.CONF


def parse_instance_info(node):
    """Gets the instance specific Node deployment info.

    This method validates whether the 'instance_info' property of the
    supplied node contains the required information for this driver to
    deploy images to the node.

    :param node: a single Node.
    :returns: A dict with the instance_info values.
    :raises: MissingParameterValue, if any of the required parameters are
        missing.
    :raises: InvalidParameterValue, if any of the parameters have invalid
        value.
    """
    info = node.instance_info
    i_info = {}
    i_info['image_source'] = info.get('image_source')
    if (i_info['image_source'] and
        not glance_service_utils.is_glance_image(
                i_info['image_source'])):
        i_info['kernel'] = info.get('kernel')
        i_info['ramdisk'] = info.get('ramdisk')

    error_msg = _("Cannot validate no-op deploy. Some parameters were missing"
                  " in node's instance_info")
    deploy_utils.check_for_missing_params(i_info, error_msg)

    if is_whole_disk_image:
        err_msg_invalid = _("Cannot deploy whole disk image in "
                            "no-op deploy mode")
        raise exception.InvalidParameterValue(err_msg_invalid)
        return i_info

    if int(i_info['swap_mb']) > 0 or int(i_info['ephemeral_gb']) > 0:
        err_msg_invalid = _("Cannot deploy image in no-op mode with "
                            "swap or ephemeral size set")
        raise exception.InvalidParameterValue(err_msg_invalid)
        return i_info

    i_info['configdrive'] = info.get('configdrive')
    i_info['kernel_cmdline'] = info.get('kernel_cmdline')

    return i_info


def get_deploy_info(node, **kwargs):
    """Returns the information required for doing iSCSI deploy in a dictionary.

    :param node: ironic node object
    :param kwargs: the keyword args passed from the conductor node.
    :raises: MissingParameterValue, if some required parameters were not
        passed.
    :raises: InvalidParameterValue, if any of the parameters have invalid
        value.
    """
    deploy_key = kwargs.get('key')
    i_info = parse_instance_info(node)
    if i_info['deploy_key'] != deploy_key:
        raise exception.InvalidParameterValue(_("Deploy key does not match"))

    params = {
        'node_uuid': node.uuid}

    params.update({'boot_option': deploy_utils.get_boot_option(node),
                       'boot_mode': _get_boot_mode(node)})

    missing = [key for key in params if params[key] is None]
    if missing:
        raise exception.MissingParameterValue(
            _("Parameters %s were not passed to ironic"
              " for deploy.") % missing)

    # ephemeral_format is nullable
    params['configdrive'] = i_info.get('configdrive')

    return params


def _get_boot_mode(node):
    """Gets the boot mode.

    :param node: A single Node.
    :returns: A string representing the boot mode type. Defaults to 'bios'.
    """
    boot_mode = deploy_utils.get_boot_mode_for_deploy(node)
    if boot_mode:
        return boot_mode
    return "bios"


def build_deploy_ramdisk_options(node):
    """Build the ramdisk config options for a node

    This method builds the ramdisk options for a node,
    given all the required parameters for doing iscsi deploy.

    :param node: a single Node.
    :returns: A dictionary of options to be passed to ramdisk for performing
        the deploy.
    """
    # NOTE: we should strip '/' from the end because this is intended for
    # hardcoded ramdisk script
    ironic_api = (CONF.conductor.api_url or
                  keystone.get_service_url()).rstrip('/')

    deploy_key = utils.random_alnum(32)
    i_info = node.instance_info
    i_info['deploy_key'] = deploy_key
    node.instance_info = i_info
    node.save()

    deploy_options = {
        'deployment_id': node['uuid'],
        'deployment_key': deploy_key,
        'boot_option': boot_option,
        'boot_mode': _get_boot_mode(node),
        # NOTE: The below entry is a temporary workaround for bug/1433812
        'coreos.configdrive': 0,
    }

    kernel_cmdline = node.instance_info.get('kernel_cmdline')
    if kernel_cmdline:
        # Merge both kernel cmdlines to avoid duplicated options, also
        # make sure that the options specified in the custom kernel command
        # line take precedence over the ones in pxe_append_params
        if CONF.pxe.pxe_append_params:
            kernel_cmdline = utils.merge_kernel_cmdline(
                kernel_cmdline, CONF.pxe.pxe_append_params)
        deploy_options['kernel_cmdline'] = kernel_cmdline

    return deploy_options


def validate(task):
    """Validates the pre-requisites for no-op deploy.

    Validates whether node in the task provided has some ports enrolled.
    This method validates whether conductor url is available either from CONF
    file or from keystone.

    :param task: a TaskManager instance containing the node to act on.
    :raises: InvalidParameterValue if the URL of the Ironic API service is not
             configured in config file and is not accessible via Keystone
             catalog.
    :raises: MissingParameterValue if no ports are enrolled for the given node.
    """
    try:
        # TODO(lucasagomes): Validate the format of the URL
        CONF.conductor.api_url or keystone.get_service_url()
    except (exception.KeystoneFailure,
            exception.CatalogNotFound,
            exception.KeystoneUnauthorized) as e:
        raise exception.InvalidParameterValue(_(
            "Couldn't get the URL of the Ironic API service from the "
            "configuration file or keystone catalog. Keystone error: %s") % e)

    parse_instance_info(task.node)


def finish_deploy(task):
    """makes the instance active.

    :param task: a TaskManager object.
    :param address: The IP address of the bare metal node.
    """
    node = task.node

    LOG.info(_LI('Deployment to node %s done'), node.uuid)
    task.process_event('done')


class NoopDeploy(base.DeployInterface):
    """PXE/no-op Deploy Interface for deploy-related actions."""

    def get_properties(self):
        return {}

    def validate(self, task):
        """Validate the deployment information for the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue.
        :raises: MissingParameterValue
        """
        task.driver.boot.validate(task)
        node = task.node

        # Check the boot_mode and boot_option capabilities values.
        deploy_utils.validate_capabilities(node)

        # TODO(rameshg87): iscsi_ilo driver uses this method. Remove
        # and copy-paste it's contents here once iscsi_ilo deploy driver
        # broken down into separate boot and deploy implementations.
        validate(task)

    @task_manager.require_exclusive_lock
    def deploy(self, task):
        """Start and complete deployment of the task's node.

        The real no-op of the driver. Returns DEPLOYDONE because
        there are no async operations waiting to complete as with
        iSCSI.

        :param task: a TaskManager instance containing the node to act on.
        :returns: deploy state DEPLOYDONE
        """

        task.driver.vendor.continue_deploy(task)
        return states.DEPLOYDONE

    @task_manager.require_exclusive_lock
    def tear_down(self, task):
        """Tear down a previous deployment on the task's node.

        Power off the node. All actual clean-up is done in the clean_up()
        method which should be called separately.

        :param task: a TaskManager instance containing the node to act on.
        :returns: deploy state DELETED.
        """
        manager_utils.node_power_action(task, states.POWER_OFF)
        return states.DELETED

    def prepare(self, task):
        """Prepare the deployment environment for this task's node.

        Generates the TFTP configuration for PXE-booting both the deployment
        and user images, fetches the TFTP image from Glance and add it to the
        local cache.

        :param task: a TaskManager instance containing the node to act on.
        """
        node = task.node
        if node.provision_state != states.ACTIVE:
            deploy_opts = build_deploy_ramdisk_options(node)

            # NOTE(lucasagomes): We are going to extend the normal PXE config
            # to also contain the agent options so it could be used for
            # both the DIB ramdisk and the IPA ramdisk
            agent_opts = agent.build_agent_options(node)
            deploy_opts.update(agent_opts)

            task.driver.boot.prepare_ramdisk(task, deploy_opts)

    def clean_up(self, task):
        """Clean up the deployment environment for the task's node.

        Unlinks TFTP and instance images.
        Removes the TFTP configuration files for this node. As a precaution,
        this method also ensures the keystone auth token file was removed.

        :param task: a TaskManager instance containing the node to act on.
        """
        task.driver.boot.clean_up_ramdisk(task)
        task.driver.boot.clean_up_instance(task)

    def take_over(self, task):
        pass


class VendorPassthru(agent_base_vendor.BaseAgentVendor):
    """Interface to mix IPMI and PXE vendor-specific interfaces."""

    def get_properties(self):
        return {}

    def validate(self, task, method, **kwargs):
        """Validates the inputs for a vendor passthru.

        If invalid, raises an exception; otherwise returns None.

        Valid methods:

        :param task: a TaskManager instance containing the node to act on.
        :param method: method to be validated.
        :param kwargs: kwargs containins the method's parameters.
        :raises: InvalidParameterValue if any parameters is invalid.
        """
        pass

    @task_manager.require_exclusive_lock
    def continue_deploy(self, task, **kwargs):
        """Method invoked from directly from driver.deploy

        :param task: a TaskManager object containing the node.
        :param kwargs: the kwargs passed from the heartbeat method.
        :raises: InstanceDeployFailure, if it encounters some error during
            the deploy.
        """
        task.process_event('resume')
        node = task.node
        LOG.debug('Continuing the deployment on node %s', node.uuid)

        try:
            task.driver.boot.prepare_instance(task)
        except Exception as e:
            LOG.error(_LE('Deploy failed for instance %(instance)s. '
                          'Error: %(error)s'),
                      {'instance': node.instance_uuid, 'error': e})
            msg = _('Failed to continue agent deployment.')
            deploy_utils.set_failed_state(task, msg)
        finish_deploy(task)
