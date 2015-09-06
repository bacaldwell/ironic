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
from oslo_utils import strutils
from six.moves.urllib import parse

from ironic.common import exception
from ironic.common.glance_service import service_utils as glance_service_utils
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LI
from ironic.common import image_service as service
from ironic.common import keystone
from ironic.common import states
from ironic.common import utils
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import image_cache
from ironic.drivers import utils as driver_utils
from ironic.openstack.common import fileutils

LOG = logging.getLogger(__name__)

# NOTE(rameshg87): This file now registers some of opts in pxe group.
# This is acceptable for now as a future refactoring into
# separate boot and deploy interfaces is planned, and moving config
# options twice is not recommended.  Hence we would move the parameters
# to the appropriate place in the final refactoring.
pxe_opts = [
    cfg.StrOpt('pxe_append_params',
               default='nofb nomodeset vga=normal',
               help='Additional append parameters for baremetal PXE boot.'),
    cfg.StrOpt('default_ephemeral_format',
               default='ext4',
               help='Default file system format for ephemeral partition, '
                    'if one is created.'),
    cfg.StrOpt('images_path',
               default='/var/lib/ironic/images/',
               help='On the ironic-conductor node, directory where images are '
                    'stored on disk.'),
    cfg.StrOpt('instance_master_path',
               default='/var/lib/ironic/master_images',
               help='On the ironic-conductor node, directory where master '
                    'instance images are stored on disk.'),
    cfg.IntOpt('image_cache_size',
               default=20480,
               help='Maximum size (in MiB) of cache for master images, '
                    'including those in use.'),
    # 10080 here is 1 week - 60*24*7. It is entirely arbitrary in the absence
    # of a facility to disable the ttl entirely.
    cfg.IntOpt('image_cache_ttl',
               default=10080,
               help='Maximum TTL (in minutes) for old master images in '
               'cache.'),
    cfg.StrOpt('disk_devices',
               default='cciss/c0d0,sda,hda,vda',
               help='The disk devices to scan while doing the deploy.'),
    ]

CONF = cfg.CONF
CONF.register_opts(pxe_opts, group='pxe')


@image_cache.cleanup(priority=50)
class InstanceImageCache(image_cache.ImageCache):

    def __init__(self, image_service=None):
        super(self.__class__, self).__init__(
            CONF.pxe.instance_master_path,
            # MiB -> B
            cache_size=CONF.pxe.image_cache_size * 1024 * 1024,
            # min -> sec
            cache_ttl=CONF.pxe.image_cache_ttl * 60,
            image_service=image_service)


def _get_image_dir_path(node_uuid):
    """Generate the dir for an instances disk."""
    return os.path.join(CONF.pxe.images_path, node_uuid)


def _get_image_file_path(node_uuid):
    """Generate the full path for an instances disk."""
    return os.path.join(_get_image_dir_path(node_uuid), 'disk')


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
    is_whole_disk_image = node.driver_internal_info.get('is_whole_disk_image')
    if not is_whole_disk_image:
        err_msg_invalid = _("Onle whole_disk_image mode is supported with
                                "diskless deploy mode")
        raise exception.InvalidParameterValue(err_msg_invalid)
    i_info['root_gb'] = info.get('root_gb')

    error_msg = _("Cannot validate Diskless deploy. Some parameters were missing"
                  " in node's instance_info")
    deploy_utils.check_for_missing_params(i_info, error_msg)

    # Internal use only
    i_info['deploy_key'] = info.get('deploy_key')

    # (blakec) There is no disk usage in those mode, so swap and ephemeral space
    # Makes no sense.
    i_info['swap_mb'] = 0
    i_info['ephemeral_gb'] = 0
    err_msg_invalid = _("Cannot validate parameter for iSCSI deploy. "
                        "Invalid parameter %(param)s. Reason: %(reason)s")
    for param in ('root_gb'):
        try:
            int(i_info[param])
        except ValueError:
            reason = _("%s is not an integer value.") % i_info[param]
            raise exception.InvalidParameterValue(err_msg_invalid %
                                                  {'param': param,
                                                   'reason': reason})

    if is_whole_disk_image:
        if int(i_info['swap_mb']) > 0 or int(i_info['ephemeral_gb']) > 0:
            err_msg_invalid = _("Cannot deploy whole disk image with "
                                "swap or ephemeral size set")
            raise exception.InvalidParameterValue(err_msg_invalid)
        return i_info

    i_info['ephemeral_format'] = info.get('ephemeral_format')
    i_info['configdrive'] = info.get('configdrive')

    if i_info['ephemeral_gb'] and not i_info['ephemeral_format']:
        i_info['ephemeral_format'] = CONF.pxe.default_ephemeral_format

    preserve_ephemeral = info.get('preserve_ephemeral', False)
    try:
        i_info['preserve_ephemeral'] = strutils.bool_from_string(
                                            preserve_ephemeral, strict=True)
    except ValueError as e:
        raise exception.InvalidParameterValue(err_msg_invalid %
                                  {'param': 'preserve_ephemeral', 'reason': e})
    return i_info


def cache_instance_image(ctx, node):
    """Fetch the instance's image from Glance

    This method pulls the AMI and writes them to the appropriate place
    on local disk.

    :param ctx: context
    :param node: an ironic node object
    :returns: a tuple containing the uuid of the image and the path in
        the filesystem where image is cached.
    """
    i_info = parse_instance_info(node)
    fileutils.ensure_tree(_get_image_dir_path(node.uuid))
    image_path = _get_image_file_path(node.uuid)
    uuid = i_info['image_source']

    LOG.debug("Fetching image %(ami)s for node %(uuid)s",
              {'ami': uuid, 'uuid': node.uuid})

    deploy_utils.fetch_images(ctx, InstanceImageCache(), [(uuid, image_path)],
                              CONF.force_raw_images)

    return (uuid, image_path)


def destroy_images(node_uuid):
    """Delete instance's image file.

    :param node_uuid: the uuid of the ironic node.
    """
    utils.unlink_without_raise(_get_image_file_path(node_uuid))
    utils.rmtree_without_raise(_get_image_dir_path(node_uuid))
    InstanceImageCache().clean_up()


def get_deploy_info(node, **kwargs):
    """Returns the information required for doing diskless deploy in a dictionary.

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
              'image_path': _get_image_file_path(node.uuid),
              'node_uuid': node.uuid}

    is_whole_disk_image = node.driver_internal_info['is_whole_disk_image']
    if not is_whole_disk_image:
        params.update({'root_mb': 1024 * int(i_info['root_gb']),
                       'swap_mb': int(i_info['swap_mb']),
                       'ephemeral_mb': 1024 * int(i_info['ephemeral_gb']),
                       'preserve_ephemeral': i_info['preserve_ephemeral'],
                       'boot_option': get_boot_option(node),
                       'boot_mode': _get_boot_mode(node)})

    missing = [key for key in params if params[key] is None]
    if missing:
        raise exception.MissingParameterValue(_(
                "Parameters %s were not passed to ironic"
                " for deploy.") % missing)

    if is_whole_disk_image:
        return params

    # configdrive and ephemeral_format are nullable
    params['ephemeral_format'] = i_info.get('ephemeral_format')
    params['configdrive'] = i_info.get('configdrive')

    return params


def continue_deploy(task, **kwargs):
    """Resume a deployment upon getting POST data from deploy
    (also the final) ramdisk.

    This method raises no exceptions because it is intended to be
    invoked asynchronously as a callback from the deploy ramdisk.

    :param task: a TaskManager instance containing the node to act on.
    :param kwargs: the kwargs to be passed to deploy.
    :raises: InvalidState if the event is not allowed by the associated
             state machine.
    :returns: a dictionary containing the following keys:
            'disk identifier': ID of the disk to which image was deployed.
    """
    node = task.node

    params = get_deploy_info(node, **kwargs)
    ramdisk_error = kwargs.get('error')

    def _fail_deploy(task, msg):
        """Fail the deploy after logging and setting error states."""
        LOG.error(msg)
        deploy_utils.set_failed_state(task, msg)
        destroy_images(task.node.uuid)
        raise exception.InstanceDeployFailure(msg)

    if ramdisk_error:
        msg = _('Error returned from deploy ramdisk: %s') % ramdisk_error
        _fail_deploy(task, msg)

    # NOTE(lucasagomes): Let's make sure we don't log the full content
    # of the config drive here because it can be up to 64MB in size,
    # so instead let's log "***" in case config drive is enabled.
    if LOG.isEnabledFor(logging.logging.DEBUG):
        log_params = {
            k: params[k] if k != 'configdrive' else '***'
            for k in params.keys()
        }
        LOG.debug('Continuing deployment for node %(node)s, params %(params)s',
                  {'node': node.uuid, 'params': log_params})

    uuid_dict_returned = {}
    try:
        if node.driver_internal_info['is_whole_disk_image']:
            uuid_dict_returned = deploy_utils.deploy_disk_image(**params)
        else:
            msg = _('Only whole disk image mode is supported')
            raise exception.InstanceDeployFailure(msg)
    except Exception as e:
        msg = (_('Deploy failed for instance %(instance)s. '
                 'Error: %(error)s') %
                 {'instance': node.instance_uuid, 'error': e})
        _fail_deploy(task, msg)

    root_uuid_or_disk_id = uuid_dict_returned.get(
        'root uuid', uuid_dict_returned.get('disk identifier'))
    if not root_uuid_or_disk_id:
        msg = (_("Couldn't determine the UUID of the root "
                 "partition or the disk identifier after deploying "
                 "node %s") % node.uuid)
        _fail_deploy(task, msg)

    destroy_images(node.uuid)
    return uuid_dict_returned

def get_boot_option(node):
    """Gets the boot option.

    :param node: A single Node.
    :raises: InvalidParameterValue if the capabilities string is not a
         dict or is malformed.
    :returns: A string representing the boot option type. Defaults to
        'netboot'.
    """
    capabilities = deploy_utils.parse_instance_info_capabilities(node)
    return capabilities.get('boot_option', 'netboot').lower()


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

    # XXX(jroll) DIB relies on boot_option=local to decide whether or not to
    # lay down a bootloader. Hack this for now; fix it for real in Liberty.
    # See also bug #1441556.
    boot_option = get_boot_option(node)
    if node.driver_internal_info.get('is_whole_disk_image'):
        boot_option = 'netboot'

    deploy_options = {
        'deployment_id': node['uuid'],
        'deployment_key': deploy_key,
        'ironic_api_url': ironic_api,
        'boot_option': boot_option,
        'boot_mode': _get_boot_mode(node),
    }

    return deploy_options


def validate_image_properties(ctx, deploy_info, properties):
    """Validate the image.

    For Glance images it checks that the image exists in Glance and its
    properties or deployment info contain the properties passed. If it's not a
    Glance image, it checks that deployment info contains needed properties.

    :param ctx: security context
    :param deploy_info: the deploy_info to be validated
    :param properties: the list of image meta-properties to be validated.
    :raises: InvalidParameterValue if:
        * connection to glance failed;
        * authorization for accessing image failed;
        * HEAD request to image URL failed or returned response code != 200;
        * HEAD request response does not contain Content-Length header;
        * the protocol specified in image URL is not supported.
    :raises: MissingParameterValue if the image doesn't contain
        the mentioned properties.
    """
    image_href = deploy_info['image_source']
    try:
        img_service = service.get_image_service(image_href, context=ctx)
        image_props = img_service.show(image_href)['properties']
    except (exception.GlanceConnectionFailed,
            exception.ImageNotAuthorized,
            exception.Invalid):
        raise exception.InvalidParameterValue(_(
            "Failed to connect to Glance to get the properties "
            "of the image %s") % image_href)
    except exception.ImageNotFound:
        raise exception.InvalidParameterValue(_(
            "Image %s can not be found.") % image_href)
    except exception.ImageRefValidationFailed as e:
        raise exception.InvalidParameterValue(e)

    missing_props = []
    for prop in properties:
        if not (deploy_info.get(prop) or image_props.get(prop)):
            missing_props.append(prop)

    if missing_props:
        props = ', '.join(missing_props)
        raise exception.MissingParameterValue(_(
            "Image %(image)s is missing the following properties: "
            "%(properties)s") % {'image': image_href, 'properties': props})


def validate(task):
    """Validates the pre-requisites for diskless deploy.

    Validates whether node in the task provided has some ports enrolled.
    This method validates whether conductor url is available either from CONF
    file or from keystone.

    :param task: a TaskManager instance containing the node to act on.
    :raises: InvalidParameterValue if the URL of the Ironic API service is not
             configured in config file and is not accessible via Keystone
             catalog.
    :raises: MissingParameterValue if no ports are enrolled for the given node.
    """
    node = task.node
    if not driver_utils.get_node_mac_addresses(task):
        raise exception.MissingParameterValue(_("Node %s does not have "
                            "any port associated with it.") % node.uuid)

    try:
        # TODO(lucasagomes): Validate the format of the URL
        CONF.conductor.api_url or keystone.get_service_url()
    except (exception.KeystoneFailure,
            exception.CatalogNotFound,
            exception.KeystoneUnauthorized) as e:
        raise exception.InvalidParameterValue(_(
            "Couldn't get the URL of the Ironic API service from the "
            "configuration file or keystone catalog. Keystone error: %s") % e)


def finish_deploy(task, address):
    """Makes the instance active.

    :param task: a TaskManager object.
    :param address: The IP address of the bare metal node.
    :raises: InstanceDeployFailure, if notifying ramdisk failed.
    """
    node = task.node
    try:
        deploy_utils.notify_ramdisk_to_proceed(address)
    except Exception as e:
        LOG.error(_LE('Deploy failed for instance %(instance)s. '
                      'Error: %(error)s'),
                  {'instance': node.instance_uuid, 'error': e})
        msg = (_('Failed to notify ramdisk that deployment is complete.'
                 ' Error: %s') % e)
        deploy_utils.set_failed_state(task, msg)
        raise exception.InstanceDeployFailure(msg)

    LOG.info(_LI('Deployment to node %s done'), node.uuid)
    task.process_event('done')
