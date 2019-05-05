#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

import os
import sys
import StringIO
import traceback
import ipaddress
import ConfigParser
from time import sleep
from datetime import datetime

# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger, logger_config

if sys.version_info >= (3,):
    import io
else:
    import cStringIO

PERMIT = 1
DENY = 0
ADDR_TYPE_IPv4 = 1
ADDR_TYPE_IPv6 = 2
IPv4_UNICAST = 1
VPNv4_UNICAST = 2
IPv6_UNICAST = 3
FRRCFG_FILE = 'frr_json.conf'
frr_cfg = {}

####
CD = os.path.dirname(os.path.realpath(__file__))
pytestini_path = os.path.join(CD, '../pytest.ini')

# Using tmp dir to save temporary files and configurations
tmpdir = "/tmp"

# NOTE: to save execution logs to log file frrtest_log_dir must be configured
# in `pytest.ini`.
config = ConfigParser.ConfigParser()
config.read(pytestini_path)

CONFIG_SECTION = 'topogen'

if config.has_option('topogen', 'verbosity'):
    loglevel = config.get('topogen', 'verbosity')
    loglevel = loglevel.upper()
else:
    loglevel = 'INFO'

if config.has_option('topogen', 'frrtest_log_dir'):
    frrtest_log_dir = config.get('topogen', 'frrtest_log_dir')
    time_stamp = datetime.time(datetime.now())
    logfile_name = "frr_test_bgp_"
    frrtest_log_file = frrtest_log_dir + logfile_name + str(time_stamp)

    logger = logger_config.get_logger(name='test_execution_logs',
                                      log_level=loglevel,
                                      target=frrtest_log_file)
    print("Logs will be sent to logfile: {}".format(frrtest_log_file))

if config.has_option('topogen', 'show_router_config'):
    show_router_config = config.get('topogen', 'show_router_config')
else:
    show_router_config = False


class RoutingPB:
    """Class for saving initial device data"""

    def __init__(self):
        """ 
        Initializatio function for RoutingPB
    * `interfaces_cfg` : interface configuration
    * `static_route` : static routes empty list
    * `prefix_lists` : prefix lists empty list
    * `route_maps` : route maps empty list 
    """

        self.interfaces_cfg = None
        self.static_route = []
        self.prefix_lists = []
        self.route_maps = []


class FRRConfig:
    """Class for initial device configuration and resetting data"""

    def __init__(self, router, routing_cfg_msg, frrcfg_file):
        """ Initialization function for FRR configuration

    * `router`: Device Under Test
        """

        self.router = router
        self.routing_pb = routing_cfg_msg
        self.errors = []
        self.interfaces_cfg = get_StringIO()
        self.routing_common = get_StringIO()
        self.static_routes = get_StringIO()
        self.as_path_prepend = False
        self.access_lists = get_StringIO()
        self.prefix_lists = get_StringIO()
        self.route_maps = get_StringIO()
        self._route_map_seq_id = 0
        self.frrcfg_file = frrcfg_file
        self._community_list_regex_index = 0

    def reset_route_map_seq_id(self):
        """Resets seq id for route map"""
        self._route_map_seq_id = 0

    def reset_it(self):
        """Resets overall configuration on the device"""
        self.errors = []
        self.interfaces_cfg = get_StringIO()
        self.routing_common = get_StringIO()
        self.static_routes = get_StringIO()
        self.as_path_prepend = False
        self.access_lists = get_StringIO()
        self.prefix_lists = get_StringIO()
        self.route_maps = get_StringIO()

    def current_route_map_seq_id(self):
        return self._route_map_seq_id

    def get_route_map_seq_id(self):
        self._route_map_seq_id = self._route_map_seq_id + 10
        return self._route_map_seq_id

    def get_community_list_regex_name(self):
        self._community_list_regex_index = self._community_list_regex_index + 1
        return 'comm-list-regex-' + str(self._community_list_regex_index)

    def print_common_config_to_file(self, topo):
        """
        Writes common configuration to the file.

        * `topo`: Topology data as defined in json file
        """
        try:
            frrcfg = open(self.frrcfg_file, 'w')

            cmd = ['! FRR General Config\n',
                   self.routing_common.getvalue(),
                   '! Interfaces Config\n',
                   self.interfaces_cfg.getvalue(), ]

            # If bgp neighborship is being done using loopback interface -
            # - then loopback interface reachability needs to be there -
            # - for that static routes needs to be added
            device = topo['routers']['{}'.format(self.router)]
            if "bgp" in device:
                neighbors = device["bgp"]['bgp_neighbors']
                for key in neighbors.keys():
                    peer = neighbors[key]['peer']
                    if "source_link" in peer and peer['source_link'] == 'lo':
                        add_static_route_for_loopback_interfaces(topo,
                                                                 self.router, frrcfg)

            cmd.extend(['! Static Route Config\n',
                        self.static_routes.getvalue(),
                        '! Access List Config\n',
                        self.access_lists.getvalue(),
                        '! Prefix List Config\n',
                        self.prefix_lists.getvalue(),
                        '! Route Maps Config\n',
                        self.route_maps.getvalue(),
                        'line vty\n'])
            frrcfg.writelines(cmd)

        except IOError as err:
            logger.error('Unable to open FRR Config File. error(%s): %s' %
                         (err.errno, err.strerror))
            return False
        finally:
            frrcfg.close()

        return True


def create_common_configuration(tgen, topo, addr_type, router):
    """
    API to create object of class FRRConfig and also create frr_json.conf
    file. It will create interface and common configurations and save it to
    frr_json.conf and load to router

    Parameters
    ----------
    * `tgen`: tgen onject 
    * `topo` : json file data
    * `addr_type`: ip address type ipv4/6 
    * `router` : router for which bgp config should be created

    Returns
    -------
    errormsg(str) or object of FRRConfig class which has interface
    and common configuration
    """

    try:
        global frr_cfg
        listRouters = []
        for routerN in topo['routers'].iteritems():
            listRouters.append(routerN[0])

        listRouters.sort()

        for curRouter in listRouters:
            if curRouter != router:
                continue

            rt_cfg = RoutingPB()
            fname = '{}/{}/{}'.format(tmpdir, router, FRRCFG_FILE)
            frr_cfg[router] = FRRConfig(router, rt_cfg, fname)

            input_dict = topo['routers']
            if 'links' in topo['routers'][router]:
                frr_cfg[router].routing_pb.interfaces_cfg = \
                    create_interfaces_cfg(topo, router)
                interfaces_cfg(frr_cfg[router])
                frr_cfg[router].print_common_config_to_file(topo)
                # Load configuration to router
                load_config_to_router(tgen, router)

            if 'static_routes' in topo['routers'][router]:
                result = create_static_routes(tgen, topo, addr_type, input_dict)
                assert result is True, ("API: create_static_routes() :Failed"
                                        " \n Error: {}".format(result))

            if 'prefix_lists' in topo['routers'][router]:
                result = create_prefix_lists(tgen, topo, addr_type, input_dict)
                assert result is True, ("API: create_prefix_lists() :Failed "
                                        "\n Error: {}".format(result))

            if 'route_maps' in topo['routers'][router]:
                result = create_route_maps(tgen, topo, addr_type, input_dict)
                assert result is True, ("API: create_route_maps() :Failed"
                                        " \n Error: {}".format(result))

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return True


#############################################
# Helper classes to save configuration
#############################################

class Interface:
    """Class for interface configuration"""

    def __init__(self, interface_name, interface_ip_addresses):
        """
        Initialization function for interface configuration
    
            Parameters
            ----------
        * `interface_name` : name of interface
        * `interface_ip_addresses` : ip address of interface
    
        """
        self.interface_name = interface_name
        self.interface_ip_addresses = interface_ip_addresses


class Interfaces:
    """Class for maintaining list of Interface type objects"""

    def __init__(self):
        """ Initializatio function for Interface configuration"""
        self.interfaces = []

    def add_interface(self, interface_name, interface_ip_addresses):
        """
        Adds interface object to the list, if not present.

    Parameters
    ----------
        * `interface_name` : Name of the interface
        * `interface_ip_addresses` : Ip address to be associated with interface
        """

        for intf in self.interfaces:
            if intf.interface_name == interface_name:
                intf.interface_ip_address.append(interface_ip_addresses)
                return

        interface = Interface(interface_name, interface_ip_addresses)
        self.interfaces.append(interface)


def _print_interfaces_cfg(frr_cfg, interface):
    """
    Prints interface config to frr_json.conf file 

    Parameters
    ----------
    * `frr_cfg` : file hander to frr_json.conf file
    * `interface` : interface ip addresss
    """

    interface_name = interface.interface_name
    interface_ip_addresses = interface.interface_ip_addresses
    cmd = ['interface {}\n'.format(str(interface_name))]
    for address in interface_ip_addresses:
        if '::' in address:
            cmd.append('ipv6 address {}\n'.format(str(address)))
        else:
            cmd.append('ip address {}\n'.format(str(address)))
    frr_cfg.interfaces_cfg.writelines(cmd)


def interfaces_cfg(frr_cfg):
    """Handlers for printing interface data"""
    ifaces = frr_cfg.routing_pb.interfaces_cfg
    for interface in ifaces.interfaces:
        _print_interfaces_cfg(frr_cfg, interface)


class Nexthop:
    """Class for nexthop configuration

    Parameters
    ---------- 
    * `ip`: Addresss for next-hop
    * `blackhole`: Nexthop is a black hole or not, default: False
    * `admin_distance`: Distance for the next-hop, default: 1
    * `if_name`: Interface name to reach next-hop 
    * `tag: tag name for static route
    """

    def __init__(self, ip, blackhole=False, admin_distance=1,
                 if_name=None, tag=None):
        """ Initialization function for Next hop configuration"""
        self.ip = ip
        self.blackhole = blackhole
        self.admin_distance = admin_distance
        self.if_name = if_name
        self.tag = tag


# Helper 
class Route:
    """Class to add static route for ip-prefix"""

    def __init__(self, prefix):
        """ Initialization function for Route configuration"""
        self.prefix = prefix
        self.nexthops = []

    def add_nexthop(self, ip, blackhole=None, admin_distance=None,
                    if_name=None, tag=None):
        """
        Adds Nexthop instance to the list

    Parameters
    ----------
        * `ip`: Addresss for next-hop
        * `blackhole`: Nexthop is a black hole or not
        * `admin_distance`: Distance for the next-hop
        * `if_name`: Interface name to reach next-hop 
        * `tag: tag name for static route
        """
        nhop = Nexthop(ip, blackhole, admin_distance, if_name, tag)
        self.nexthops.append(nhop)


def static_rt_nh(nh):
    """
    Takes Nexthop object and returns formatted values

    * `nh`: Nexthop instance 

    Returns:
    nexthop: ip address, admin_dist: int, tag: int 
    """

    nexthop = ''
    admin_dist = '1'
    tag = None
    if nh.ip:
        nexthop = IpAddressMsg_to_str(nh.ip)
    elif nh.blackhole:
        nexthop = 'blackhole'
    if nh.if_name:
        nexthop = nexthop + ' ' + nh.if_name
    if nh.admin_distance > 0:
        admin_dist = str(nh.admin_distance)
    if nh.tag:
        tag = nh.tag
    return nexthop, admin_dist, tag


def static_rt_cfg(frr_cfg):
    """
    Handler for writing static route configuration

    * `frr_cfg`: File object for frr configuration
    """
    if frr_cfg.routing_pb.static_route is None:
        return
    for st in frr_cfg.routing_pb.static_route:
        prefix = IpAddressMsg_to_str(st.prefix)
        addr_type = st.prefix.afi
        ip_cmd = get_ip_cmd(addr_type)
        for nh in st.nexthops:
            nexthop, admin_dist, tag = static_rt_nh(nh)

            if tag is None:
                frr_cfg.static_routes.write('{} route {} {} {} \n'.
                                            format(ip_cmd, prefix, nexthop,
                                                   admin_dist))
            else:
                frr_cfg.static_routes.write('{} route {} {} tag {} {}\n'.
                                            format(ip_cmd, prefix, nexthop,
                                                   str(tag), admin_dist))


class Network:
    """Class to define Network details"""

    def __init__(self, afi, ipv4=None, ipv6=None, prefix_length=None):
        """
        Initialization function for Network configuration
    
        Parameters
        ----------
        * `afi` : address family identifier
        * `ipv4` : address type ipv4
        * `ipv6` : address type ipv6
        * `prefix_length` : prefix length
        """

        self.afi = afi
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.prefix_length = prefix_length


class Address:
    """Class for Address type configuration"""

    def __init__(self, afi, ipv4=None, ipv6=None):
        """
        Initialization function for Address family config
    
            Parameters
            ----------
            * `afi` : address family identifier
            * `ipv4` : address type ipv4
            * `ipv6` : address type ipv6
        """

        self.afi = afi
        self.ipv4 = ipv4
        self.ipv6 = ipv6


# Helper class for IP Prefix list configuration
class Pfx:
    """Class for IP Prefix list configuration"""

    def __init__(self, less_or_equal_bits=None, greater_or_equal_bits=None,
                 action=None, network=None, seqid=None):
        """
        Initialization function for prefix list config

        Parameters
        ----------
        * `less_or_equal_bits` : less or equal bits
        * `greater_or_equal_bits` : greater or equal bits
        * `action` : prefix list action, permit/deny
        * `network` : network to be permit/deny in prefix list
        * `seqid` : prefix list sequence id
        """

        self.less_or_equal_bits = less_or_equal_bits
        self.greater_or_equal_bits = greater_or_equal_bits
        self.action = action
        self.network = network
        self.seq_id = seqid


class PrefixList:
    """Class to save list of Pfx instances"""

    def __init__(self, name):
        self.prefix_list_uuid_name = name
        self.prefix = []

    def add_pfx(self, pfx):
        self.prefix.append(pfx)


def prefixlist_cfg(frr_cfg, addr_type):
    """
    Handler for writing prefix-list configuriation

    * `frr_cfg`: File object for frr configuration
    * `addr_type`: ip type ipv4/ipv6
    """
    if frr_cfg.routing_pb.prefix_lists is None:
        return
    for prefixlist in frr_cfg.routing_pb.prefix_lists:
        name = prefixlist.prefix_list_uuid_name
        for prefix in prefixlist.prefix:
            le_ge = ""

            if prefix.network is not None:
                if (prefix.less_or_equal_bits and
                        prefix.network.prefix_length <=
                        prefix.less_or_equal_bits):
                    le_ge = "{} le {}".format(
                        le_ge, str(prefix.less_or_equal_bits))

                if (prefix.greater_or_equal_bits and
                        prefix.greater_or_equal_bits >=
                        prefix.network.prefix_length):
                    le_ge = "{} ge {}".format(
                        le_ge, str(prefix.greater_or_equal_bits))

                network = IpPrefixMsg_to_str(prefix.network)
                ip_cmd = get_ip_cmd(prefix.network.afi)
                cmd = '{} prefix-list {} seq {} {} {} {}\n'.format(
                    ip_cmd, name, str(prefix.seq_id), prefix.action, network,
                    le_ge)
            else:
                network = 'any'
                if addr_type == "ipv4":
                    cmd = 'ip prefix-list {} seq {} {} {}\n'.format(
                        name, str(prefix.seq_id), prefix.action, network)
                else:
                    cmd = 'ipv6 prefix-list {} seq {} {} {}\n'.format(
                        name, str(prefix.seq_id), prefix.action, network)

            frr_cfg.prefix_lists.write(cmd)


class RouteMapMatch:
    """Class for route-map configuration"""

    def __init__(self):
        self.tag = None
        self.match_exact = None
        self.prefix_list = []
        self.community_list = []
        self.large_community_list = []

    def add_prefix_list(self, prefix_list):
        self.prefix_list.append(prefix_list)

    def add_community_list(self, community_list):
        self.community_list.append(community_list)

    def add_large_community_list(self, large_community_list):
        self.large_community_list.append(large_community_list)


class RouteMapSet:
    """
    Class for 'set' configuration in route-map

    Parameters
    ----------
    * `local_preference`:
    * `metric`:
    * `as_path_prepend`: to prepend as-path, default: False
    * `community`: configure the community value
    * `community_additive`: whether community/larg-communiy value to be added
    * `weight`: weight
    * `large_community`: confgiure large-community value
    * `set_action`: 
    * `med`:
    """

    def __init__(self, local_preference=None, metric=None,
                 as_path_prepend=False, community=None,
                 community_additive=None, weight=None, large_community=None,
                 set_action=None, med=None):
        """ Initialization function for Route map set config"""

        self.local_preference = local_preference
        self.metric = metric
        self.as_path_prepend = as_path_prepend
        self.community = community
        self.community_additive = community_additive
        self.weight = weight
        self.large_community = large_community
        self.set_action = set_action
        self.med = med


class RouteMapSeq:
    """Class for route-map data"""

    def __init__(self, match, action, route_map_set):
        """
        Initialization function for RouteMapSeq
    
        Parameters
        ----------
        * `match` : route-map match clause
        * `action` : route-map action, permit/deny
        * `route_map_set` : route-map set clause
        """

        self.match = match
        self.action = action
        self.route_map_set = route_map_set


class RouteMap:
    """Class for keeping list of RouteMapSeq instances"""

    def __init__(self, name):
        self.route_map_uuid_name = name
        self.route_map_seq = []

    def add_seq(self, match, action, route_map_set):
        """ To add route-map new sequences """
        rmap_seq = RouteMapSeq(match, action, route_map_set)
        self.route_map_seq.append(rmap_seq)


def get_action_from_route_map_seq(route_map_seq):
    """Returns action type for route map"""
    if route_map_seq.action == PERMIT:
        return 'permit'
    else:
        return 'deny'


def route_map_set_cfg(frr_cfg, route_map_set):
    """
    Handler for writing route-map configuration

    * `frr_cfg: file object for frr configuration
    * `route_map_set: route-map object
    """
    # community_additive
    cmd = []
    additive = ''
    if route_map_set.community_additive:
        additive = 'additive'

    # Local Preference
    if route_map_set.local_preference:
        cmd.extend('set local-preference {} \n'.format(
            str(route_map_set.local_preference)))

    # Metric
    if route_map_set.metric:
        cmd.extend('set metric {} \n'.format(str(route_map_set.metric)))

    # AS Path Prepend
    if route_map_set.as_path_prepend:
        cmd.extend('set asp-path prepend {} \n'.format(
            route_map_set.as_path_prepend))

    # Community
    if route_map_set.community:
        cmd.extend('set community {} {} {} \n'.format(
            route_map_set.community, additive, route_map_set.set_action))

    # Large-Community with delete
    if route_map_set.set_action and route_map_set.set_action == "delete":
        if route_map_set.large_community:
            cmd.extend('set large-comm-list {} {}\n'.format(
                route_map_set.large_community, route_map_set.set_action))
    else:
        # Large-Community
        if route_map_set.large_community:
            cmd.extend('set large-community {} {} \n'.format(
                route_map_set.large_community, additive))

    # Weight
    if route_map_set.weight:
        cmd.extend('set weigh {}'.format(str(route_map_set.weight)))

    frr_cfg.route_maps.write(cmd)


def handle_route_map_seq_set(frr_cfg, route_map_seq):
    """ To configure route-map set clause """

    if route_map_seq.route_map_set:
        route_map_set_cfg(frr_cfg, route_map_seq.route_map_set)


def handle_match_prefix_list(frr_cfg, routemap, route_map_seq, addr_type):
    """ Configure route-map to match prefix-lists """

    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)
    cmd = []
    seq_id = frr_cfg.get_route_map_seq_id()
    cmd.extend('route-map {} {} {}\n'.format(name, action, str(seq_id)))

    if addr_type == 'ipv4':
        protocol = 'ip'
    else:
        protocol = 'ipv6'

    # MATCH
    for prefix_list in route_map_seq.match.prefix_list:
        cmd.extend('match {} address prefix-list {}\n'.format(
            protocol, prefix_list.prefix_list_uuid_name))
    # SET
    handle_route_map_seq_set(frr_cfg, route_map_seq)
    cmd.extend('! END of {} - {}\n'.format(name, str(seq_id)))

    frr_cfg.route_maps.write(cmd)


def handle_match_tag(frr_cfg, routemap, route_map_seq, addr_type):
    """ Configure route-map to match tag """

    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)

    seq_id = frr_cfg.get_route_map_seq_id()
    cmd = ['route-map {} {} {}\n'.format(name, action, str(seq_id))]
    cmd.extend('match tag {}\n'.format(str(route_map_seq.match.tag)))
    # SET
    handle_route_map_seq_set(frr_cfg, route_map_seq)
    cmd.extend('! END of {} - {}\n'.format(name, str(seq_id)))

    frr_cfg.route_maps.write(cmd)


def handle_match_community_list(frr_cfg, routemap, route_map_seq, addr_type):
    """ Configure route-map to match community-lists """

    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)
    # MATCH
    cmd = []
    for community in route_map_seq.match.community_list:
        # IPv4
        seq_id = frr_cfg.get_route_map_seq_id()
        cmd.extend('route-map {} {} {}\n'.format(name, action, str(seq_id)))
        cmd.extend('match community {}\n'.format(community))
        # SET
        handle_route_map_seq_set(frr_cfg, route_map_seq)
        cmd.extend('! END of {} - {}\n'.format(name, str(seq_id)))

    frr_cfg.route_maps.write(cmd)


def handle_match_large_community_list(frr_cfg, routemap, route_map_seq,
                                      addr_type):
    """ Configure route-map to match large-community-lists """

    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)
    # MATCH
    cmd = []
    for community in route_map_seq.match.large_community_list:
        # IPv4
        seq_id = frr_cfg.get_route_map_seq_id()
        cmd.extend('route-map {} {} {}\n'.format(name, action, str(seq_id)))

        # Match-exact case
        if route_map_seq.match.match_exact != None:
            cmd.extend('match large-community {} exact-match \n'. \
                       format(community))
        else:
            cmd.extend('match large-community {}\n'.format(community))

        # SET
        handle_route_map_seq_set(frr_cfg, route_map_seq)
        cmd.extend('! END of {} - {}\n'.format(name, str(seq_id)))

    frr_cfg.route_maps.write(cmd)


def handle_no_match_set_only(frr_cfg, routemap, route_map_seq):
    """ Configure route-map with set only, no match clause """

    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)
    seq_id = frr_cfg.get_route_map_seq_id()
    cmd = ['route-map {} {} {}\n'.format(name, action, str(seq_id))]
    # SET
    handle_route_map_seq_set(frr_cfg, route_map_seq)
    cmd.extend('! END of {} - {}\n'.format(name, str(seq_id)))
    frr_cfg.route_maps.write(cmd)


def routemap_cfg(frr_cfg, addr_type):
    """ Route-map configuration handler """

    if frr_cfg.routing_pb.route_maps is None:
        return
    for routemap in frr_cfg.routing_pb.route_maps:
        for route_map_seq in routemap.route_map_seq:
            # No Match - Only Set
            if route_map_seq.match is None:
                handle_no_match_set_only(frr_cfg, routemap, route_map_seq)
            else:
                # Match by Prefix List
                if len(route_map_seq.match.prefix_list) > 0:
                    handle_match_prefix_list(frr_cfg, routemap, route_map_seq,
                                             addr_type)
                # Match by tag
                elif route_map_seq.match.tag:
                    handle_match_tag(frr_cfg, routemap, route_map_seq,
                                     addr_type)
                # Match by Community
                elif len(route_map_seq.match.community_list) > 0:
                    handle_match_community_list(frr_cfg, routemap,
                                                route_map_seq, addr_type)
                # Match by large-Community
                elif len(route_map_seq.match.large_community_list) > 0:
                    handle_match_large_community_list(frr_cfg, routemap,
                                                      route_map_seq, addr_type)


#############################################
# Common APIs, will be used by all protocols
#############################################
def get_StringIO():
    """Returns StringIO to be used"""
    if sys.version_info >= (3,):
        return io.StringIO()
    else:
        return cStringIO.StringIO()


def get_address_family(addr_family):
    """
    Returns address family as per the input address family type

    * "addr_family": address family type IPv4_UNICAST/IPv6_UNICAST/
                     VPNv4_UNICAST
    """
    if addr_family == IPv4_UNICAST:
        return 'ipv4 unicast'
    if addr_family == IPv6_UNICAST:
        return 'ipv6 unicast'
    if addr_family == VPNv4_UNICAST:
        return 'ipv4 vpn'
    assert 'Unknown address family'


def get_ip_cmd(addr_type):
    """
    Returns ip for ipv4 and ipv6 for ipv6 address as command address

    * "addr_type": ip type ipv4/ipv6
    """
    if addr_type == ADDR_TYPE_IPv4:
        return 'ip'
    else:
        return 'ipv6'


def IpPrefixMsg_to_str(addr, subnet=True):
    """
    Converts ip address to str with attaching mask to ip address

    * "addr": ip type ipv4/ipv6
    """
    ip_string = ''
    ip_string = IpAddressMsg_to_str(addr)
    if subnet and addr.prefix_length:
        ip_string = ip_string + '/' + str(addr.prefix_length)
    return ip_string


def IpAddressMsg_to_str(addr):
    """
    Returns Ip address to str as per the input ip type

    * "addr": ip type ipv4/ipv6
    """

    if addr.afi == ADDR_TYPE_IPv4:
        return addr.ipv4
    else:
        return addr.ipv6


def number_to_row(routerName):
    """
    Returns the number for the router.
    Calculation based on name a0 = row 0, a1 = row 1, b2 = row 2, z23 = row 23
    etc
    """
    return int(routerName[1:])


def number_to_column(routerName):
    """
    Returns the number for the router.
    Calculation based on name a0 = columnn 0, a1 = column 0, b2= column 1,
    z23 = column 26 etc
    """
    return ord(routerName[0]) - 97


def generate_ips(addr_type, start_ip, no_of_ips):
    """
    Returns list of IPs.
    based on start_ip and no_of_ips

    * `addr_type` : to identify ip address type ex- ipv4/ipv6
    * `start_ip`  : from here the ip will start generating, start_ip will be
                    first ip
    * `no_of_ips` : these many IPs will be generated

    Limitation: It will generate IPs only for ip_mask 32

    """

    if '/' in start_ip:
        start_ip = start_ip.split("/")[0]

    if addr_type == 'ipv4':
        start_ip = ipaddress.IPv4Address(unicode(start_ip))
    else:
        start_ip = ipaddress.IPv6Address(unicode(start_ip))
    ipaddress_list = [start_ip]
    next_ip = start_ip
    count = 1
    while count <= no_of_ips:
        next_ip += 1
        ipaddress_list.append(next_ip)
        count += 1

    return ipaddress_list


def find_interface_with_greater_ip(topo, router):
    """
    Returns highest interface ip for ipv4/ipv6. If loopback is there then
    it will return highest IP from loopback IPs otherwise from physical
    interface IPs.

    * `topo`  : json file data
    * `router` : router for which hightest interface should be calculated
    """

    link_data = topo['routers'][router]['links']
    lo_list = []
    interfaces_list = []
    lo_exists = False
    for destRouterLink, data in sorted(link_data.iteritems()):
        if 'type' in data and data['type'] == 'loopback':
            lo_exists = True
            ip_address = topo['routers'][router]['links'][
                destRouterLink]['ipv4'].split('/')[0]
            lo_list.append(ip_address)
        else:
            ip_address = topo['routers'][router]['links'][
                destRouterLink]['ipv4'].split('/')[0]
            interfaces_list.append(ip_address)
    
    if lo_exists:
        return sorted(lo_list)[-1]
    
    return sorted(interfaces_list)[-1]


def start_topology(tgen):
    """
    Starting topology, create tmp files which are loaded to routers
    to start deamons and then start routers

    * `tgen`  : topogen object
    """

    # Starting topology
    tgen.start_topology()

    # Starting deamons
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        try:
            os.chdir(tmpdir)
            # Deleting router named dirs if exists
            if os.path.exists('{}'.format(rname)):
                os.system("rm -rf {}".format(rname))

            # Creating rouer named dir and empty zebra.conf bgpd.conf files
            # inside the current directory
            os.mkdir('{}'.format(rname))
            os.chdir('{}/{}'.format(tmpdir, rname))
            os.system('touch zebra.conf bgpd.conf')

        except IOError as (errno, strerror):
            logger.error("I/O error({0}): {1}".format(errno, strerror))

        # Loading empty zebra.conf file to router, to start the zebra deamon
        router.load_config(
            TopoRouter.RD_ZEBRA,
            '{}/{}/zebra.conf'.format(tmpdir, rname)
            # os.path.join(tmpdir, '{}/zebra.conf'.format(rname))
        )
        # Loading empty bgpd.conf file to router, to start the bgp deamon
        router.load_config(
            TopoRouter.RD_BGP,
            '{}/{}/bgpd.conf'.format(tmpdir, rname)
            # os.path.join(tmpdir, '{}/bgpd.conf'.format(rname))
        )

    # Starting routers
    logger.info("Starting all routers once topology is created")
    tgen.start_router()


def stop_topology(tgen):
    """
    It will stop topology and remove temporary dirs and files.

    * `tgen`  : topogen object
    """

    # This function tears down the whole topology.
    tgen.stop_topology()

    # Removing tmp dirs and files, once the topology is deleted
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        try:
            os.chdir(tmpdir)
            os.system("rm -rf {}".format(rname))
        except IOError as (errno, strerror):
            logger.error("I/O error({0}): {1}".format(errno, strerror))


def stop_router(tgen, router):
    """
    Router's current config would be saved to /etc/frr/ for each deamon
    and router and its deamons would be stopped.

    * `tgen`  : topogen object
    * `router`: Device under test
    """

    router_list = tgen.routers()

    # Saving router config to /etc/frr, which will be loaded to router
    # when it starts
    router_list[router].vtysh_cmd("write memory")

    # Stop router
    router_list[router].stop()


def start_router(tgen, router):
    """
    Router will started and config would be loaded from /etc/frr/ for each
    deamon

    * `tgen`  : topogen object
    * `router`: Device under test
    """

    router_list = tgen.routers()

    # Router and its deamons would be started and config would be loaded to 
    # for each deamon from /etc/frr
    router_list[router].start()


def load_config_to_router(tgen, routerName):
    """
    Delta will be created between router's running config and user defined 
    config. Delta would be loaded to router using /usr/lib/frr/frr-reload.py
    utility

    Parameters 
    ----------
    * `tgen` : Topogen object
    * `routerName` : router for which delta config should be generated and
                     uploaded
    """

    logger.info('Entering API: load_common_config_to_router')

    try:
        router_list = tgen.routers()
        for rname, router in router_list.iteritems():
            if rname == routerName:

                cfg = router.run("vtysh -c 'show running'")
                fname = '{}/{}/frr.sav'.format(tmpdir, rname)
                dname = '{}/{}/delta.conf'.format(tmpdir, rname)
                f = open(fname, 'w')
                for line in cfg.split('\n'):
                    line = line.strip()

                    if (line == 'Building configuration...' or
                            line == 'Current configuration:' or
                            not line):
                        continue
                    f.write(line)
                    f.write('\n')

                f.close()

                try:
                    filenames = ['bgp_json.conf', 'frr_json.conf']
                    with open('{}/{}/frr.conf'.format(tmpdir, rname), 'w') as cfg:
                        for f_name in filenames:
                            if os.path.exists(
                                    '{}/{}/{}'.format(tmpdir, rname, f_name)):
                                with open('{}/{}/{}'.\
                                    format(tmpdir, rname, f_name), 'r') as \
                                           infile:
                                    for line in infile:
                                        cfg.write(line)
                except IOError as err:
                    logger.warning('Unable to open config File. error(%s): %s'
                                   % (err.errno, err.strerror))
                    return False

                command = '/usr/lib/frr/frr-reload.py  --input {}/{}/frr.sav' \
                          ' --test {}/{}/frr.conf > {}'.\
                          format(tmpdir, rname, tmpdir, rname, dname)
                result = os.system(command)

                # Assert if command fail
                if result != 0:
                    command_output = False
                    assert command_output, ('Command:{} is failed due to '
                                            'non-zero exit code'.\
                                            format(command))

                f = open(dname, 'r')
                delta = StringIO.StringIO()
                delta.write('configure terminal\n')
                t_delta = f.read()
                for line in t_delta.split('\n'):
                    line = line.strip()
                    if (line == 'Lines To Delete' or
                            line == '===============' or
                            line == 'Lines To Add' or
                            line == '============' or
                            not line):
                        continue
                    delta.write(line)
                    delta.write('\n')

                delta.write('end\n')
                router.vtysh_multicmd(delta.getvalue())
                logger.info('New configuration for router {}:'.format(rname))
                delta.close()
                delta = StringIO.StringIO()
                cfg = router.run("vtysh -c 'show running'")
                for line in cfg.split('\n'):
                    line = line.strip()
                    delta.write(line)
                    delta.write('\n')

                # Router current configuration to log file or console if
                # "show_router_config" is defined in "pytest.ini"
                if show_router_config:
                    logger.info(delta.getvalue())
                delta.close()

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info('Exting API: load_common_config_to_router')
    return True


#############################################
# These APIs,  will used by testcase
#############################################
def create_interfaces_cfg(topo, curRouter):
    """ 
    Create interface configuration for created topology and
    save the configuration to frr.conf file. Basic Interface configuration
    is provided in input json file.

    Parameters
    ----------
    * `topo` : json file data
    * `curRouter` : router for which interface config should be created

    Returns
    -------
    interfaces config or False
    """

    try:
        interfaces = Interfaces()
        c_router = topo['routers'][curRouter]
        for destRouterLink, data in sorted(c_router['links'].iteritems()):
            # Loopback interfaces
            if 'type' in data and data['type'] == 'loopback':
                interface_name = destRouterLink
                lo_addresses = []
                if 'ipv4' in c_router['links'][destRouterLink]:
                    lo_addresses.append(c_router['links'][destRouterLink]['ipv4'])
                if 'ipv6' in c_router['links'][destRouterLink]:
                    lo_addresses.append(c_router['links'][destRouterLink]['ipv6'])
                interfaces.add_interface(interface_name, lo_addresses)
            else:
                interface_name = c_router['links'][destRouterLink]['interface']
                int_addresses = []
                if 'ipv4' in c_router['links'][destRouterLink]:
                    int_addresses.append(c_router['links'][destRouterLink]['ipv4'])
                if 'ipv6' in c_router['links'][destRouterLink]:
                    int_addresses.append(c_router['links'][destRouterLink]['ipv6'])
                interfaces.add_interface(interface_name, int_addresses)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return interfaces


def add_static_route_for_loopback_interfaces(topo, curRouter, frrcfg):
    """
    Add static routes for loopback interfaces reachability, It will add static
    routes in current router for other router's loopback interfaces os the
    reachability will be up and so will BGP neighborship.

    Parameters
    ----------
    * `topo` : json file data
    * `curRouter` : Device Under Test
    * `frrcfg` : frr config file handler
    """

    bgp_neighbors = topo['routers'][curRouter]['bgp']['bgp_neighbors']
    for bgp_neighbor in bgp_neighbors.keys():
        add_static_route = False
        for destRouterLink, data2 in sorted(topo['routers']\
                                            [bgp_neighbor]['links'].iteritems()):
            # IPv4
            if 'ipv4' in data2:
                if 'type' in data2 and data2['type'] == 'loopback':
                    if 'add_static_route' in data2 and data2 \
                            ['add_static_route'] == "yes":
                        add_static_route = True
                        # Loopback interfaces
                        lo_ipv4_addr = topo['routers'][bgp_neighbor] \
                            ['links'][destRouterLink]['ipv4']

                # Next hop address
                if curRouter in destRouterLink:
                    ipv4_next_hop = topo['routers'][bgp_neighbor]['links'] \
                        [destRouterLink]['ipv4'].split("/")[0]

                    if add_static_route:
                        frrcfg.write("ip route " + lo_ipv4_addr + " " +
                                     ipv4_next_hop + "\n")
            # IPv6
            if 'ipv6' in data2:
                if 'type' in data2 and data2['type'] == 'loopback':
                    if 'add_static_route' in data2 and data2 \
                            ['add_static_route'] == "yes":
                        add_static_route = True
                        # Loopback interfaces
                        lo_ipv6_addr = topo['routers'][bgp_neighbor] \
                            ['links'][destRouterLink]['ipv6']

                # Next hop address
                if curRouter in destRouterLink:
                    ipv6_next_hop = topo['routers'][bgp_neighbor]['links'] \
                        [destRouterLink]['ipv6'].split("/")[0]

                    if add_static_route:
                        frrcfg.write("ipv6 route " + lo_ipv6_addr + " " +
                                     ipv6_next_hop + "\n")


def create_static_routes(tgen, topo, addr_type, input_dict):
    """
    Create static routes for given router as defined in input_dict

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `addr_type` : ip type, ipv4/ipv6
    * `input_dict` : input to create static routes for given router

    Usage
    -----
    input_dict should be in the format below:
    # static_routes: list of all routes
    # network: network address
    # no_of_ip: number of next-hop address that will be configured
    # admin_distance: admin distance for route/routes.
    # next_hop: starting next-hop address
    # tag: tag id for static routes

    Example:
    "routers": {
        "r1": {
            "static_routes": [
                {
                    "network": "100.0.20.1/32",
                    "no_of_ip": 9,
                    "admin_distance": 100,
                    "next_hop": "10.0.0.1",
                    "tag": 4001
                }
            ]
        }
    }

    Returns
    -------
    errormsg(str) or True
    """

    try:
        global frr_cfg
        for router in input_dict.keys():
            if "static_routes" in input_dict[router]:
                static_routes_list = []

                # Reset config for routers
                frr_cfg[router].reset_it()

                static_routes = input_dict[router]["static_routes"]
                for static_route in static_routes:
                    network = static_route["network"]
                    # No of IPs
                    if "no_of_ip" in static_route:
                        no_of_ip = static_route["no_of_ip"]
                    else:
                        no_of_ip = 0

                    if "admin_distance" in static_route:
                        admin_distance = static_route["admin_distance"]
                    else:
                        admin_distance = 1

                    if "tag" in static_route:
                        tag = static_route["tag"]
                    else:
                        tag = None

                    if "if_name" in static_route:
                        if_name = static_route["if_name"]
                    else:
                        if_name = None

                    next_hop = static_route["next_hop"]

                    ip_list = generate_ips(addr_type, network, no_of_ip)
                    for ip in ip_list:
                        ip = str(ipaddress.ip_network(unicode(ip)))
                        if addr_type == "ipv4":
                            addr = Address(ADDR_TYPE_IPv4, ip, None)
                            route = Route(addr)
                            nh = Address(ADDR_TYPE_IPv4, next_hop, None)
                        else:
                            addr = Address(ADDR_TYPE_IPv6, None, ip)
                            route = Route(addr)
                            nh = Address(ADDR_TYPE_IPv6, None, next_hop)
                        route.add_nexthop(nh, None, admin_distance, if_name,
                                          tag)

                        static_routes_list.append(route)
                        frr_cfg[router].routing_pb.static_route = \
                            static_routes_list

                interfaces_cfg(frr_cfg[router])
                static_rt_cfg(frr_cfg[router])
                frr_cfg[router].print_common_config_to_file(topo)
                # Load configuration to router
                load_config_to_router(tgen, router)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return True


def modify_admin_distance_for_static_routes(tgen, topo, input_dict):
    """
    Modify admin distance for given static route/s

    Parameters
    ----------
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` :  static route/s and admin distance to be modified

    Usage
    -----
    # 10.0.20.1/32: network address for which ad needs to be modified
    # admin_distance: Admin distance value for the network
    # next_hop: next-hop ip to reach the network

    Example
    -------
    input_dict = {
        'r1': {
            '10.0.20.1/32':{
                'admin_distance': 10,
                'next_hop': '10.0.0.2'
            }
        }
    }

    Returns
    -------
    errormsg(str) or True
    """
    logger.info("Entering lib API: modify_admin_distance_for_static_routes()")

    try:
        for router in input_dict.keys():
            # Reset config for routers
            frr_cfg[router].reset_it()

            for static_route in input_dict[router].keys():
                next_hop = input_dict[router][static_route]['next_hop']
                admin_distance = input_dict[router][static_route][
                    'admin_distance']

                for st in frr_cfg[router].routing_pb.static_route:
                    st_ip_prefix = IpAddressMsg_to_str(st.prefix)
                    for nh in st.nexthops:
                        if st_ip_prefix == static_route and \
                                IpAddressMsg_to_str(nh.ip) == next_hop:
                            nh.admin_distance = admin_distance

            interfaces_cfg(frr_cfg[router])
            static_rt_cfg(frr_cfg[router])
            frr_cfg[router].print_common_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, router)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_admin_distance_for_static_routes")
    return True


def create_prefix_lists(tgen, topo, addr_type, input_dict):
    """
    Create ip prefix lists as per the config provided in input 
    JSON or input_dict

    Parameters
    ----------
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `addr_type`  : ip_type, ipv4/ipv6
    * `input_dict` :  data to create prefix lists

    Usage
    -----
    # pf_lists_1: name of prefix-list, user defined
    # seqid: prefix-list seqid, auto-generated if not given by user
    # network: criteria for applying prefix-list
    # action: permit/deny
    # le: less than or equal number of bits
    # ge: greater than or equal number of bits

    Example
    -------
    input_dict = {
        'r1': {
            'prefix_lists':{
                'pf_list_1': [
                    {
                        'seqid': 10,
                        'network': 'any',
                        'action': 'permit',
                        'le': '32',
                        'ge': '30'
                    }
                ]
            }
        }
    }

    Returns
    -------
    errormsg or True
    """

    logger.info("Entering lib API: create_prefix_lists()")

    try:
        for router in input_dict.keys():
            if "prefix_lists" in input_dict[router]:
                # Reset config for routers
                frr_cfg[router].reset_it()

                for prefix_name, prefix_list in \
                        input_dict[router]['prefix_lists'].iteritems():
                    for prefix_dict in prefix_list:
                        network_addr = prefix_dict['network']
                        action = prefix_dict['action']
                        if 'le' in prefix_dict:
                            le = prefix_dict['le']
                        else:
                            le = None

                        if 'ge' in prefix_dict:
                            ge = prefix_dict['ge']
                        else:
                            ge = None

                        if 'seqid' in prefix_dict:
                            seqid = prefix_dict['seqid']
                        else:
                            seqid = None

                        if network_addr != 'any':
                            # IP from network, removing mask
                            ip = network_addr.split("/")[0]
                            mask = network_addr.split("/")[1]
                        else:
                            ip = 'any'
                            mask = None

                        if ip != 'any':
                            if addr_type == 'ipv4':
                                net = Network(ADDR_TYPE_IPv4, ip, None,
                                              int(mask))
                            else:
                                net = Network(ADDR_TYPE_IPv6, None, ip,
                                              int(mask))
                        else:
                            net = None

                        pfx = Pfx(le, ge, action, net, seqid)
                        pfx_l = PrefixList(prefix_name)
                        pfx_l.add_pfx(pfx)
                        frr_cfg[router].routing_pb.prefix_lists.append(pfx_l)

                interfaces_cfg(frr_cfg[router])
                static_rt_cfg(frr_cfg[router])
                prefixlist_cfg(frr_cfg[router], addr_type)
                frr_cfg[router].print_common_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, router)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: create_prefix_lists()")
    return True


def delete_prefix_lists(tgen, topo, addr_type, input_dict):
    """
    Delete ip prefix lists from the device

    Parameters
    ----------
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `addr_type`  : ip type, ipv4/ipv6
    * `input_dict` :  for which router pf_list has to be deleted

    Usage
    -----
    # prefix_lists: list of prefix-list names that need to be deleted
    input_dict = {
        'r1': {
            'prefix_lists': ['pf_list_1']
        }}
    result = delete_prefix_lists('ipv4', input_dict, tgen, CWD, topo)

    Returns
    -------
    errormsg(str) or True
    """
    logger.info("Entering lib API: delete_prefix_lists()")

    try:
        global frr_cfg
        for dut in input_dict.keys():
            for router, rnode in tgen.routers().iteritems():
                if router != dut:
                    continue

                # Reset config for routers
                frr_cfg[router].reset_it()

                seq_id = []
                pb_prefix_lists = frr_cfg[router].routing_pb.prefix_lists
                for pfx_l in pb_prefix_lists:
                    for pfx in pfx_l.prefix:
                        seq_id.append(pfx.seq_id)

                prefix_lists = input_dict[router]["prefix_lists"]
                for seqid in seq_id:
                    found = False
                    for pfx_list_name in prefix_lists:
                        for pfx_l in pb_prefix_lists[:]:
                            if pfx_l.prefix_list_uuid_name == pfx_list_name:
                                found = True
                                for pfx in pfx_l.prefix[:]:
                                    if pfx.seq_id == seqid:
                                        pfx_l.prefix.remove(pfx)
                                        if len(pfx_l.prefix) == 0:
                                            pb_prefix_lists.remove(pfx_l)
                        if not found:
                            errormsg = ("Prefix list {} not found in router "
                                        "{}".format(pfx_list_name, router))
                            return errormsg

                interfaces_cfg(frr_cfg[router])
                prefixlist_cfg(frr_cfg[router], addr_type)
                frr_cfg[router].print_common_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, router)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: delete_prefix_lists()")
    return True


def modify_prefix_lists(tgen, topo, addr_type, input_dict):
    """
    Modify prefix lists is exists otherwise returns error

    Parameters
    ----------
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `addr_type`  : ip type, ipv4/ipv6
    * `input_dict` : data to modify prefix lists

    Usage
    -----
    # Modify ip prefix list pf_ls_1 for router r1
    input_dict = {
         'r1': {
              'prefix_lists':{
                  'pf_ls_1': [{'seqid': '10', 'network': '10.0.0.0/8',\
                 'le': '32', 'action': 'permit'}]
               }}}
    result = modify_prefix_lists('ipv4', input_dict_1, tgen, CWD, topo)

    Returns
    -------
    errormsg(str) or True
    """
    logger.info("Entering lib API: modify_prefix_lists()")

    try:
        for router in input_dict.keys():
            # Reset config for routers
            frr_cfg[router].reset_it()

            for prefix_name, prefix_list in \
                    input_dict[router]['prefix_lists'].iteritems():
                for prefix_dict in prefix_list:
                    network_addr = prefix_dict['network']
                    action = prefix_dict['action']
                    if 'le' in prefix_dict:
                        le = prefix_dict['le']
                    else:
                        le = None

                    if 'ge' in prefix_dict:
                        ge = prefix_dict['ge']
                    else:
                        ge = None

                    if 'seqid' in prefix_dict:
                        seqid = prefix_dict['seqid']
                    else:
                        seqid = None

                    if network_addr != 'any':
                        # IP from network, removing mask
                        ip = network_addr.split("/")[0]
                        mask = network_addr.split("/")[1]
                    else:
                        ip = 'any'
                        mask = None

                    if ip != 'any':
                        if addr_type == 'ipv4':
                            net = Network(ADDR_TYPE_IPv4, ip, None, int(mask))
                        else:
                            net = Network(ADDR_TYPE_IPv6, None, ip, int(mask))
                    else:
                        net = None

                    for pfx_l in frr_cfg[router].routing_pb.prefix_lists:
                        if pfx_l.prefix_list_uuid_name == prefix_name:
                            for pfx in pfx_l.prefix:
                                if seqid:
                                    if pfx.seq_id == seqid:
                                        pfx.network = net
                                        pfx.less_or_equal_bits = le
                                        pfx.greater_or_equal_bits = ge
                                        pfx.action = action
                                        pfx.seqid = seqid

            interfaces_cfg(frr_cfg[router])
            static_rt_cfg(frr_cfg[router])
            prefixlist_cfg(frr_cfg[router], addr_type)
            frr_cfg[router].print_common_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, router)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_prefix_lists()")
    return True


def create_route_maps(tgen, topo, addr_type, input_dict):
    """
    Create route-map on the devices as per the arguments passed

    Parameters
    ----------
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `addr_type`  : ip_type, ipv4/ipv6
    * `input_dict` :  for which static route/s admin distance should modified

    Usage
    -----
    # route_maps: key, value pair for route-map name and its attribute
    # rmap_match_prefix_list_1: user given name for route-map
    # action: PERMIT/DENY
    # match: key,value pair for match criteria. prefix_list, community-list,
             large-community-list or tag. Only one option at a time.
    # prefix_list: name of prefix list
    # large-community-list: name of large community list
    # community-ist: name of community list
    # tag: tag id for static routes
    # set: key, value pair for modifying route attributes
    # localpref: preference value for the network
    # med: metric value advertised for AS
    # aspath: set AS path value
    # weight: weight for the route
    # community: standard community value to be attached
    # large_community: large community value to be attached
    # community_additive: if set to 'additive', adds community/large-community
                          value to the existing values of the network prefix

    Example:
    --------
    input_dict = {
        "r1": {
            "route_maps": {
                "rmap_match_prefix_list_1": [
                    {
                        "action": "PERMIT",
                        "match": {
                            "prefix_list": "pf_list_1",
                            "large-community-list": "community_1",
                            "community-list": "community_2",
                            "tag": "tag_id"
                        },
                        "set": {
                            "localpref": 150,
                            "med": 30,
                            "aspath": 20000,
                            "weight": 500,
                            "community": "1:2 2:3",
                            "large_community": "1:2:3 4:5;6",
                            "community_additvie: 'additive',

                        }
                    }
                ]
            }
        }
    }

    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: create_route_maps()")

    try:
        for router in input_dict.keys():
            if "route_maps" in input_dict[router]:
                # Reset config for routers
                frr_cfg[router].reset_it()

                for rmap_name, rmap_value in \
                        input_dict[router]["route_maps"].iteritems():
                    for rmap_dict in rmap_value:
                        rmap_action = rmap_dict["action"]

                        if rmap_action == 'PERMIT':
                            rmap_action = PERMIT
                        else:
                            rmap_action = DENY

                        rmap = RouteMap(rmap_name)
                        frr_cfg[router].routing_pb.route_maps.append(rmap)

                        # Verifying if SET criteria is defined
                        if 'set' in rmap_dict:
                            if 'localpref' in rmap_dict["set"]:
                                local_preference = \
                                    rmap_dict["set"]['localpref']
                            else:
                                local_preference = None

                            if 'med' in rmap_dict["set"]:
                                metric = rmap_dict["set"]['med']
                            else:
                                metric = None

                            if 'aspath' in rmap_dict["set"]:
                                as_path = rmap_dict["set"]['aspath']
                            else:
                                as_path = None

                            if 'weight' in rmap_dict["set"]:
                                weight = rmap_dict["set"]['weight']
                            else:
                                weight = None

                            if 'community' in rmap_dict["set"]:
                                community = rmap_dict["set"]['community']
                            else:
                                community = None

                            if 'large_community' in rmap_dict["set"]:
                                large_community = rmap_dict["set"][
                                    'large_community']
                            else:
                                large_community = None

                            if 'set_action' in rmap_dict["set"]:
                                set_action = rmap_dict["set"]['set_action']
                            else:
                                set_action = None

                            if 'community_additive' in rmap_dict["set"]:
                                community_additive = rmap_dict["set"][
                                    'community_additive']
                            else:
                                community_additive = None

                            set_criteria = RouteMapSet(
                                local_preference, metric, as_path, community,
                                community_additive, weight, large_community,
                                set_action)
                        else:
                            set_criteria = None

                        # Adding MATCH and SET sequence to RMAP if defined
                        if "match" in rmap_dict:
                            match = RouteMapMatch()
                            for match_criteria in rmap_dict["match"].keys():
                                if match_criteria == 'prefix_list':
                                    pb_prefix_list = \
                                        frr_cfg[router].routing_pb.prefix_lists
                                    pfx_list = rmap_dict["match"][
                                        match_criteria]
                                    for prefix_list in pb_prefix_list[:]:
                                        prefix_lists = []
                                        if prefix_list.prefix_list_uuid_name \
                                                == pfx_list:
                                            prefix_lists.append(prefix_list)
                                            match.prefix_list = prefix_lists
                                            rmap.add_seq(match, rmap_action,
                                                         set_criteria)
                                elif match_criteria == 'community-list':
                                    community_lists = []
                                    communities = rmap_dict["match"][
                                        match_criteria]
                                    for community in communities:
                                        community_lists.append(community)
                                        match.community_list = community_lists
                                    rmap.add_seq(match, rmap_action,
                                                 set_criteria)
                                elif match_criteria == 'large-community-list':
                                    large_community_lists = []
                                    large_communities = rmap_dict["match"][
                                        match_criteria]

                                    if "match_exact" in rmap_dict["match"]:
                                        match.match_exact = rmap_dict["match"] \
                                            ["match_exact"]
                                    else:
                                        match.match_exact = None

                                    for large_community in large_communities:
                                        large_community_lists.append(
                                            large_community)
                                        match.large_community_list = \
                                            large_community_lists
                                    rmap.add_seq(match, rmap_action,
                                                 set_criteria)
                                elif match_criteria == 'tag':
                                    tag = rmap_dict["match"][match_criteria]
                                    match.tag = tag
                                    rmap.add_seq(match, rmap_action,
                                                 set_criteria)
                        else:
                            match = None
                            rmap.add_seq(match, rmap_action, set_criteria)

                interfaces_cfg(frr_cfg[router])
                static_rt_cfg(frr_cfg[router])
                prefixlist_cfg(frr_cfg[router], addr_type)
                routemap_cfg(frr_cfg[router], addr_type)
                frr_cfg[router].print_common_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, router)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: create_route_maps()")
    return True


def delete_route_maps(tgen, topo, addr_type, input_dict):
    """
    Delete ip route maps from device

    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `addr_type`  : ip type, ipv4/ipv6
    * `input_dict` :  for which router, route map has to be deleted

    Usage
    -----
    # Delete route-map rmap_1 and rmap_2 from router r1
    input_dict = {
        'r1': {
            'route_maps': ['rmap_1', 'rmap__2']
        }}
    result = delete_route_maps('ipv4', input_dict, tgen, CWD, topo)

    Returns
    -------
    errormsg(str) or True
    """
    logger.info("Entering lib API: delete_route_maps()")

    try:
        global frr_cfg
        for router in input_dict.keys():

            # Reset config for routers
            frr_cfg[router].reset_it()

            route_maps = input_dict[router]['route_maps']
            found = False
            for route_map in route_maps:
                for rmap in frr_cfg[router].routing_pb.route_maps[:]:
                    if rmap.route_map_uuid_name == route_map:
                        found = True
                        frr_cfg[router].routing_pb.route_maps.remove(rmap)
            if not found:
                errormsg = ("Route map {} not found in router {}".
                            format(route_map, router))
                return errormsg

            interfaces_cfg(frr_cfg[router])
            static_rt_cfg(frr_cfg[router])
            prefixlist_cfg(frr_cfg[router], addr_type)
            routemap_cfg(frr_cfg[router], addr_type)
            frr_cfg[router].print_common_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, router)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback 
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: delete_route_maps()")
    return True


#############################################
## Verification APIs
#############################################
def verify_rib(tgen, addr_type, dut, input_dict, next_hop=None, protocol=None):
    """
    Data will be read from input_dict or input JSON file, API will generate
    same prefixes, which were redistributed by either create_static_routes() or
    advertise_networks_using_network_command() and do will verify next_hop and 
    each prefix/routes is present in "show ip/ipv6 route {bgp/stataic} json"
    command o/p.

    Parameters
    ----------
    * `tgen` : topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test, for which user wants to test the data
    * `input_dict` : input dict, has details of static routes
    * `next_hop`[optional]: next_hop which needs to be verified, default: static
    * `protocol`[optional]: protocol, default = None

    Usage
    -----
    # RIB can be verified for static routes OR network advertised using
    network command. Following are input_dicts to create static routes 
    and advertise networks using network command. Any one of the input_dict
    can be passed to verify_rib() to verify routes in DUT's RIB.

    # Creating static routes for r1
    input_dict = {
        "r1": {
            "static_routes": [{"network": "10.0.20.1/32", "no_of_ip": 9, \
        "admin_distance": 100, "next_hop": "10.0.0.2", "tag": 4001}]
        }}
    # Advertising networks using network command in router r1
    input_dict = {
       'r1': {
          'advertise_networks': [{'start_ip': '20.0.0.0/32', 
                                  'no_of_network': 10},
                                  {'start_ip': '30.0.0.0/32'}]
        }}
    # Verifying ipv4 routes in router r1 learned via BGP
    dut = 'r2'
    protocol = "bgp"
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol = protocol)

    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: verify_rib()")

    router_list = tgen.routers()
    for routerInput in input_dict.keys():
        for router, rnode in router_list.iteritems():
            if router != dut:
                continue

            # Verifying RIB routes
            if addr_type == "ipv4":
                if protocol:
                    command = "show ip route {} json".format(protocol)
                else:
                    command = "show ip route json"
            else:
                if protocol:
                    command = "show ipv6 route {} json".format(protocol)
                else:
                    command = "show ipv6 route json"

            sleep(2)
            logger.info('Checking router {} RIB:'.format(router))
            rib_routes_json = rnode.vtysh_cmd(command, isjson=True)

            # Verifying output dictionary rib_routes_json is not empty
            if bool(rib_routes_json) is False:
                errormsg = "No {} route found in rib of router {}..". \
                    format(protocol, router)
                return errormsg

            if 'static_routes' in input_dict[routerInput]:
                static_routes = input_dict[routerInput]["static_routes"]
                st_found = False
                nh_found = False
                found_routes = []
                missing_routes = []
                for static_route in static_routes:
                    network = static_route["network"]
                    if "no_of_ip" in static_route:
                        no_of_ip = static_route["no_of_ip"]
                    else:
                        no_of_ip = 0

                    # Generating IPs for verification
                    ip_list = generate_ips(addr_type, network, no_of_ip)
                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(unicode(st_rt)))

                        if st_rt in rib_routes_json:
                            st_found = True
                            found_routes.append(st_rt)

                            if next_hop:
                                if rib_routes_json[st_rt][0]['nexthops'] \
                                        [0]['ip'] == next_hop:
                                    nh_found = True
                                else:
                                    errormsg = ("Nexthop {} is Missing for {}"
                                                " route {} in RIB of router"
                                                " {}\n".format(next_hop, 
                                                               protocol,
                                                               st_rt, dut))
                                    return errormsg
                        else:
                            missing_routes.append(st_rt)
                if nh_found:
                    logger.info("Found next_hop {} for all routes in RIB of"
                                " router {}\n".format(next_hop, dut))

                if not st_found and len(missing_routes) > 0:
                    errormsg = "Missing route in RIB of router {}, routes: {}" \
                               " \n".format(dut, missing_routes)
                    return errormsg

                logger.info("Verified routes in router {} RIB, found routes"
                            " are: {}\n".format(dut, found_routes))

            if 'advertise_networks' in input_dict[routerInput]:
                found_routes = []
                missing_routes = []
                advertise_network = input_dict[routerInput]\
                                    ['advertise_networks']
                found = False
                for advertise_network_dict in advertise_network:
                    start_ip = advertise_network_dict['start_ip']
                    if 'no_of_network' in advertise_network_dict:
                        no_of_network = advertise_network_dict['no_of_network']
                    else:
                        no_of_network = 0

                    # Generating IPs for verification
                    ip_list = generate_ips(addr_type, start_ip, no_of_network)
                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(unicode(st_rt)))

                        if st_rt in rib_routes_json:
                            found = True
                            found_routes.append(st_rt)
                        else:
                            missing_routes.append(st_rt)

                if not found and len(missing_routes) > 0:
                    errormsg = "Missing route in RIB of router {}, are: {}" \
                               " \n".format(dut, missing_routes)
                    return errormsg

                logger.info("Verified routes in router {} RIB, found routes"
                            " are: {}\n".format(dut, found_routes))

    logger.info("Exiting lib API: verify_rib()")
    return True


def verify_admin_distance_for_static_routes(tgen, addr_type, input_dict):
    """
    API to verify admin distance for static routes as defined in input_dict/
    input JSON by running show ip/ipv6 route json command.

    Parameter
    ---------
    * `tgen` : topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `input_dict`: having details like - for which router and static routes
                    admin dsitance needs to be verified
    Usage
    -----
    # To verify admin distance is 10 for prefix 10.0.20.1/32 having next_hop
    10.0.0.2 in router r1
    input_dict = {
        'r1': {
            '10.0.20.1/32':{
                'admin_distance': 10,
                'next_hop': '10.0.0.2'
            }}}
    result = verify_admin_distance_for_static_routes(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: verify_admin_distance_for_static_routes()")

    for dut in input_dict.keys():
        for router, rnode in tgen.routers().iteritems():
            if router != dut:
                continue

            # Command to execute
            if addr_type == "ipv4":
                command = "show ip route json"
            else:
                command = "show ipv6 route json"

            show_ip_route_json = rnode.vtysh_cmd(command, isjson=True)
            for static_route in input_dict[dut].keys():
                logger.info('Verifying admin distance for static route {}'
                            ' under dut {}:'.format(static_route, router))
                next_hop = input_dict[dut][static_route]['next_hop']
                admin_distance = input_dict[dut][static_route]\
                                 ['admin_distance']
                route_data = show_ip_route_json[static_route][0]
                if static_route in show_ip_route_json:
                    if route_data['nexthops'][0]['ip'] == next_hop:
                        if route_data['distance'] != admin_distance:
                            errormsg = ('Verification failed: admin distance'
                                        ' for static route {} under dut {},'
                                        ' found:{} but expected:{}'.\
                                        format(static_route, router,
                                               route_data['distance'],
                                               admin_distance))
                            return errormsg
                        else:
                            logger.info('Verification successful: admin'
                                        ' distance for static route {} under'
                                        ' dut {}, found:{}'.\
                                        format(static_route, router,
                                               route_data['distance']))

                else:
                    errormsg = ('Static route {} not found in '
                                'show_ip_route_json for dut {}'.\
                                format(static_route, router))
                    return errormsg

    logger.info("Exiting lib API: verify_admin_distance_for_static_routes()")
    return True


def verify_prefix_lists(tgen, addr_type, input_dict):
    """
    Running "show ip prefix-list" command and verifying given prefix-list
    is present in router.

    Parameters
    ----------
    * `tgen` : topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `input_dict`: data to verify prefix lists

    Usage
    -----
    # To verify pf_list_1 is present in router r1
    input_dict = {
        'r1': {
            'prefix_lists': ['pf_list_1']
        }}
    result = verify_prefix_lists('ipv4', input_dict, tgen)

    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: verify_prefix_lists()")

    for dut in input_dict.keys():
        for router, rnode in tgen.routers().iteritems():
            if router != dut:
                continue

            # Show ip prefix list
            show_prefix_list = rnode.vtysh_cmd("show ip prefix-list")

            # Verify Prefix list is deleted
            prefix_lists = input_dict[router]["prefix_lists"]
            for prefix_list in prefix_lists:
                if prefix_list in show_prefix_list:
                    errormsg = ("Prefix list {} is not deleted from router"
                                " {}".format(prefix_list, router))
                return errormsg

            logger.info("Prefix list {} is/are deleted successfully from"
                        "router {}".format(prefix_lists, dut))

    logger.info("Exiting lib API: verify_prefix_lissts()")
    return True

def verify_route_maps(tgen, input_dict):
    """
    Running "show route-map" command and verifying given route-map
    is present in router.

    Parameters
    ----------
    * `tgen` : topogen object
    * `input_dict`: data to verify prefix lists

    Usage
    -----
    # To verify rmap_1 and rmap_2 are present in router r1
    input_dict = {
        'r1': {
            'route_maps': ['rmap_1', 'rmap_2']
        }
    }
    result = verify_route_maps(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: verify_route_maps()")

    for dut in input_dict.keys():
        for router, rnode in tgen.routers().iteritems():
            if router != dut:
                continue

            # Show ip route-map
            show_route_maps = rnode.vtysh_cmd("show route-map")

            # Verify route-map is deleted
            route_maps = input_dict[router]["route_maps"]
            for route_map in route_maps:
                if route_map in show_route_maps:
                    errormsg = ("Route map {} is not deleted from router"
                                " {}".format(route_map, router))
                    return errormsg

            logger.info("Route map {} is/are deleted successfully from"
                        " router {}".format(route_maps, router))

    logger.info("Exiting lib API: verify_route_maps()")
    return True
