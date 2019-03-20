#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
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
import json
import time
import errno
import pytest
import StringIO
import traceback
import ipaddress
import ConfigParser
from time import sleep
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
number_to_router = {}
FRRCFG_FILE = 'frr_json.conf'
frr_cfg = {}

####
CD = os.path.dirname(os.path.realpath(__file__))
pytestini_path = os.path.join(CD, '../pytest.ini')

# NOTE: to save execution logs to log file frrtest_log_dir must be configured in `pytest.ini`.
config = ConfigParser.ConfigParser()
config.read(pytestini_path)

CONFIG_SECTION = 'topogen'

if config.has_option('topogen', 'verbosity'):
    loglevel = config.get('topogen', 'verbosity')
    loglevel = loglevel.upper()
else:
    loglevel = 'INFO'

if config.has_option('topogen', 'frrtest_log_dir'):
    frrtest_log_dir =  config.get('topogen', 'frrtest_log_dir')
    time_stamp = datetime.time(datetime.now())
    logfile_name = "frr_test_bgp_"
    frrtest_log_file = frrtest_log_dir + logfile_name + str(time_stamp)

    logger = logger_config.get_logger(name='test_execution_logs', log_level=loglevel, target=frrtest_log_file)
    print "Logs will be sent to logfile: {}".format(frrtest_log_file)

if config.has_option('topogen', 'show_router_config'):
    show_router_config = config.get('topogen', 'show_router_config')
else:
    show_router_config = False

###
class RoutingPB:

    def __init__(self):
        self.interfaces_cfg = None
        self.static_route = []
        self.prefix_lists = []
        self.route_maps = []


class FRRConfig:

    def __init__(self, router, routing_cfg_msg, frrcfg_file):
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

    def reset_route_map_seq_id(self):
        self._route_map_seq_id = 0

    def reset_it(self):
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
        try:
            frrcfg = open(self.frrcfg_file, 'w')
        except IOError as err:
            logger.error('Unable to open FRR Config File. error(%s): %s' % (err.errno, err.strerror))
            return False

        frrcfg.write('! FRR General Config\n')
        frrcfg.write(self.routing_common.getvalue())
        frrcfg.write('! Interfaces Config\n')
        frrcfg.write(self.interfaces_cfg.getvalue())
        # If bgp neighborship is being done using loopback interface -
        # - then we have make the loopback interface reachability up -
        # - for that we are adding static routes -
        for router, number in number_to_router.iteritems():
            if number == self.router:
                neighbors = topo['routers']['{}'.format(router)]["bgp"]['bgp_neighbors']
                for key, value in neighbors.iteritems():
                    peer = neighbors[key]['peer']
                    if "source" in peer and peer['source'] == 'lo':
                        add_static_route_for_loopback_interfaces('ipv4', router, topo, frrcfg)

        frrcfg.write('! Static Route Config\n')
        frrcfg.write(self.static_routes.getvalue())
        frrcfg.write('! Access List Config\n')
        frrcfg.write(self.access_lists.getvalue())
        frrcfg.write('! Prefix List Config\n')
        frrcfg.write(self.prefix_lists.getvalue())
        frrcfg.write('! Route Maps Config\n')
        frrcfg.write(self.route_maps.getvalue())

        frrcfg.write('line vty\n')
        frrcfg.close()
        return True

    def close(self):
        self.routing_common.close()
        self.static_routes.close()
        self.prefix_lists.close()
        self.route_maps.close()

def create_common_configuration(ADDR_TYPE, tgen, CWD, topo, router):
    """
    It will save routers common configuration to frr.conf file
 
    * `ADDR_TYPE` : ip type ipv4/ipv6 
    * `tgen` : Topogen object
    * `CWD`  : caller's current working directory
    * `topo` : json file data 
    * `router` : current router
    """
   
    try:
        global frr_cfg
        listRouters = []
        for routerN in topo['routers'].iteritems():
            listRouters.append(routerN[0])

        listRouters.sort()

        # Creating a dictionary for routers, 'r1': 1, 'r2': 2 ...(respective numbers 
	# would be used to save router's config)
        assign_number_to_routers(listRouters)

        for curRouter in listRouters:
            if curRouter != router:
                continue

            # Getting numner to router
            i = number_to_router[router]

            rt_cfg = RoutingPB()
            fname = '%s/r%d/%s' % (CWD, i, FRRCFG_FILE)
            frr_cfg[i] = FRRConfig(i, rt_cfg, fname)

	    input_dict = topo['routers']
            if 'link' in topo['routers'][router] or 'lo' in topo['routers'][router]:
                frr_cfg[i].routing_pb.interfaces_cfg = create_interfaces_cfg(router, topo)
                interfaces_cfg(frr_cfg[i])
                frr_cfg[i].print_common_config_to_file(topo)
                # Load configuration to router
                #load_config_to_router(tgen, CWD, router)
	
      	    if 'static_routes' in topo['routers'][router]:
	        result = create_static_routes(ADDR_TYPE, input_dict, tgen, CWD, topo)
	        if result != True : assert False, "API: create_static_routes() " + ":Failed \n Error: {}".format(result)
	
	    if 'prefix_lists' in topo['routers'][router]:
	        result = create_prefix_lists(ADDR_TYPE, input_dict, tgen, CWD, topo)
	        if result != True : assert False, "API: create_prefix_lists()" + ":Failed \n Error: {}".format(result)
	    
	    if 'route_maps' in topo['routers'][router]:
		result = create_route_maps(ADDR_TYPE, input_dict, tgen, CWD, topo)
	        if result != True : assert False, "API: create_route_maps()" + ":Failed \n Error: {}".format(result)
    
    except Exception as e:
        logger.error(traceback.format_exc())
        return False
    
    return True 

#############################################
# Helper classes to save configuration
#############################################

# Interface helper class for interface configuration
class Interface:

    def __init__(self, interface_name, interface_ip_addresses):
        self.interface_name = interface_name
        self.interface_ip_addresses = interface_ip_addresses


class Interfaces:

    def __init__(self):
        self.interfaces = []

    def add_interface(self, interface_name, interface_ip_addresses):
        for n in self.interfaces:
            if n.interface_name == interface_name:
                n.interface_ip_address.append(interface_ip_addresses)
                return

        interface = Interface(interface_name, interface_ip_addresses)
        self.interfaces.append(interface)
        return interface


def _print_interfaces_cfg(frr_cfg, interface):
    interface_name = interface.interface_name
    interface_ip_addresses = interface.interface_ip_addresses
    frr_cfg.interfaces_cfg.write('interface ' + str(interface_name) + '\n')
    for address in interface_ip_addresses:
        if '::' in address:
            frr_cfg.interfaces_cfg.write('ipv6 address ' + str(address) + '\n')
        else:
            frr_cfg.interfaces_cfg.write('ip address ' + str(address) + '\n')


def interfaces_cfg(frr_cfg):
    ifaces = frr_cfg.routing_pb.interfaces_cfg
    for interface in ifaces.interfaces:
        _print_interfaces_cfg(frr_cfg, interface)

# Helper class for Static route nexthop configuration
class Nexthop:

    def __init__(self, ip, blackhole = False, admin_distance = 1, if_name = None, tag = None):
        self.ip = ip
        self.blackhole = blackhole
        self.admin_distance = admin_distance
        self.if_name = if_name
        self.tag = tag

# Helper class for Static route ip-prefix  configuration
class Route:

    def __init__(self, prefix):
        self.prefix = prefix
        self.nexthops = []

    def add_nexthop(self, ip, blackhole, admin_distance, if_name, tag):
        nhop = Nexthop(ip, blackhole, admin_distance, if_name, tag)
        self.nexthops.append(nhop)


def static_rt_nh(nh):
    rc = 0
    nexthop = ''
    admin_dist = '1'
    tag = None
    if nh.ip:
        nexthop = IpAddressMsg_to_str(nh.ip)
    elif nh.blackhole:
        nexthop = 'blackhole'
    if nh.if_name != None:
        nexthop = nexthop + ' ' + nh.if_name
    if nh.admin_distance > 0:
        admin_dist = str(nh.admin_distance)
    if nh.tag != None:
        tag = nh.tag
    return (rc, nexthop, admin_dist, tag)

def static_rt_cfg(frr_cfg):
    if frr_cfg.routing_pb.static_route == None:
        return
    for st in frr_cfg.routing_pb.static_route:
        prefix = IpAddressMsg_to_str(st.prefix)
        addr_type = st.prefix.afi
        ip_cmd = get_ip_cmd(addr_type)
        for nh in st.nexthops:
            rc, nexthop, admin_dist, tag = static_rt_nh(nh)
            if rc == 0:
                if tag == None:
                    frr_cfg.static_routes.write(' '.join([ip_cmd,
                     'route', prefix, nexthop, admin_dist, '\n']))
                else:
                    frr_cfg.static_routes.write(' '.join([ip_cmd,
                     'route', prefix, nexthop, 'tag', str(tag), admin_dist, '\n']))
            else:
                frr_cfg.errors.append('Static Route: ' + prefix + 'with Nexthop: ' + str(nh))

# Helper class for general Network configuration
class Network:

    def __init__(self, afi, ipv4, ipv6, prefix_length):
        self.afi = afi
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.prefix_length = prefix_length


# Helper class for Address type  configuration
class Address:

    def __init__(self, afi, ipv4, ipv6):
        self.afi = afi
        self.ipv4 = ipv4
        self.ipv6 = ipv6

# Helper class for IP Prefix list configuration
class Pfx:
    def __init__(self, less_or_equal_bits, greater_or_equal_bits, action, network, seqid):
        self.less_or_equal_bits = less_or_equal_bits
        self.greater_or_equal_bits = greater_or_equal_bits
        self.action = action
        self.network = network
        self.seq_id = seqid

class PrefixList:
    def __init__(self, name):
        self.prefix_list_uuid_name = name
        self.prefix = []
    def add_pfx(self, pfx):
        self.prefix.append(pfx)

def get_action_from_route_map_seq(route_map_seq):
    if route_map_seq.action == PERMIT:
        return 'permit'
    else:
        return 'deny'

def prefixlist_cfg(frr_cfg, ADDR_TYPE):
    if frr_cfg.routing_pb.prefix_lists == None:
        return
    for prefixlist in frr_cfg.routing_pb.prefix_lists:
        name = prefixlist.prefix_list_uuid_name
        for prefix in prefixlist.prefix:
            le_ge = ""

	    if prefix.network != None:
                if (prefix.less_or_equal_bits and
                    prefix.network.prefix_length <= prefix.less_or_equal_bits):
                    le_ge = " ".join([le_ge, "le", str(prefix.less_or_equal_bits)])

                if (prefix.greater_or_equal_bits and
                    prefix.greater_or_equal_bits >= prefix.network.prefix_length):
                    le_ge = " ".join([le_ge, "ge", str(prefix.greater_or_equal_bits)])

                network = IpPrefixMsg_to_str(prefix.network)
                ip_cmd = get_ip_cmd(prefix.network.afi)
                frr_cfg.prefix_lists.write(' '.join([
                    ip_cmd, 'prefix-list', name, 'seq', str(prefix.seq_id), prefix.action, network, le_ge, '\n']))
            else:
                network = 'any'
		if ADDR_TYPE == "ipv4":
                    frr_cfg.prefix_lists.write(' '.join([
                        'ip', 'prefix-list', name, 'seq', str(prefix.seq_id), prefix.action, network, '\n']))
		else:
                    frr_cfg.prefix_lists.write(' '.join([
                        'ipv6', 'prefix-list', name, 'seq', str(prefix.seq_id), prefix.action, network, '\n']))

# Helper class for Route-Maps configuration
class RouteMapMatch:
    def __init__(self):
	self.tag = None
        self.prefix_list = []
        self.community_list = []

    def add_prefix_list(self, prefix_list):
        self.prefix_list.append(prefix_list)

    def add_community_list(self, community_list):
        self.community_list.append(community_list)

class RouteMapSet:
    def __init__(self, local_preference, metric, as_path_prepend, community, community_additive, weight):
        self.local_preference = local_preference
        self.metric = metric
        self.as_path_prepend = as_path_prepend
        self.community = community
        self.community_additive = community_additive
        self.weight = weight

class RouteMapSeq:
    def __init__(self, match, action, route_map_set):
        self.match = match
        self.action = action
        self.route_map_set = route_map_set

class RouteMap:
    def __init__(self, name):
        self.route_map_uuid_name = name
        self.route_map_seq = []

    def add_seq(self, match, action, route_map_set):
        rmap_seq = RouteMapSeq(match, action, route_map_set)
        self.route_map_seq.append(rmap_seq)

def get_action_from_route_map_seq(route_map_seq):
    if route_map_seq.action == PERMIT:
        return 'permit'
    else:
        return 'deny'

def route_map_set_cfg(frr_cfg, route_map_set):
    # Local Preference
    if route_map_set.local_preference:
        frr_cfg.route_maps.write(' '.join([
            'set', 'local-preference', str(route_map_set.local_preference), "\n"]))
    # Metric
    if route_map_set.metric:
        frr_cfg.route_maps.write(' '.join([
            'set', 'metric', str(route_map_set.metric), "\n"]))
    # AS Path Prepend
    if route_map_set.as_path_prepend != None:
        frr_cfg.route_maps.write(' '.join([
            'set', 'as-path', 'prepend', route_map_set.as_path_prepend, "\n"]))
    # Community
    if route_map_set.community:
        # community_additive
        additive = ''
        if route_map_set.community_additive:
            additive = 'additive'
        frr_cfg.route_maps.write(' '.join([
            'set', 'community', route_map_set.community, additive, "\n"]))
    # Weight
    if route_map_set.weight:
        frr_cfg.route_maps.write(' '.join([
            'set', 'weight', str(route_map_set.weight), "\n"]))

def handle_route_map_seq_set(frr_cfg, route_map_seq):
    if route_map_seq.route_map_set != None:
        route_map_set_cfg(frr_cfg, route_map_seq.route_map_set)

def handle_match_prefix_list(frr_cfg, routemap, route_map_seq, ADDR_TYPE):
    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)
    # IPv4
    if ADDR_TYPE == 'ipv4':
        seq_id = frr_cfg.get_route_map_seq_id()
        frr_cfg.route_maps.write(' '.join(['route-map', name, action, str(seq_id), "\n"]))
        # MATCH
    	for prefix_list in route_map_seq.match.prefix_list:
            frr_cfg.route_maps.write(' '.join([
                'match', 'ip', 'address', 'prefix-list', prefix_list.prefix_list_uuid_name, '\n']))
        # SET
        handle_route_map_seq_set(frr_cfg, route_map_seq)
        frr_cfg.route_maps.write("! END of " + name + " - " + str(seq_id) + "\n")

    else:
        # IPv6
        seq_id = frr_cfg.get_route_map_seq_id()
        frr_cfg.route_maps.write(' '.join(['route-map', name, action, str(seq_id), "\n"]))
        # MATCH
    	for prefix_list in route_map_seq.match.prefix_list:
            frr_cfg.route_maps.write(' '.join([
                'match', 'ipv6', 'address', 'prefix-list', prefix_list.prefix_list_uuid_name, '\n']))
        # SET
        handle_route_map_seq_set(frr_cfg, route_map_seq)
        frr_cfg.route_maps.write("! END of " + name + " - " + str(seq_id) + "\n")

def handle_match_tag(frr_cfg, routemap, route_map_seq, ADDR_TYPE):
    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)
    # MATCH
        
    # IPv4
    if ADDR_TYPE == 'ipv4':
        seq_id = frr_cfg.get_route_map_seq_id()
        frr_cfg.route_maps.write(' '.join(['route-map', name, action, str(seq_id), "\n"]))
        frr_cfg.route_maps.write(' '.join([
    	    'match', 'tag', str(route_map_seq.match.tag), '\n']))
    	# SET
        handle_route_map_seq_set(frr_cfg, route_map_seq)
        frr_cfg.route_maps.write("! END of " + name + " - " + str(seq_id) + "\n")

    else:
        # IPv6
        seq_id = frr_cfg.get_route_map_seq_id()
        frr_cfg.route_maps.write(' '.join(['route-map', name, action, str(seq_id), "\n"]))
        frr_cfg.route_maps.write(' '.join([
    	    'match', 'tag', str(route_map_seq.match.tag), '\n']))
        # SET
        handle_route_map_seq_set(frr_cfg, route_map_seq)
        frr_cfg.route_maps.write("! END of " + name + " - " + str(seq_id) + "\n")

def handle_match_community_list(frr_cfg, routemap, route_map_seq):
    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)
    # MATCH
    for community in route_map_seq.match.community_list:
        # IPv4
        seq_id = frr_cfg.get_route_map_seq_id()
        frr_cfg.route_maps.write(' '.join(['route-map', name, action, str(seq_id), "\n"]))
        frr_cfg.route_maps.write(' '.join([
            'match', 'community', community.comm_list_uuid_name, '\n']))
        # SET
        handle_route_map_seq_set(frr_cfg, route_map_seq)
        frr_cfg.route_maps.write("! END of " + name + " - " + str(seq_id) + "\n")

def handle_no_match_set_only(frr_cfg, routemap, route_map_seq):
    name = routemap.route_map_uuid_name
    action = get_action_from_route_map_seq(route_map_seq)
    seq_id = frr_cfg.get_route_map_seq_id()
    frr_cfg.route_maps.write(' '.join(['route-map', name, action, str(seq_id), "\n"]))
    # SET
    handle_route_map_seq_set(frr_cfg, route_map_seq)
    frr_cfg.route_maps.write("! END of " + name + " - " + str(seq_id) + "\n")

def routemap_cfg(frr_cfg, ADDR_TYPE):
    if frr_cfg.routing_pb.route_maps == None:
        return
    for routemap in frr_cfg.routing_pb.route_maps:
        for route_map_seq in routemap.route_map_seq:
            # Match by Prefix List
            if len(route_map_seq.match.prefix_list) > 0:
                handle_match_prefix_list(frr_cfg, routemap, route_map_seq, ADDR_TYPE)
	    elif route_map_seq.match.tag != None: 
                handle_match_tag(frr_cfg, routemap, route_map_seq, ADDR_TYPE)
            # Match by Community
            elif len(route_map_seq.match.community_list) > 0:
                handle_match_community_list(frr_cfg, routemap, route_map_seq, ADDR_TYPE)
            # No Match - Only Set
            else:
                handle_no_match_set_only(frr_cfg, routemap, route_map_seq, ADDR_TYPE)

#############################################
# Common APIs, will be used by all protocols
#############################################
def get_StringIO():
    if sys.version_info >= (3,):
        return io.StringIO()
    else:
        return cStringIO.StringIO()

def get_address_family(addr_family):
    """ Returns address family as par the input address family type

    ```
    * "addr_family": address family type IPv4_UNICAST/IPv6_UNICAST/VPNv4_UNICAST
    """
    if addr_family == IPv4_UNICAST:
        return 'ipv4 unicast'
    if addr_family == IPv6_UNICAST:
        return 'ipv6 unicast'
    if addr_family == VPNv4_UNICAST:
        return 'ipv4 vpn'
    assert 'Unknown address family'

def get_ip_cmd(addr_type):
    """ Returns ip for ipv4 and ipv6 for ipv6 address as command address

    ```
    * "addr_type": ip type ipv4/ipv6
    """
    if addr_type == ADDR_TYPE_IPv4:
        return 'ip'
    else:
        return 'ipv6'

def IpPrefixMsg_to_str(addr, subnet = True):
    """ Converts ip address to str with attaching mask to ip address

    ```
    * "addr": ip type ipv4/ipv6
    """
    ip_string = ''
    ip_string = IpAddressMsg_to_str(addr)
    if subnet and addr.prefix_length:
        ip_string = ip_string + '/' + str(addr.prefix_length)
    return ip_string

def IpAddressMsg_to_str(addr):
    """ Returns Ip address to str as per the input ip type 

    ```
    * "addr": ip type ipv4/ipv6
    """
 
    if addr.afi == ADDR_TYPE_IPv4:
        return addr.ipv4
    else:
        return addr.ipv6

def number_to_row(routerName):
    """
    Returns the number for the router.
    Calculation based on name a0 = row 0, a1 = row 1, b2 = row 2, z23 = row 23 etc
    """
    return int(routerName[1:])

def number_to_column(routerName):
    """
    Returns the number for the router.
    Calculation based on name a0 = columnn 0, a1 = column 0, b2= column 1, z23 = column 26 etc
    """
    return ord(routerName[0]) - 97

def generate_ips(ADDR_TYPE, start_ip, no_of_ips):
    """
    Returns list of IPs.
    based on start_ip and no_of_ips
    
    * `ADDR_TYPE` : to identify ip address type ex- ipv4/ipv6
    * `start_ip`  : from here the ip will start generating, start_ip will be first ip
    * `no_of_ips` : these many IPs will be generated

    Limitation: It will generate IPs only for ip_mask 32
    
    """

    if '/' in start_ip:
        start_ip = start_ip.split("/")[0]

    if ADDR_TYPE == 'ipv4':
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

def assign_number_to_routers(listRouters):
    """
    It will assign numbers to router ex- r1:1, r2:2.....r10:10
    these number would be used to save/access configuration in/from frr.conf file.
    """
    for routerNumber, routerName in enumerate(listRouters, 1):
        number_to_router[routerName] = routerNumber

def find_interface_with_greater_ip(ADDR_TYPE, topo, router):
    """  
    Returns highest interface ip for ipv4/ipv6
 
    * `ADDR_TYPE`  : ip type, ipv4/ipv6
    * `topo`  : json file data
    * `router` : router for which hightest interface should be calculated 
    """

    if ADDR_TYPE == "ipv4":
        if 'lo' in topo['routers'][router]:
            return topo['routers'][router]['lo']['ipv4'].split('/')[0]
        interfaces_list = []
        for destRouter  in sorted(topo['routers'][router]['links'].iteritems()):
            for link in topo['routers'][curRouter]['links'][destRouter[0]].iteritems():
                if 'ipv4' in topo['routers'][router]['links'][destRouter[0]][link[0]]:
                    ip_address = topo['routers'][router]['links'][destRouter[0]][link[0]]['ipv4'].split('/')[0]
                    interfaces_list.append(ipaddress.IPv4Address(ip_address))
    else:
        if 'lo' in topo['routers'][router]:
            ip_address = topo['routers'][router]['lo']['ipv6'].split('/')[0]
            return ipaddress.IPv4Address(ip_address)
        interfaces_list = []
        for destRouter in sorted(topo['routers'][router]['links'].iteritems()):
            for link in topo['routers'][curRouter]['links'][destRouter[0]].iteritems():
                if 'ipv6' in topo['routers'][router]['links'][destRouter[0]][link[0]]:
                    ip_address = topo['routers'][router]['links'][destRouter[0]][link[0]]['ipv6'].split('/')[0]
                    interfaceis_list.append(ipaddress.IPv4Address(ip_address))

    return sorted(interfaces_list)[-1]

def load_config_to_router(tgen, CWD, routerName):
    """ 
    This API is to create a delta of running config and user defined config, upload the delta config to router. 
 
    * `tgen` : Topogen object
    * `CWD`  : caller's current working directory
    * `routerName` : router for which delta config should be generated and uploaded
    """

    logger.info('Entering API: load_common_config_to_router')

    try:
        router_list = tgen.routers()
        for rname, router in router_list.iteritems():
            if rname == routerName:

                cfg = router.run("vtysh -c 'show running'")
                fname = '{}/{}/frr.sav'.format(CWD, rname)
                dname = '{}/{}/delta.conf'.format(CWD, rname)
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
                    with open('{}/{}/frr.conf'.format(CWD, rname), 'w') as cfg:
                        for f_name in filenames:
			    if os.path.exists('{}/{}/{}'.format(CWD, rname, f_name)):
                                with open('{}/{}/{}'.format(CWD, rname, f_name), 'r') as infile:
                                    for line in infile:
                                        cfg.write(line)
                except IOError as err:
                   logger.warning('Unable to open config File. error(%s): %s' % (err.errno, err.strerror))
                   return False

                command = '/usr/lib/frr/frr-reload.py  --input {}/{}/frr.sav --test {}/{}/frr.conf > \
				{}'.format(CWD, rname, CWD, rname, dname)
                result = os.system(command)

                # Assert if command fail
                if result != 0:
                    command_output = False
                    assert command_output, 'Command:{} is failed due to non-zero exit code'.format(command)

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

                # Router current configuration to log file or console if "show_router_config"
		#  is defined in "pytest.ini"
                if show_router_config:
                    logger.info(delta.getvalue())
                delta.close()
    except Exception as e:
        logger.error(traceback.format_exc())
        return False

    logger.info('Exting API: load_common_config_to_router')
    return True

#############################################
# These APIs,  will used by testcase
#############################################
def create_interfaces_cfg(curRouter, topo):
    """ Create interface configuration for created topology and
        save the configuration to frr.conf file. Basic Interface configuration
        is provided in input json file.
    
    * `curRouter` : router for which interface config should be created
    * `topo` : json file data
    """

    try:
        interfaces = Interfaces()
        if 'lo' in topo['routers'][curRouter]:
            interface_name = 'lo'
            lo_addresses = []
            if 'ipv4' in topo['routers'][curRouter]['lo']:
                lo_addresses.append(topo['routers'][curRouter]['lo']['ipv4'])
            if 'ipv6' in topo['routers'][curRouter]['lo']:
                lo_addresses.append(topo['routers'][curRouter]['lo']['ipv6'])
            interfaces.add_interface(interface_name, lo_addresses)
        for destRouterLink, data in sorted(topo['routers'][curRouter]['links'].iteritems()):
            interface_name = topo['routers'][curRouter]['links'][destRouterLink]['interface']
            int_addresses = []
            if 'ipv4' in topo['routers'][curRouter]['links'][destRouterLink]:
                int_addresses.append(topo['routers'][curRouter]['links'][destRouterLink]['ipv4'])
            if 'ipv6' in topo['routers'][curRouter]['links'][destRouterLink]:
                int_addresses.append(topo['routers'][curRouter]['links'][destRouterLink]['ipv6'])
            interfaces.add_interface(interface_name, int_addresses)

    except Exception as e:
        logger.error(traceback.format_exc())
        return False

    return interfaces

def add_static_route_for_loopback_interfaces(ADDR_TYPE, curRouter, topo, frrcfg):
    """ 
    Add static routes for loopback interfaces reachability, It will add static routes in current 
    router for other router's loopback interfaces os the reachability will be up and so will BGP neighborship. 
    
    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `curRouter` : Device Under Test
    * `topo` : json file data
    * `frrcfg` : frr config file
    """

    for bgp_neighbor in topo['routers'][curRouter]['bgp']['bgp_neighbors'].keys():
        if topo['routers'][curRouter]['bgp']['bgp_neighbors'][bgp_neighbor]['peer']['source'] == 'lo':
    	    ip_addr = topo['routers'][bgp_neighbor]['lo'][ADDR_TYPE]
            destRouterLink = topo['routers'][curRouter]['bgp']['bgp_neighbors'][bgp_neighbor]['peer']['link']
            next_hop = topo['routers'][bgp_neighbor]['links'][destRouterLink][ADDR_TYPE].split("/")[0]

            if ADDR_TYPE == "ipv4":
                frrcfg.write("ip route " + ip_addr + " " + next_hop + "\n")
            else:
                frrcfg.write("ipv6 route " + ip_addr + " " + next_hop + "\n")


def create_static_routes(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """ 
    Create  static routes for given router as defined in input_dict
    
    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `input_dict` : input to create static routes for given router
    * `tgen` : Topogen object
    * `CWD` : caller's current working directory
    * `topo` : json file data
    """

    try:
	global frr_cfg
        for router in input_dict.keys():
	    if "static_routes" in input_dict[router]:
                static_routes_list = []
   
                # Getting number for router
                i = number_to_router[router]

                # Reset config for routers
                frr_cfg[i].reset_it()

		static_routes = input_dict[router]["static_routes"]
                for static_route in static_routes:
		    network = static_route["network"] 
                    no_of_ip = static_route["no_of_ip"]
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

                    ip_list = generate_ips(ADDR_TYPE, network, no_of_ip)
                    for ip in ip_list:
                        ip = str(ipaddress.ip_network(unicode(ip)))
                        if ADDR_TYPE == "ipv4":
                            addr = Address(ADDR_TYPE_IPv4, ip, None)
                            route = Route(addr)
                            nh = Address(ADDR_TYPE_IPv4, next_hop, None)
                        else:
                            addr = Address(ADDR_TYPE_IPv6, None, ip)
                            route = Route(addr)
                            nh = Address(ADDR_TYPE_IPv6, None, next_hop)
                        route.add_nexthop(nh, None, admin_distance, if_name, tag)

                        static_routes_list.append(route)
                        frr_cfg[i].routing_pb.static_route = static_routes_list

                interfaces_cfg(frr_cfg[i])
                static_rt_cfg(frr_cfg[i])
                frr_cfg[i].print_common_config_to_file(topo)
                # Load configuration to router
                load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg
        
    return True

def modify_admin_distance_for_static_routes(input_dict, CWD, tgen, topo):
    """
    Modify admin distance for given static route/s
    
    * `input_dict` :  for which static route/s admin distance should modified
    * `CWD`  : caller's current working directory
    * `tgen`  : Topogen object
    * `topo`  : json file data
    """
    logger.info("Entering lib API: modify_admin_distance_for_static_routes()")   

    try:
        for router in input_dict.keys():
            # Getting number for router
            i = number_to_router[router]

            # Reset config for routers
            frr_cfg[i].reset_it()
	    
	    for static_route in input_dict[router].keys():
                next_hop = input_dict[router][static_route]['next_hop']
                admin_distance = input_dict[router][static_route]['admin_distance']
           
 	        for st in frr_cfg[i].routing_pb.static_route:
		    st_ip_prefix = IpAddressMsg_to_str(st.prefix)
		    for nh in st.nexthops:
		        if st_ip_prefix == static_route and IpAddressMsg_to_str(nh.ip) == next_hop:
            	            nh.admin_distance = admin_distance
	        
	    interfaces_cfg(frr_cfg[i])
            static_rt_cfg(frr_cfg[i])
            frr_cfg[i].print_common_config_to_file(topo)
    	    # Load config to router
            load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_admin_distance_for_static_routes")
    return True

def create_prefix_lists(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    Create ip prefix lists

    * `ADDR_TYPE`  : ip_type, ipv4/ipv6
    * `input_dict` :  for which static route/s admin distance should modified
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """

    logger.info("Entering lib API: create_prefix_lists()")

    try:
        for router in input_dict.keys():
            if "prefix_lists" in input_dict[router]:
                # Getting number for router
                i = number_to_router[router]
    
                # Reset config for routers
                frr_cfg[i].reset_it()
    
                for prefix_list in input_dict[router]['prefix_lists'].keys():
                    for prefix_dict in input_dict[router]['prefix_lists'][prefix_list]:
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
                            if ADDR_TYPE == 'ipv4':
                                net = Network(ADDR_TYPE_IPv4, ip, None, int(mask))
                            else:
                                net = Network(ADDR_TYPE_IPv6, None, ip, int(mask))
                        else:
                            net = None
    
                        pfx = Pfx(le, ge, action, net, seqid)
                        pfx_l = PrefixList(prefix_list)
                        pfx_l.add_pfx(pfx)
                        frr_cfg[i].routing_pb.prefix_lists.append(pfx_l)
    
                interfaces_cfg(frr_cfg[i])
                static_rt_cfg(frr_cfg[i])
                prefixlist_cfg(frr_cfg[i], ADDR_TYPE)
                frr_cfg[i].print_common_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, CWD, router)
    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: create_prefix_lists()")
    return True

def delete_prefix_lists(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    Delete ip prefix lists
    
    * `ADDR_TYPE`  : ip type, ipv4/ipv6
    * `input_dict` :  for which static route/s admin distance should modified
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """
    logger.info("Entering lib API: delete_prefix_lists()")
	
    try:
	global frr_cfg
        for router in input_dict.keys():
            # Getting number for router
            i = number_to_router[router]

            # Reset config for routers
            frr_cfg[i].reset_it()

            prefix_lists = input_dict[router]["prefix_lists"]
	    for prefix_list in prefix_lists:
   	        for pfx_l in frr_cfg[i].routing_pb.prefix_lists:
        	    if pfx_l.prefix_list_uuid_name == prefix_list:
                        frr_cfg[i].routing_pb.prefix_lists.remove(pfx_l)

            interfaces_cfg(frr_cfg[i])
            prefixlist_cfg(frr_cfg[i], ADDR_TYPE)
            frr_cfg[i].print_common_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, CWD, router)
    except Exception as e:
	errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: delete_prefix_lists()")
    return True

def modify_prefix_lists(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    Modify prefix lists
   
    * `ADDR_TYPE`  : ip type, ipv4/ipv6 
    * `input_dict` :  for which static route/s admin distance should modified
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """
    logger.info("Entering lib API: modify_prefix_lists()")

    try:
        for router in input_dict.keys():
            # Getting number for router
            i = number_to_router[router]

            # Reset config for routers
            frr_cfg[i].reset_it()

            for prefix_list in input_dict[router]['prefix_lists'].keys():
                for prefix_dict in input_dict[router]['prefix_lists'][prefix_list]:
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
                        if ADDR_TYPE == 'ipv4':
                            net = Network(ADDR_TYPE_IPv4, ip, None, int(mask))
                        else:
                            net = Network(ADDR_TYPE_IPv6, None, ip, int(mask))
                    else:
                        net = None

                    for pfx_l in frr_cfg[i].routing_pb.prefix_lists:
                        if pfx_l.prefix_list_uuid_name == prefix_list:
                            for pfx in pfx_l.prefix:
                                if seqid != None:
                                    if pfx.seq_id == seqid:
		 			pfx.network = net
					pfx.less_or_equal_bits = le
        				pfx.greater_or_equal_bits = ge
        				pfx.action = action
        				pfx.seqid = seqid

            interfaces_cfg(frr_cfg[i])
            static_rt_cfg(frr_cfg[i])
            prefixlist_cfg(frr_cfg[i], ADDR_TYPE)
            frr_cfg[i].print_common_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_prefix_lists()")
    return True

def create_route_maps(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    Create ip prefix lists

    * `ADDR_TYPE`  : ip_type, ipv4/ipv6
    * `input_dict` :  for which static route/s admin distance should modified
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """

    logger.info("Entering lib API: create_route_maps()")

    try:
        for router in input_dict.keys():
            if "route_maps" in input_dict[router]:
                # Getting number for router
                i = number_to_router[router]
    
                # Reset config for routers
                frr_cfg[i].reset_it()
    
                for rmap_name in input_dict[router]["route_maps"].keys():
		    for rmap_dict in input_dict[router]["route_maps"][rmap_name]:
                        rmap_action = rmap_dict["action"]
    
                        if rmap_action == 'PERMIT':
                            rmap_action = PERMIT
                        else:
                            rmap_action = DENY
    
                        rmap = RouteMap(rmap_name)
                        frr_cfg[i].routing_pb.route_maps.append(rmap)
    
                        # Verifying if SET criteria is defined
                        if 'set' in rmap_dict:
                            if 'localpref' in rmap_dict["set"]:
                                local_preference = rmap_dict["set"]['localpref']
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
    
                            set_criteria = RouteMapSet(local_preference, metric, as_path, None, None, weight)
                        else:
                            set_criteria = None
    
                        # Adding MATCH and SET sequence to RMAP if match criteria is defined
                        if "match" in rmap_dict:
                            match = RouteMapMatch()
                            for match_criteria in rmap_dict["match"].keys():
                                if match_criteria == 'prefix_list':
                                    prefix_lists = []
                                    pfx_list = rmap_dict["match"][match_criteria]
                                    for prefix_list in frr_cfg[i].routing_pb.prefix_lists:
    					if prefix_list.prefix_list_uuid_name == pfx_list:
				            prefix_lists.append(prefix_list)
            			    	    match.prefix_list = prefix_lists
                                            rmap.add_seq(match, rmap_action, set_criteria)
                                elif match_criteria == 'tag':
                                    tag = rmap_dict["match"][match_criteria]
                                    match.tag = tag
                                    rmap.add_seq(match, rmap_action, set_criteria)
    
                interfaces_cfg(frr_cfg[i])
                static_rt_cfg(frr_cfg[i])
                prefixlist_cfg(frr_cfg[i], ADDR_TYPE)
                routemap_cfg(frr_cfg[i], ADDR_TYPE)
                frr_cfg[i].print_common_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, CWD, router)
    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: create_route_maps()")
    return True

def delete_route_maps(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    Delete ip route maps
    
    * `ADDR_TYPE`  : ip type, ipv4/ipv6
    * `input_dict` :  for which static route/s admin distance should modified
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """
    logger.info("Entering lib API: delete_prefix_lists()")

    try:
        global frr_cfg
        for router in input_dict.keys():

            # Getting number for router
            i = number_to_router[router]

            # Reset config for routers
            frr_cfg[i].reset_it()

            route_maps = input_dict[router]['route_maps']
            for route_map in route_maps:
                for rmap in frr_cfg[i].routing_pb.route_maps:
                    if rmap.route_map_uuid_name == route_map:
                        frr_cfg[i].routing_pb.route_maps.remove(rmap)

            interfaces_cfg(frr_cfg[i])
            static_rt_cfg(frr_cfg[i])
            prefixlist_cfg(frr_cfg[i], ADDR_TYPE)
            routemap_cfg(frr_cfg[i], ADDR_TYPE)
            frr_cfg[i].print_common_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, CWD, router)
    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: delete_prefix_lists()")
    return True

#############################################
## Verification APIs
#############################################
def verify_rib(ADDR_TYPE, dut, tgen, input_dict, next_hop = None, protocol = None):
    """ 
    This API is to verify RIB  BGP routes.

    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `dut`: Device Under Test, for which user wants to test the data
    * `input_dict` : input dict, has details of static routes
    * `tgen` : topogen object
    * `next_hop`[optional]: next_hop which needs to be verified, default = static
    * `protocol`[optional]: protocol, default = None
    """

    logger.info("Entering lib API: verify_rib()")

    router_list = tgen.routers()
    for routerInput in input_dict.keys():
        for router, rnode in router_list.iteritems():
            if router != dut:
                continue

            # Verifying RIB routes
	    if protocol != None:
                command = "show ip route {} json".format(protocol)
            else:
                command = "show ip route json"

            sleep(2)
            logger.info('Checking router {} RIB:'.format(router))
            rib_routes_json = rnode.vtysh_cmd(command, isjson=True)
        
	    # Verifying output dictionary rib_routes_json is not empty
            if bool(rib_routes_json) == False:
                errormsg = "No {} route found in rib of router {}..".format(protocol, router)
                return errormsg

            if 'static_routes' in input_dict[routerInput]:
		static_routes = input_dict[routerInput]["static_routes"]
		for static_route in static_routes:
		    found_routes = []
	    	    missing_routes = []
                    network = static_route["network"]
                    no_of_ip = static_route["no_of_ip"]

                    # Generating IPs for verification
                    ip_list = generate_ips(ADDR_TYPE, network, no_of_ip)
                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(unicode(st_rt)))

                        st_found = False
			nh_found = False
                        if st_rt in rib_routes_json:
                            st_found = True
			    found_routes.append(st_rt)

                            if next_hop != None:
                                if rib_routes_json[st_rt][0]['nexthops'][0]['ip'] == next_hop:
                                    nh_found = True
                                else:
                                    errormsg = ("Nexthop {} is Missing for {} route {} in RIB of router {}\n".format( \
										     next_hop, protocol, st_rt, dut))
                                    return errormsg
			else:
			    missing_routes.append(st_rt)
                if nh_found:
		    logger.info("Found next_hop {} for all {} routes in RIB of router {}\n".format(next_hop, protocol, dut))

		if not st_found and len(missing_routes) > 0:
                    errormsg = "Missing route in RIB of router {}, routes: {} \n".format(dut, missing_routes)
                    return errormsg
		
		logger.info("Verified routes in router {} RIB, found routes are: {}\n".format(dut, found_routes))
		
            if 'advertise_networks' in input_dict[routerInput]:
	        found_routes = []
		missing_routes = []
                advertise_network = input_dict[routerInput]['advertise_networks']
                for advertise_network_dict in advertise_network:
                    start_ip = advertise_network_dict['start_ip']
                    if 'no_of_network' in advertise_network_dict:
                        no_of_network = advertise_network_dict['no_of_network']
                    else:
                        no_of_network = 0

                    # Generating IPs for verification
                    ip_list = generate_ips(ADDR_TYPE, start_ip, no_of_network)
                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(unicode(st_rt)))

                        found = False
                        if st_rt in rib_routes_json:
                            found = True
			    found_routes.append(st_rt)
                        else:
                            missing_routes.append(st_rt)

		if not found and len(missing_routes) > 0:
                    errormsg = "Missing route in RIB of router {}, are: {} \n".format(dut, missing_routes)
                    return errormsg
	    
		logger.info("Verified routes in router {} RIB, found routes are: {}\n".format(dut, found_routes))

        logger.info("Exiting lib API: verify_rib()")
        return True

def verify_admin_distance_for_static_routes(input_dict, tgen):
    """ 
    This API is to verify admin distance for static routes.
    
    * `input_dict`: having details like - for which router and static routes admin dsitance needs to be verified
    * `tgen` : topogen object
    """

    logger.info("Entering lib API: verify_admin_distance_for_static_routes()")

    for dut in input_dict.keys():
        for router, rnode in tgen.routers().iteritems():
            if router != dut:
                continue

            show_ip_route_json = rnode.vtysh_cmd("show ip route json", isjson=True)
            for static_route in input_dict[dut].keys():
                logger.info('Verifying admin distance for static route {} under dut {}:'.format(static_route, router))
                next_hop = input_dict[dut][static_route]['next_hop']
                admin_distance = input_dict[dut][static_route]['admin_distance']

                if static_route in show_ip_route_json:
                    if show_ip_route_json[static_route][0]['nexthops'][0]['ip'] == next_hop:
                        if show_ip_route_json[static_route][0]['distance'] != admin_distance:
                            errormsg = ('Verification failed: admin distance for static route {} under dut {}, \
				       found:{} but expected:{}'.format(static_route, router, 	\
			    	       show_ip_route_json[static_route][0]['distance'], admin_distance))
                            return errormsg
                        else:
                            logger.info('Verification successful: admin distance for static route {} under dut {}, \
	              	    found:{}'.format(static_route, router, show_ip_route_json[static_route][0]['distance']))

                else:
                    errormsg = ('Static route {} not found in show_ip_route_json for dut {}'.format(static_route, router))
                    return errormsg

    logger.info("Exiting lib API: verify_admin_distance_for_static_routes()")
    return True

