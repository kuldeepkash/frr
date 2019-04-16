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

import ipaddress
import traceback
from time import sleep
from lib.topolog import logger, logger_config

# Import common_config to use commomnly used APIs
from lib.common_config import *

BGPCFG_FILE = 'bgp_json.conf'
bgp_cfg = {}
BGP_CONVERGENCE_TIMEOUT = 10

###
class BGPRoutingPB:

    def __init__(self, router_id):
        self.bgp_config = None
        self.community_lists = []
        self.redistribute_static = None
	self.redistribute_static_route_map = None
        self.redistribute_connected = None
	self.redistribute_connected_route_map = None
        self.routing_global = {'router_id': router_id}


class BGPConfig:

    def __init__(self, router, routing_cfg_msg, bgpcfg_file):
        self.router = router
        self.routing_pb = routing_cfg_msg
        self.bgp_global = get_StringIO()
        self.bgp_neighbors = get_StringIO()
        self.bgp_address_family = {}
        self.as_path_prepend = False
        self.bgp_address_family[IPv4_UNICAST] = get_StringIO()
        self.bgp_address_family[IPv6_UNICAST] = get_StringIO()
        self.bgp_address_family[VPNv4_UNICAST] = get_StringIO()
        self.community_list = get_StringIO()
        self._community_list_regex_index = 0
        self.bgpcfg_file =  bgpcfg_file

    def reset_it(self):
        self.bgp_global = get_StringIO()
        self.bgp_neighbors = get_StringIO()
        self.bgp_address_family = {}
        self.as_path_prepend = False
        self.bgp_address_family[IPv4_UNICAST] = get_StringIO()
        self.bgp_address_family[IPv6_UNICAST] = get_StringIO()
        self.bgp_address_family[VPNv4_UNICAST] = get_StringIO()
        self.community_list = get_StringIO()

    def print_bgp_config_to_file(self, topo):
        try:
            bgpcfg = open(self.bgpcfg_file, 'w')
        except IOError as err:
            logger.error('Unable to open BGP Config File. error(%s): %s' % (
                err.errno, err.strerror))
            return False

        bgpcfg.write("! Community List Config\n")
        bgpcfg.write(self.community_list.getvalue())

        if self.is_bgp_configured:
            bgpcfg.write('! BGP Config\n')
            bgpcfg.write(self.bgp_global.getvalue())
            bgpcfg.write(self.bgp_neighbors.getvalue())
            for addr_family in self.bgp_address_family:
                bgpcfg.write('address-family ' + get_address_family(
                    addr_family) + '\n')
                bgpcfg.write(self.bgp_address_family[addr_family].getvalue())
                bgpcfg.write('exit-address-family\n')
            bgpcfg.write('line vty\n')
            bgpcfg.close()
        return True

    def close(self):
        self.bgp_neighbors.close()
        self.bgp_global.close()
        for addr_family in self.bgp_address_family:
            self.bgp_address_family[addr_family].close()

def create_bgp_cfg(router, topo):
    """
    Create BGP configuration for created topology and
    save the configuration to frr.conf file. BGP configuration
    is provided in input json file.

    * `router` : router for which bgp config should be created
    * `topo` : json file data
    """

    try:
        # Setting key to bgp to read data from json file for bgp configuration
        key = 'bgp'
        local_as = topo['routers']['{}'.format(router)][key]['local_as']
        if "ecmp" in topo['routers']['{}'.format(router)][key]:
	    ecmp = topo['routers']['{}'.format(router)][key]['ecmp']
	else:
	    ecmp = 1
	if "gracefulrestart" in topo['routers']['{}'.format(router)][key]:
            gracefull_restart = topo['routers']['{}'.format(router)][key][
                'gracefulrestart']
	else:
	    gracefull_restart = False
	if "enabled" in topo['routers']['{}'.format(router)][key]:
            bgp_enabled = topo['routers']['{}'.format(router)][key]['enabled']
	else:
	    bgp_enabled = True
        bgp_cfg[router].is_bgp_configured = bgp_enabled
        bgp = Bgp(local_as, gracefull_restart, ecmp)

        neighbors = topo['routers']['{}'.format(router)][key]['bgp_neighbors']
        for neighbor_name, data in neighbors.iteritems():
            remote_as = neighbors[neighbor_name]['remote_as']
	    if "holddowntimer" in neighbors[neighbor_name]:
                holddowntimer = neighbors[neighbor_name]['holddowntimer']
	    else:
		holddowntimer = None
	    if "keepalivetimer" in neighbors[neighbor_name]:
                keepalivetimer = neighbors[neighbor_name]['keepalivetimer']
	    else:
		keepalivetimer = None

            # Peer details
            peer = neighbors[neighbor_name]['peer']
            dest_link = peer['dest_link']
            ADDR_TYPE = peer['addr_type']
            # TODO
            # Add support for multiple loopback address
            # Loopback interface
            nb_name = topo['routers'][neighbor_name]
            if "source_link" in peer and peer['source_link'] == 'lo':
                ip_addr = nb_name['lo'][ADDR_TYPE].split('/')[0]
                update_source = topo['routers']['{}'.format(router)]['lo'][
                    ADDR_TYPE].split('/')[0]
                if ADDR_TYPE == "ipv4":
                    af_modifier = IPv4_UNICAST
                else:
                    af_modifier = IPv6_UNICAST

                addr = Address(af_modifier, ip_addr, None)
                neighbor = bgp.add_neighbor(af_modifier, addr, remote_as,
                                            keepalivetimer, holddowntimer,
                                            None, update_source, 2)
                neighbor.add_address_family(af_modifier, True, None, None,
                                            None, None)

            # Physical interface
            else:
                for destRouterLink, data in sorted(nb_name['links'].
                                                   iteritems()):
                    if dest_link == destRouterLink:
                        ip_addr = nb_name['links'][destRouterLink][ADDR_TYPE].\
                                          split('/')[0]
                        if ADDR_TYPE == "ipv4":
                            af_modifier = IPv4_UNICAST
                        else:
                            af_modifier = IPv6_UNICAST

                        addr = Address(af_modifier, ip_addr, None)
                        neighbor = bgp.add_neighbor(af_modifier, addr,
                                                    remote_as, keepalivetimer,
                                                    holddowntimer, None,
                                                    None, 0)
                        neighbor.add_address_family(af_modifier, True, None,
                                                    None, None, None)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return bgp

def create_bgp_configuration(ADDR_TYPE, tgen, CWD, topo, router):
    """
    It will create bgp.conf file, in which all the routers common configuration
    would be saved

    * `ADDR_TYPE` : ip type ipv4/ipv6
    * `tgen` : Topogen object
    * `CWD`  : caller's current working directory
    * `topo` : json file data
    * `router` : current router
    """

    try:
        global bgp_cfg
        listRouters = []
        for routerN in topo['routers'].iteritems():
            listRouters.append(routerN[0])

        listRouters.sort()

        for curRouter in listRouters:
            if curRouter != router:
                continue

	    if 'bgp' in topo['routers'][router]:
                if 'router-id' in topo['routers'][router]['bgp']:
                    rid = topo['routers'][router]['bgp']['router-id']
                    router_id = Address(ADDR_TYPE_IPv4, rid, None)
                else:
                    router_id = None

                rt_cfg = BGPRoutingPB(router_id)

                fname = '{}/{}/{}'.format(CWD, router, BGPCFG_FILE)
                bgp_cfg[router] = BGPConfig(router, rt_cfg, fname)
                bgp_cfg[router].is_standby = False

                input_dict = topo['routers']
                bgp_cfg[router].routing_pb.bgp_config = create_bgp_cfg(router, topo)
                Bgp_cfg(bgp_cfg[router])
                bgp_cfg[router].print_bgp_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, CWD, router)

                if 'redistribute' in topo['routers'][router]:
                    result = redistribute_static_routes(ADDR_TYPE, input_dict,
                                                    tgen, CWD, topo)
                    assert result is True, ("API: redistribute_static_routes() "
                                        ":Failed \n Error: {}".format(result))

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return True

# Helper class for Address type  configuration
class Address:

    def __init__(self, afi, ipv4=None, ipv6=None):
        self.afi = afi
        self.ipv4 = ipv4
        self.ipv6 = ipv6

# Helper class for Address family configuration
class AddressFamily:

    def __init__(self, ad_family, enabled=None, filter_in_prefix_list=None,
                 filter_out_prefix_list=None, filter_in_rmap=None,
                 filter_out_rmap=None, next_hop_self = False):
        self.type = ad_family
        self.enabled = enabled
        self.filter_in_prefix_list = filter_in_prefix_list
        self.filter_out_prefix_list = filter_out_prefix_list
        self.filter_in_rmap = filter_in_rmap
        self.filter_out_rmap = filter_out_rmap
	self.next_hop_self = next_hop_self

# Helper class for BGP Neighbor configuration
class Neighbor:

    def __init__(self, afi, ip_address, remote_as, keep_alive_time=None,
                 hold_down_time=None, password=None, update_source=None,
                 max_hop_limit = 0):
        self.afi = afi
        self.ip_address = ip_address
        self.remote_as = remote_as
        self.keep_alive_time = keep_alive_time
        self.hold_down_time = hold_down_time
        self.password = password
        self.max_hop_limit = max_hop_limit
        self.update_source = update_source 
        self.address_families = []

    def add_address_family(self, ad_family, enabled=None,
                           filter_in_prefix_list=None,
                           filter_out_prefix_list=None,
                           filter_in_rmap=None,
                           filter_out_rmap=None,
			   next_hop_self = False):
        for f in self.address_families:
            if f.type == ad_family:
                f.enabled = enabled
                f.filter_in_prefix_list = filter_in_prefix_list
                f.filter_out_prefix_list = filter_out_prefix_list
                f.filter_in_rmap = filter_in_rmap
                f.filter_out_rmap = filter_out_rmap
		f.next_hop_self = next_hop_self
                return

        family = AddressFamily(ad_family, enabled, filter_in_prefix_list,
                               filter_out_prefix_list, filter_in_rmap,
                               filter_out_rmap, next_hop_self = False)
        self.address_families.append(family)

    def del_address_family(self, ad_family):
        for f in self.address_families:
            if f.type == ad_family:
                self.address_families.remove(f)

# Helper class for BGP configuration
class Bgp:

    def __init__(self, local_as, graceful_restart, ecmp):
        self.local_as = local_as
        self.graceful_restart = graceful_restart
        self.ecmp = ecmp
        self.neighbors = []

    def add_neighbor(self, afi, ip_address, remote_as, keep_alive_time=None,
                     hold_down_time=None, password=None, update_source=None,
                     max_hop_limit=None):
        for n in self.neighbors:
            if n.afi == afi and n.ip_address == ip_address:
                n.remote_as = remote_as
                n.keep_alive_time = keep_alive_time
                n.hold_down_time = hold_down_time
                n.password = password
                n.update_source = update_source
                n.max_hop_limit = max_hop_limit
                return

        neighbor = Neighbor(afi, ip_address, remote_as, keep_alive_time,
                            hold_down_time, password, update_source,
                            max_hop_limit)
        self.neighbors.append(neighbor)
        return neighbor

    def get_neighbor(self, afi, ip_address):
        for n in self.neighbors:
            if n.afi == afi and n.ip_address.ipv4 == ip_address.ipv4:
                return n

    def del_neighbor(self, afi, ip_address):
        for n in self.neighbors:
            if n.afi == afi and n.ip_address == ip_address:
                self.neighbors.remove(n)


def _print_bgp_global_cfg(bgp_cfg, local_as_no, router_id, ecmp_path,
                          gr_enable):
    bgp_cfg.bgp_global.write('router bgp ' + str(local_as_no) + '\n')
    if router_id != None:
        bgp_cfg.bgp_global.write('bgp router-id ' + IpAddressMsg_to_str(
            router_id) + ' \n')
    bgp_cfg.bgp_global.write('no bgp network import-check\n')
    if ecmp_path > 1:
        bgp_cfg.bgp_global.write('maximum-paths ' + str(ecmp_path) + '\n')
    bgp_cfg.bgp_global.write('bgp fast-external-failover\n')
    bgp_cfg.bgp_global.write('bgp log-neighbor-changes\n')
    if gr_enable:
        bgp_cfg.bgp_global.write(' bgp graceful-restart\n')

def _print_bgp_address_family_cfg(bgp_cfg, neigh_ip, addr_family):
    out_filter_or_rmap = False
    neigh_cxt = 'neighbor ' + neigh_ip + ' '

    # next-hop-self
    if addr_family.next_hop_self != False:
       bgp_cfg.bgp_address_family[addr_family.type].write(
            neigh_cxt + 'next-hop-self' '\n')

    bgp_cfg.bgp_address_family[addr_family.type].write(neigh_cxt + 'activate\n')

    # PL_IN
    if addr_family.filter_in_prefix_list != None:
        bgp_cfg.bgp_address_family[addr_family.type].write(
                neigh_cxt + 'prefix-list ' + addr_family.filter_in_prefix_list + ' in\n')
    # PL_OUT
    if addr_family.filter_out_prefix_list != None:
        bgp_cfg.bgp_address_family[addr_family.type].write(
                neigh_cxt + 'prefix-list ' + addr_family.filter_out_prefix_list + ' out\n')
        out_filter_or_rmap = True
    # RM_IN
    if addr_family.filter_in_rmap != None:
        bgp_cfg.bgp_address_family[addr_family.type].write(
                neigh_cxt + 'route-map ' + addr_family.filter_in_rmap + ' in\n')
    # RM_OUT
    if addr_family.filter_out_rmap != None:
        bgp_cfg.bgp_address_family[addr_family.type].write(
                neigh_cxt + 'route-map ' + addr_family.filter_out_rmap + ' out\n')
        out_filter_or_rmap = True
    # AS_PATH_PREPEND
    if not out_filter_or_rmap and bgp_cfg.as_path_prepend:
        if addr_family.type == IPv4_UNICAST:
            bgp_cfg.bgp_address_family[IPv4_UNICAST].write(
                neigh_cxt + ' route-map ' + AS_PREPEND_RMAP_V4 + ' out\n')
        if addr_family.type == IPv6_UNICAST:
            bgp_cfg.bgp_address_family[IPv6_UNICAST].write(
                neigh_cxt + ' route-map ' + AS_PREPEND_RMAP_V6 + ' out\n')

def _print_bgp_neighbors_cfg(bgp_cfg, neighbor):
    neigh_ip = IpAddressMsg_to_str(neighbor.ip_address)
    neigh_cxt = 'neighbor ' + neigh_ip + ' '
    bgp_cfg.bgp_neighbors.write(
        neigh_cxt + 'remote-as ' + str(neighbor.remote_as) + '\n')
    bgp_cfg.bgp_neighbors.write(neigh_cxt + 'activate\n')
    bgp_cfg.bgp_neighbors.write(neigh_cxt + 'disable-connected-check\n')
    if neighbor.update_source != None:
        bgp_cfg.bgp_neighbors.write(
            neigh_cxt + 'update-source ' + neighbor.update_source + ' \n')
    keep_alive = '60'
    hold_down = '180'
    if neighbor.keep_alive_time and neighbor.hold_down_time:
        keep_alive = str(neighbor.keep_alive_time)
        hold_down = str(neighbor.hold_down_time)
    bgp_cfg.bgp_neighbors.write(
        neigh_cxt + 'timers ' + keep_alive + ' ' + hold_down + '\n')
    if neighbor.password != None:
        bgp_cfg.bgp_neighbors.write(
            neigh_cxt + 'password ' + neighbor.password + '\n')
    if neighbor.max_hop_limit > 1:
        bgp_cfg.bgp_neighbors.write(
            neigh_cxt + 'ebgp-multihop ' + str(neighbor.max_hop_limit) + '\n')
        bgp_cfg.bgp_neighbors.write(neigh_cxt + 'enforce-multihop\n')
    for addr_family in neighbor.address_families:
        if addr_family.type not in [IPv4_UNICAST, IPv6_UNICAST, VPNv4_UNICAST]:
            logger.error('unsupported address family')
            return False
        if addr_family.type == VPNv4_UNICAST and not addr_family.enabled:
            logger.error('vpnv4 family is not enabled')
            return False
        _print_bgp_address_family_cfg(bgp_cfg, neigh_ip, addr_family)


def _print_ipv6_prefix_list(bgp_cfg, name, action):
    bgp_cfg.prefix_lists.write('ipv6 prefix-list ' + name + ' ' + action + '\n')

def _print_as_prepand_access_list(bgp_cfg):
    _print_ipv6_prefix_list(bgp_cfg, IPV6_PREFIXLIST_RSVD1, 'permit  any')

def _print_as_prepand_rmap(bgp_cfg, local_as, repeat = 3):
    as_prepend = (str(local_as) + ' ') * repeat
    _print_as_prepand_access_list(bgp_cfg)
    bgp_cfg.route_maps.write('route-map ' + AS_PREPEND_RMAP_V4 + ' permit  10\n')
    bgp_cfg.route_maps.write(
        'match ip address ' + IPV4_ACCESSLIST_NUMBER_RSVD1 + '\n')
    bgp_cfg.route_maps.write('set  as-path  prepend ' + as_prepend + '\n')
    bgp_cfg.route_maps.write('route-map ' + AS_PREPEND_RMAP_V6 + ' permit  10\n')
    bgp_cfg.route_maps.write('set as-path  prepend ' + as_prepend + '\n')


def Bgp_cfg(bgp_cfg):
    if not bgp_cfg.is_bgp_configured:
        logger.debug('BGP is disabled')
        return
    bgp = bgp_cfg.routing_pb.bgp_config
    if bgp_cfg.is_standby:
        bgp_cfg.as_path_prepend = True
        _print_as_prepand_rmap(bgp_cfg, bgp.local_as)
    _print_bgp_global_cfg(bgp_cfg, bgp.local_as,
                          bgp_cfg.routing_pb.routing_global['router_id'],
                          bgp.ecmp, bgp.graceful_restart)
    for neighbor in bgp.neighbors:
        _print_bgp_neighbors_cfg(bgp_cfg, neighbor)

def redist_cfg(bgp_cfg, ADDR_TYPE):
    """
    To redistribute static and connected  routes for given router.

    * `bgp_cfg` : bgp config file to save router's bgp config
    * `ADDR_TYPE` : ip type, ipv4/6
    """

    try:
        if bgp_cfg.is_bgp_configured:
            if ADDR_TYPE == "ipv4":
                af_modifier = IPv4_UNICAST
            else:
                af_modifier = IPv6_UNICAST
            if bgp_cfg.routing_pb.redistribute_static == True:
		if bgp_cfg.routing_pb.redistribute_static_route_map != None:
                    bgp_cfg.bgp_address_family[af_modifier].write(
                    'redistribute static route-map {} \n'.\
	 	    format(bgp_cfg.routing_pb.redistribute_static_route_map))
		else:
		    bgp_cfg.bgp_address_family[af_modifier].write(
                                'redistribute static \n')

            if bgp_cfg.routing_pb.redistribute_connected == True:
		if bgp_cfg.routing_pb.redistribute_connected_route_map != None:
                    bgp_cfg.bgp_address_family[af_modifier].write(
                    'redistribute connected route-map {} \n'.\
	 	    format(bgp_cfg.routing_pb.redistribute_connected_route_map))
		else:
                    bgp_cfg.bgp_address_family[af_modifier].write(
                                'redistribute connected\n')

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
	return errormsg

    return True

# Helper class for Community list configuration
class Community:
    def __init__(self, community, community_type, community_action, community_number):
        self.community = community
        self.community_type = community_type
        self.community_action = community_action
        self.community_number = community_number

class CommunityList:
    def __init__(self, name):
        self.comm_list_uuid_name = name
        self.community = []
    def add_community(self, community):
        self.community.append(community)

class Expression:
    def __init__(self, match_community_sg_condition, regular_expression, community_list):
        self.regular_expression = regular_expression
        self.match_community_sg_condition = match_community_sg_condition
        self.community_list = community_list

def community_list_cfg(bgp_cfg):
    if bgp_cfg.routing_pb.community_lists == None:
        return
    for communities in bgp_cfg.routing_pb.community_lists:
        name = communities.comm_list_uuid_name
        for community in communities.community:
            # Community action
            if community.community_action == 'PERMIT':
                action = 'permit'
            else:
                action = 'deny'

            bgp_cfg.community_list.write(' '.join([
                'bgp', str(community.community) , str(community.community_type), name, action, str(community.community_number), '\n']))

# These APIs will used by testcases
def find_ibgp_and_ebgp_peers_in_topology(peer_type, topo):
    """
    It will find ebgp/ibgp peer

    * `peer_type` : type of bgp neighborship, ebgp/ibgp
    * `topo`  : json file data

    """

    peers = {}
    for router, data in sorted(topo['routers'].iteritems()):
        peers_list = []
        ebgp_peers_dict = {}
        ibgp_peers_dict = {}

        #peers_list.append(router)
        local_as = topo['routers'][router]['bgp']['local_as']
        for neighbor, data in topo['routers'][router]['bgp'][
            'bgp_neighbors'].iteritems():
            remote_as = topo['routers'][router]['bgp']['bgp_neighbors'][
                neighbor]['remote_as']
            peer = topo['routers'][router]['bgp']['bgp_neighbors'][neighbor][
                'peer']['name']

            if peer_type == "ibgp":
                if local_as == remote_as:
                    peers_list.append(peer)
                    ibgp_peers_dict["ibgp_peers"] = peers_list
                    peers[router] = ibgp_peers_dict
            else:
                if local_as != remote_as:
                    peers_list.append(peer)
                    ebgp_peers_dict["ebgp_peers"] = peers_list
                    peers[router] = ebgp_peers_dict

    return peers

def modify_delete_router_id(action, input_dict, CWD, tgen, topo):
    """
    Modify or delete router-id for a given router

    * `action :  action to be performed, modify/delete
    * `input_dict` :  for which router/s router-id should modified or deleted
    * `CWD`  : caller's current working directory
    * `tgen`  : Topogen object
    * `topo`  : json file data
    """
    logger.info("Entering lib API: modify_delete_router_id()")

    try:
        if action == 'modify':
            for router in input_dict.keys():
                # Reset FRR config
                bgp_cfg[router].reset_it()

                router_id = input_dict[router]['router_id']
                rid = str(ipaddress.IPv4Address(unicode(router_id)))
                router_id = Address(ADDR_TYPE_IPv4, rid, None)

                bgp_cfg[router].routing_pb.routing_global['router_id'] = router_id

                Bgp_cfg(bgp_cfg[router])
                bgp_cfg[router].print_bgp_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, CWD, router)
        elif action == 'delete':
            for router in input_dict["router_ids"]:
                # Reset FRR config
                bgp_cfg[router].reset_it()

                router_id = None
                bgp_cfg[router].routing_pb.routing_global['router_id'] = router_id

                Bgp_cfg(bgp_cfg[router])
                bgp_cfg[router].print_bgp_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_delete_router_id()")
    return True

def modify_bgp_timers(ADDR_TYPE, input_dict, CWD, tgen, topo):
    """
    Modify admin distance for given static route/s

    * `ADDR_TYPE` :  ip_type, ipv4/ipv6
    * `input_dict` :  for which static route/s admin distance should modified
    * `CWD`  : caller's current working directory
    * `tgen`  : Topogen object
    * `topo`  : json file data
    """
    logger.info("Entering lib API: modify_bgp_timers()")

    try:
        for router in input_dict.keys():
            # Reset config for routers
            bgp_cfg[router].reset_it()

            neighbors = bgp_cfg[router].routing_pb.bgp_config.neighbors
            for neighbor in neighbors:
                for bgp_neighbor in input_dict[router]["bgp"]["bgp_neighbors"].\
				    keys():
                    keepalivetimer = input_dict[router]["bgp"]["bgp_neighbors"]\
					       [bgp_neighbor]["keepalivetimer"]
                    holddowntimer = input_dict[router]["bgp"]["bgp_neighbors"]\
				              [bgp_neighbor]["holddowntimer"]

                    # Peer details
                    peer = topo['routers'][router]["bgp"]["bgp_neighbors"]\
			       [bgp_neighbor]['peer']
                    dest_link = peer['dest_link']

                    # Loopback interface
                    if "source_link" in peer and peer['source_link'] == 'lo':
                        neighbor_ip = topo['routers'][bgp_neighbor]['lo'][ADDR_TYPE].\
				 	  split('/')[0]
                    else:
                        # Physical interface
                        for destRouterLink in topo['routers'][bgp_neighbor]['links'].\
						  iteritems():
                            if dest_link == destRouterLink[0]:
                                neighbor_ip = \
                                topo['routers'][bgp_neighbor]['links'][destRouterLink[0]]\
				    [ADDR_TYPE].split("/")[0]

                    if IpAddressMsg_to_str(neighbor.ip_address) == neighbor_ip:
                        neighbor.keep_alive_time = str(keepalivetimer)
                        neighbor.hold_down_time = str(holddowntimer)

                Bgp_cfg(bgp_cfg[router])
                bgp_cfg[router].print_bgp_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_bgp_timers()")
    return True

def advertise_networks_using_network_command(ADDR_TYPE, input_dict, tgen, CWD,
                                             topo):
    """
    Advertise network using network command

    * `ADDR_TYPE` : ip type, ipv4/6
    * `input_dict` :  for which static route/s admin distance should modified
    * `CWD`  : caller's current working directory
    * `tgen`  : Topogen object
    * `topo`  : json file data
    """
    logger.info("Entering lib API: advertise_networks_using_network_command()")

    try:
        for router in input_dict.keys():
            networks = []

            # Reset config for routers
            #bgp_cfg[router].reset_it()

            advertise_network = input_dict[router]['advertise_networks']
            for advertise_network_dict in advertise_network:
                start_ip = advertise_network_dict['start_ip']
                if 'no_of_network' in advertise_network_dict:
                    no_of_network = advertise_network_dict['no_of_network']
                else:
                    no_of_network = 0

                network_list = generate_ips(ADDR_TYPE, start_ip, no_of_network)
                for ip in network_list:
                    ip = str(ipaddress.ip_network(unicode(ip)))
                    if ADDR_TYPE == "ipv4":
                        addr = Address(ADDR_TYPE_IPv4, ip, None)
                        # IPv4
                        bgp_cfg[router].bgp_address_family[IPv4_UNICAST].write(
                            'network ' + IpAddressMsg_to_str(addr) + '\n')
                    else:
                        addr = Address(ADDR_TYPE_IPv6, None, ip)
                        # IPv6
                        bgp_cfg[router].bgp_address_family[IPv6_UNICAST].write(
                            'network ' + IpAddressMsg_to_str(addr) + '\n')

            Bgp_cfg(bgp_cfg[router])
            bgp_cfg[router].print_bgp_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: advertise_networks_using_network_command()")
    return True

def modify_AS_number(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    Modify existing AS number

    * `ADDR_TYPE` : ip type, ipv4/6
    * `input_dict` :  for which static route/s admin distance should modified
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """

    logger.info("Entering lib API: modify_AS_number()")

    try:
        for router in input_dict.keys():
            networks = []

            # Reset config for routers
            bgp_cfg[router].reset_it()

            local_as = input_dict[router]["local_as"]
            bgp_cfg[router].routing_pb.bgp_config.local_as = local_as
            neighbors = input_dict[router]["bgp_neighbors"]
            for neighbor in neighbors.keys():
                remote_as = input_dict[router]["bgp_neighbors"][neighbor]['remote_as']

                # loopback interface
                bgp_neighbors = topo['routers'][router]["bgp"]["bgp_neighbors"]
                if "source_link" in bgp_neighbors[neighbor]['peer'] \
                    and bgp_neighbors[neighbor]['peer']['source_link'] == 'lo':
                    ip_address = topo['routers'][neighbor]['lo'][
                        ADDR_TYPE].split("/")[0]
                else:
                    # Physical interface
                    # Peer Details
                    peer = bgp_neighbors[neighbor]['peer']
                    dest_link = peer['dest_link']

                    for destRouterLink in topo['routers'][neighbor]['links'].\
                            iteritems():
                        if dest_link == destRouterLink[0]:
                            ip_address = topo['routers'][neighbor]['links'][
                                destRouterLink[0]][ADDR_TYPE].split("/")[0]

                neighbors = bgp_cfg[router].routing_pb.bgp_config.neighbors
                for n in neighbors:
                    if ADDR_TYPE == 'ipv4':
                        if n.ip_address.ipv4 == ip_address:
                            n.remote_as = remote_as
                    else:
                        if n.ip_address.ipv6 == ip_address:
                            n.remote_as = remote_as

            Bgp_cfg(bgp_cfg[router])
            bgp_cfg[router].print_bgp_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_AS_number()")
    return True

def redistribute_static_routes(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    redistribute static or connected routes or networks

    * `ADDR_TYPE` : ip type, ipv4/6
    * `input_dict` :  for which router routes has to be redistributed as static
                      or connected
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """

    logger.info("Entering lib API: redistribute_static_routes_to_bgp()")

    try:
        global bgp_cfg
        for router in input_dict.keys():
            if "redistribute" in input_dict[router]:
                networks = []

                # Reset config for routers
                #bgp_cfg[router].reset_it()

		bgp_cfg[router].routing_pb.redistribute_static_route_map = None
		bgp_cfg[router].routing_pb.redistribute_connected_route_map = None
                
		redist = input_dict[router]['redistribute']
		for redist_dict in redist:
		    for key, value in redist_dict.items():
			if key == 'static':
			    if value == True or value == "true":
			        bgp_cfg[router].routing_pb.redistribute_static =\
							 True
			    if isinstance(value, dict):
				bgp_cfg[router].routing_pb.redistribute_static_route_map =\
							 value['route-map']
			if key == 'connected':	
			    if value == True or value == "true":
			        bgp_cfg[router].routing_pb.redistribute_connected =\
							 True
			    if isinstance(value, dict):
				bgp_cfg[router].routing_pb.redistribute_connected_route_map =\
							 value['route-map']

                Bgp_cfg(bgp_cfg[router])
                redist_cfg(bgp_cfg[router], ADDR_TYPE)
                bgp_cfg[router].print_bgp_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: redistribute_static_routes_to_bgp()")
    return True

def configure_bgp_neighbors(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    configure bgp neighbors prefix lists

    * `ADDR_TYPE` : ip type ipv4/ipv6
    * `input_dict` :  for which static route/s admin distance should modified
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """
    logger.info("Entering lib API: configure_bgp_neighbors()")

    try:
        for router in input_dict.keys():
            for neighbor in input_dict[router]['neighbor_config'].keys():
                # Reset config for routers
                #bgp_cfg[router].reset_it()

                # Loopback interface
                bgp_neighbors = topo['routers'][router]["bgp"]["bgp_neighbors"]
                if "source_link" in bgp_neighbors[neighbor]['peer'] \
                    and bgp_neighbors[neighbor]['peer']['source_link'] == 'lo':
                    nh_ip = topo['routers'][neighbor]['lo'][
                        ADDR_TYPE].split("/")[0]

                else:
                    # Physical interface
                    # Peer details
                    peer = bgp_neighbors[neighbor]['peer']
                    dest_link = peer['dest_link']

                    for destRouterLink in topo['routers'][neighbor]['links'].\
                            iteritems():
                        if dest_link == destRouterLink[0]:
                            nh_ip = topo['routers'][neighbor]['links'][
                                destRouterLink[0]][ADDR_TYPE].split("/")[0]

                # Apply prefix-list to BGP neighbor
                nb_config = input_dict[router]['neighbor_config']
                if "prefix_list" in nb_config[neighbor]:
                    for prefix_list in nb_config[neighbor]['prefix_list'].keys():
                        direction =  nb_config[neighbor]['prefix_list'][prefix_list]

                        if ADDR_TYPE == "ipv4":
                            af_modifier = IPv4_UNICAST
                            addr = Address(ADDR_TYPE_IPv4, nh_ip, None)
                        else:
                            af_modifier = IPv6_UNICAST
                            addr = Address(ADDR_TYPE_IPv6, None, nh_ip)

                        neighbor = bgp_cfg[router].routing_pb.bgp_config.\
                            get_neighbor(IPv4_UNICAST, addr)
                        if direction == 'IN':
                            neighbor.add_address_family(af_modifier, True,
                                                        prefix_list, None,
                                                        None, None)
                        if direction == 'OUT':
                            neighbor.add_address_family(af_modifier, True,
                                                        None, prefix_list,
                                                        None, None)

                # Apply route map to BGP neighbor
                elif "route_map" in nb_config[neighbor]:
                    for route_map in nb_config[neighbor]['route_map'].keys():
                        direction = nb_config[neighbor]['route_map'][route_map]

                        if ADDR_TYPE == "ipv4":
                            af_modifier = IPv4_UNICAST
                            addr = Address(ADDR_TYPE_IPv4, nh_ip, None)
                        else:
                            af_modifier = IPv6_UNICAST
                            addr = Address(ADDR_TYPE_IPv6, None, nh_ip)

                        neighbor = bgp_cfg[router].routing_pb.bgp_config.\
                            get_neighbor(af_modifier, addr)
                        if direction == 'IN':
                            neighbor.add_address_family(af_modifier, True,
                                                        None, None, route_map,
                                                        None)
                        if direction == 'OUT':
                            neighbor.add_address_family(af_modifier, True,
                                                        None, None, None,
                                                        route_map)

                # Apply next-hop-self to bgp neighbors
                elif "next_hop_self" in input_dict[router]['neighbor_config']\
					[neighbor]:
                    nh_self = input_dict[router]['neighbor_config'][neighbor]\
					["next_hop_self"]

                    if ADDR_TYPE == "ipv4":
                        addr = Address(ADDR_TYPE_IPv4, nh_ip, None)
                        neighbor = bgp_cfg[router].routing_pb.bgp_config.get_neighbor(\
				   IPv4_UNICAST, addr)
                        neighbor.add_address_family(IPv4_UNICAST, True, None, None,\
				    None, None, next_hop_self = nh_self)
                    else:
                        addr = Address(ADDR_TYPE_IPv6, None, nh_ip)
                        neighbor = bgp_cfg[router].routing_pb.bgp_config.get_neighbor(\
				   IPv6_UNICAST, addr)
                        neighbor.add_address_family(IPv6_UNICAST, True, None, None,\
				    None, None, next_hop_self = nh_self)

                # Apply no send-community
                elif "no_send_community" in input_dict[router]['neighbor_config']\
                                        [neighbor]:
                    no_send_community = input_dict[router]['neighbor_config'][neighbor]\
                                        ["no_send_community"]

                    if ADDR_TYPE == "ipv4":
                        addr = Address(ADDR_TYPE_IPv4, nh_ip, None)
                        neighbor = bgp_cfg[router].routing_pb.bgp_config.get_neighbor(\
                                   IPv4_UNICAST, addr)
                        neighbor.add_address_family(IPv4_UNICAST, True, None, None,\
                                    None, None, next_hop_self = nh_self)
                    else:
                        addr = Address(ADDR_TYPE_IPv6, None, nh_ip)
                        neighbor = bgp_cfg[router].routing_pb.bgp_config.get_neighbor(\
                                   IPv6_UNICAST, addr)
                        neighbor.add_address_family(IPv6_UNICAST, True, None, None,\
                                    None, None, next_hop_self = nh_self)

            Bgp_cfg(bgp_cfg[router])
            redist_cfg(bgp_cfg[router], ADDR_TYPE)
            bgp_cfg[router].print_bgp_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: configure_bgp_neighbors()")
    return True

def create_community_lists(ADDR_TYPE, input_dict, tgen, CWD, topo):
    """
    Create community lists

    * `ADDR_TYPE`  : ip type, ipv4/ipv6
    * `input_dict` :  for which static route/s admin distance should modified
    * `tgen`  : Topogen object
    * `CWD`  : caller's current working directory
    * `topo`  : json file data
    """
    logger.info("Entering lib API: create_community_lists()")

    try:
        for router in input_dict.keys():
            if "community-list" in input_dict[router] or \
                "large-community-list" in input_dict[router]:

                # Reset config for routers
                bgp_cfg[router].reset_it()

                for comm_list in input_dict[router].keys():
                    for comm_type in input_dict[router][comm_list].keys():
                        for comm_name in input_dict[router][comm_list][comm_type].\
                            keys():
                                
			    for comm in bgp_cfg[router].routing_pb.community_lists:
                                if comm.comm_list_uuid_name == comm_name:
                                    errormsg = ("Community list is already exists")
                                    return errormsg
                            
			    for comm_dict in input_dict[router][comm_list][comm_type]\
                                [comm_name]:

                                comm_action = comm_dict["action"]
                                comm_attribute = comm_dict["attribute"]

                                comm = CommunityList(comm_name)
                                community = Community(comm_list, comm_type, comm_action,\
                                                               comm_attribute)
                                comm.add_community(community)

                                bgp_cfg[router].routing_pb.community_lists.append(comm)

                Bgp_cfg(bgp_cfg[router])
                redist_cfg(bgp_cfg[router], ADDR_TYPE)
                community_list_cfg(bgp_cfg[router])
                bgp_cfg[router].print_bgp_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, CWD, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: create_community_lists()")
    return True

## Verification APIs
def verify_router_id(input_dict, tgen, topo):
    """
    This API is to verify router-id for any router.

    * `input_dict`: input dictionary, have details of Device Under Test, for
                    which user wants to test the data
    * `tgen`: topogen object
    * `topo`: input json file data
    """
    logger.info("Entering lib API: verify_router_id()")

    if "router_ids" in input_dict:
        for dut in input_dict["router_ids"]:
            for router, rnode in tgen.routers().iteritems():
                if router != dut:
                    continue

                logger.info('Checking router {} router-id'.format(router))
                show_bgp_json = rnode.vtysh_cmd("show ip bgp json", isjson=True)
                router_id_out = show_bgp_json["routerId"]
                router_id_out = ipaddress.IPv4Address(unicode(router_id_out))

                # Once router-id is deleted, highest interface ip should become
                # router-id
                router_id = find_interface_with_greater_ip('ipv4', topo, dut)
                router_id = ipaddress.IPv4Address(unicode(router_id))

                if router_id == router_id_out:
                    logger.info("Found expected router-id {} for router {} \n".
                                format(router_id, router))
                else:
                    errormsg = "Router-id for router:{} mismatch, expected:{}"\
                               " but found:{}".format(router, router_id,
                                                      router_id_out)
                    return errormsg
    else:
        for dut in input_dict.keys():
            for router, rnode in tgen.routers().iteritems():
                if router != dut:
                    continue

                logger.info('Checking router {} router-id'.format(router))
                show_bgp_json = rnode.vtysh_cmd("show ip bgp json", isjson=True)
                router_id_out = show_bgp_json["routerId"]
                router_id_out = ipaddress.IPv4Address(unicode(router_id_out))

                router_id = input_dict[router]['router_id']
                router_id = ipaddress.IPv4Address(unicode(router_id))

                if router_id == router_id_out:
                    logger.info("Found expected router-id {} for router {} \n".
                                format(router_id, router))
                else:
                    errormsg = "Router-id for router:{} mismatch, expected:{}"\
                               " but found:{}".format(router, router_id,
                                                      router_id_out)
                    return errormsg

    logger.info("Exiting lib API: verify_router_id()")
    return True

def verify_bgp_convergence(ADDR_TYPE, tgen, topo):
    """
    This API is to verify BGP-Convergence on any router.

    * `ADDR_TYPE`: ip_type, ipv4/ipv6
    * `tgen`: topogen object
    * `topo`: input json file data
    """

    logger.info("Entering lib API: verify_bgp_confergence()")

    for router, rnode in tgen.routers().iteritems():
        logger.info('Verifying BGP Convergence on router {}:'.format(router))

        for retry in range(1, 11):
            show_bgp_json = rnode.vtysh_cmd("show bgp summary json", isjson=True)
            # Verifying output dictionary show_bgp_json is empty or not
            if bool(show_bgp_json) == False:
                errormsg = "BGP is not running"
                return errormsg

            # To find neighbor ip type
            bgp_neighbors = topo['routers'][router]['bgp']["bgp_neighbors"]
            total_peer = len(bgp_neighbors)
            no_of_peer = 0
            for bgp_neighbor, data in bgp_neighbors.iteritems():
                dest_link = bgp_neighbors[bgp_neighbor]["peer"]["dest_link"]
                # Loopback interface
                if "source_link" in bgp_neighbors[bgp_neighbor]["peer"] and \
                        bgp_neighbors[bgp_neighbor]["peer"]["source_link"] == 'lo':
                    neighbor_ip = topo['routers'][bgp_neighbor]['lo'][
                        ADDR_TYPE].split("/")[0]
                    if ADDR_TYPE  == 'ipv4':
                        nh_state = show_bgp_json["ipv4Unicast"]["peers"][
                            neighbor_ip]["state"]
                    else:
                        nh_state = show_bgp_json["ipv6Unicast"]["peers"][
                            neighbor_ip]["state"]

                    if nh_state == "Established":
                        no_of_peer += 1
                else:
                    # Physical interface
                    for neighborLink in topo['routers'][bgp_neighbor]['links'].\
                            iteritems():
                        if dest_link == neighborLink[0]:
                            neighbor_ip = topo['routers'][
                                bgp_neighbor]['links'][neighborLink[0]][
                                ADDR_TYPE].split("/")[0]
                            if ADDR_TYPE  == 'ipv4':
                                nh_state = show_bgp_json["ipv4Unicast"][
                                    "peers"][neighbor_ip]["state"]
                            else:
                                nh_state = show_bgp_json["ipv6Unicast"][
                                    "peers"][neighbor_ip]["state"]

                            if nh_state == "Established":
                                no_of_peer += 1
            if no_of_peer == total_peer:
                logger.info('BGP is Converged for router {}'.format(router))
                break
            else:
                logger.warning('BGP is not yet Converged for router {}'.
                               format(router))
                sleeptime = 2 * retry
                if sleeptime <= BGP_CONVERGENCE_TIMEOUT:
                    # Waiting for BGP to converge
                    logger.info("Waiting for {} sec for BGP to converge on"
                                " router {}...".format(sleeptime, router))
                    sleep(sleeptime)
                else:
                    show_bgp_summary = rnode.vtysh_cmd("show bgp summary")
                    errormsg = "TIMEOUT!! BGP is not converged in {} seconds" \
                               " for router {} \n {}".format(
                        BGP_CONVERGENCE_TIMEOUT, router, show_bgp_summary)
                    return errormsg

    logger.info("Exiting API: verify_bgp_confergence()")
    return True

def clear_bgp(ADDR_TYPE, tgen, dut):
    """
    This API is to clear bgp neighborship.

    * `ADDR_TYPE`: ip type ipv4/ipv6
    * `tgen`: topogen object
    * `dut`: device under test
    """

    logger.info("Entering lib API: clear_bgp()")

    for router, rnode in tgen.routers().iteritems():
        if router != dut:
            continue

        # Clearing BGP
        logger.info('Clearing BGP neighborship for router {}..'.format(router))
        if ADDR_TYPE == "ipv4":
            rnode.vtysh_cmd("clear ip bgp *")
	elif ADDR_TYPE == "ipv6":
            rnode.vtysh_cmd("clear bgp ipv6 *")
	sleep(5)

    logger.info("Exiting lib API: clear_bgp()")
    return True

def clear_bgp_and_verify(ADDR_TYPE, tgen, dut, topo):
    """
    This API is to clear bgp neighborship and verify.

    * `ADDR_TYPE`: ip type ipv4/ipv6
    * `tgen`: topogen object
    * `dut`: device under test
    * `topo`: input json file data
    """

    logger.info("Entering lib API: clear_bgp_and_verify()")

    for router, rnode in tgen.routers().iteritems():
        if router != dut:
            continue

        peerUptime_before_clear_bgp = {}
        # Verifying BGP convergence before bgp clear command
        for retry in range(1, 11):
            show_bgp_json = rnode.vtysh_cmd("show bgp summary json", isjson=True)
            # Verifying output dictionary show_bgp_json is empty or not
            if bool(show_bgp_json) == False:
                errormsg = "BGP is not running"
                return errormsg

            sleeptime = 2 * retry
            if sleeptime <= BGP_CONVERGENCE_TIMEOUT:
                # Waiting for BGP to converge
                logger.info("Waiting for {} sec for BGP to converge on router"
                            " {}...".format(sleeptime, router))
                sleep(sleeptime)
            else:
                errormsg = "TIMEOUT!! BGP is not converged in {} seconds for" \
                           " router {}".format(BGP_CONVERGENCE_TIMEOUT, router)
                return errormsg

            # To find neighbor ip type
            bgp_neighbors = topo['routers'][router]['bgp']['bgp_neighbors']
            total_peer = len(bgp_neighbors)
            no_of_peer = 0
            for bgp_neighbor, data in bgp_neighbors.iteritems():
                dest_link = bgp_neighbors[bgp_neighbor]['peer']['dest_link']
                # Loopback interface
                if "source_link" in bgp_neighbors[bgp_neighbor]['peer'] and \
                        bgp_neighbors[bgp_neighbor]['peer']['source_link'] == 'lo':
                    neighbor_ip = topo['routers'][bgp_neighbor]['lo'][
                        ADDR_TYPE].split("/")[0]
                    if ADDR_TYPE == 'ipv4':
                        nh_state = show_bgp_json['ipv4Unicast']['peers'][
                            neighbor_ip]['state']

                        # Peer up time dictionary
                        peerUptime_before_clear_bgp[bgp_neighbor] = \
                            show_bgp_json['ipv4Unicast']['peers'][neighbor_ip][
                                          'peerUptime']
                    else:
                        nh_state = show_bgp_json['ipv6Unicast']['peers'][
                            neighbor_ip]['state']

                        # Peer up time dictionary
                        peerUptime_before_clear_bgp[bgp_neighbor] = \
                            show_bgp_json['ipv6Unicast']['peers'][neighbor_ip][
                                'peerUptime']

                    if nh_state == 'Established':
                        no_of_peer += 1
                else:
                    # Physical interface
                    for neighborLink in topo['routers'][bgp_neighbor]['links'].\
                            iteritems():
                        if dest_link == neighborLink[0]:
                            neighbor_ip = topo['routers'][bgp_neighbor][
                                'links'][neighborLink[0]][
                                ADDR_TYPE].split("/")[0]
                            if ADDR_TYPE == 'ipv4':
                                nh_state = show_bgp_json['ipv4Unicast'][
                                    'peers'][neighbor_ip]['state']

                                # Peer up time dictionary
                                peerUptime_before_clear_bgp[bgp_neighbor] = \
                                    show_bgp_json['ipv4Unicast']['peers'][
                                        neighbor_ip]['peerUptime']
                            else:
                                nh_state = show_bgp_json['ipv6Unicast'][
                                    'peers'][neighbor_ip]['state']

                                # Peer up time dictionary
                                peerUptime_before_clear_bgp[bgp_neighbor] = \
                                    show_bgp_json['ipv4Unicast']['peers'][
                                        neighbor_ip]['peerUptime']

                            if nh_state == 'Established':
                                no_of_peer += 1

            if no_of_peer == total_peer:
                logger.info('BGP is Converged for router {} before bgp clear'.
                            format(router))
                break
            else:
                logger.warning('BGP is not yet Converged for router {} before'
                               ' bgp clear'.format(router))

        # Clearing BGP 
        logger.info('Clearing BGP neighborship for router {}..'.format(router))
	if ADDR_TYPE == 'ipv4':
            result = rnode.vtysh_cmd("clear ip bgp *")
	elif ADDR_TYPE == 'ipv6':
            result = rnode.vtysh_cmd("clear bgp ipv6 *")

        peerUptime_after_clear_bgp = {}
        # Verifying BGP convergence after bgp clear command
        for retry in range(1, 11):
            show_bgp_json = rnode.vtysh_cmd("show bgp summary json", isjson=True)
            # Verifying output dictionary show_bgp_json is empty or not
            if bool(show_bgp_json) == False:
                errormsg = "BGP is not running"
                return errormsg

            sleeptime = 2 * retry
            if sleeptime <= BGP_CONVERGENCE_TIMEOUT:
                # Waiting for BGP to converge
                logger.info("Waiting for {} sec for BGP to converge on router"
                            " {}...".format(sleeptime, router))
                sleep(sleeptime)
            else:
                errormsg = "TIMEOUT!! BGP is not converged in {} seconds for" \
                           " router {}".format(BGP_CONVERGENCE_TIMEOUT, router)
                return errormsg

            # To find neighbor ip type
            bgp_neighbors = topo['routers'][router]['bgp']['bgp_neighbors']
            total_peer = len(bgp_neighbors)
            no_of_peer = 0
            for bgp_neighbor, data in bgp_neighbors.iteritems():
                dest_link = bgp_neighbors[bgp_neighbor]['peer']['dest_link']
                # Loopback interface
                if "source_link" in bgp_neighbors[bgp_neighbor]['peer'] and \
                        bgp_neighbors[bgp_neighbor]['peer']['source_link'] == 'lo':
                    neighbor_ip = topo['routers'][bgp_neighbor]['lo'][
                        ADDR_TYPE].split("/")[0]
                    if ADDR_TYPE == 'ipv4':
                        nh_state = show_bgp_json['ipv4Unicast']['peers'][
                            neighbor_ip]['state']
                        # Peer up time dictionary
                        peerUptime_after_clear_bgp[bgp_neighbor] = \
                                        show_bgp_json['ipv4Unicast']['peers'][
                                            neighbor_ip]['peerUptime']
                    else:
                        nh_state = show_bgp_json['ipv6Unicast']['peers'][
                            neighbor_ip]['state']
                        # Peer up time dictionary
                        peerUptime_after_clear_bgp[bgp_neighbor] = \
                                        show_bgp_json['ipv6Unicast']['peers'][
                                            neighbor_ip]['peerUptime']

                    if nh_state == 'Established':
                        no_of_peer += 1
                else:
                    # Physical interface
                    for neighborLink in topo['routers'][bgp_neighbor]['links'].\
                            iteritems():
                        if dest_link == neighborLink[0]:
                            neighbor_ip = topo['routers'][bgp_neighbor][
                                'links'][neighborLink[0]][
                                ADDR_TYPE].split("/")[0]
                            if ADDR_TYPE == 'ipv4':
                                nh_state = show_bgp_json['ipv4Unicast'][
                                    'peers'][neighbor_ip]['state']
                                # Peer up time dictionary
                                peerUptime_after_clear_bgp[bgp_neighbor] = \
                                    show_bgp_json['ipv4Unicast']['peers'][
                                        neighbor_ip]['peerUptime']
                            else:
                                nh_state = show_bgp_json['ipv6Unicast'][
                                    'peers'][neighbor_ip]['state']
                                # Peer up time dictionary
                                peerUptime_after_clear_bgp[bgp_neighbor] = \
                                    show_bgp_json['ipv4Unicast']['peers'][
                                        neighbor_ip]['peerUptime']

                            if nh_state == 'Established':
                                no_of_peer += 1

            if no_of_peer == total_peer:
                logger.info('BGP is Converged for router {} after bgp clear'.
                            format(router))
                break
            else:
                logger.warning('BGP is not yet Converged for router {} after'
                               ' bgp clear'.format(router))

    # Compariung peerUptime dictionaries
    if peerUptime_before_clear_bgp != peerUptime_after_clear_bgp:
        logger.info('BGP neighborship is reset after clear BGP on router {}'.
                    format(dut))
    else:
        errormsg = 'BGP neighborship is not reset after clear bgp on router' \
                   ' {}'.format(dut)
        return erromsg

    logger.info("Exiting lib API: clear_bgp_and_verify()")
    return True

def verify_bgp_timers_and_functionality(ADDR_TYPE, tgen, input_dict, topo):
    """
    This API is to verify bgp timers and functionality.

    * `ADDR_TYPE`: ip type, ipv4/ipv6
    * `tgen`: topogen object
    * `input_dict`: having details like - for which router, bgp timers needs
                    to be verified
    * `topo`: input json file data
    """

    logger.info("Entering lib API: verify_bgp_timers_and_functionality()")

    sleep(5)
    for dut in input_dict.keys():
        router_list = tgen.routers()
        for router, rnode in router_list.iteritems():
            if router != dut:
                continue

            logger.info('Verifying bgp timers functionality, DUT is {}:'.
                        format(router))

            show_ip_bgp_neighbor_json = \
                rnode.vtysh_cmd("show ip bgp neighbor json", isjson=True)
            for bgp_neighbor in input_dict[router]["bgp"]["bgp_neighbors"].keys():
                keepalivetimer = input_dict[router]["bgp"]["bgp_neighbors"]\
                    [bgp_neighbor]["keepalivetimer"]
                holddowntimer = input_dict[router]["bgp"]["bgp_neighbors"]\
                    [bgp_neighbor]["holddowntimer"]

                # Peer details
                peer = topo['routers'][router]["bgp"]["bgp_neighbors"][bgp_neighbor]\
                    ['peer']
                dest_link = peer['dest_link']

                # Loopback interface
                if "source_link" in peer and peer['source_link'] == 'lo':
                    neighbor_ip = topo['routers'][bgp_neighbor]['lo'][ADDR_TYPE].\
                        split('/')[0]
                else:
                    # Physical Interface
                    for destRouterLink in topo['routers'][bgp_neighbor]['links'].\
                            iteritems():
                        if dest_link == destRouterLink[0]:
                            neighbor_ip = \
                            topo['routers'][bgp_neighbor]['links'][destRouterLink[0]]\
                                [ADDR_TYPE].split("/")[0]

                # Verify HoldDownTimer for neighbor
                bgpHoldTimeMsecs = show_ip_bgp_neighbor_json[neighbor_ip]\
                    ["bgpTimerHoldTimeMsecs"]
                if bgpHoldTimeMsecs != holddowntimer * 1000:
                    errormsg = "Verifying holddowntimer for bgp neighbor {} under dut {},\
                    found: {} but expected: {}".format(neighbor_ip, router,
                                                       bgpHoldTimeMsecs,
                                                       holddowntimer * 1000)
                    return errormsg

                # Verify KeepAliveTimer for neighbor
                bgpKeepAliveTimeMsecs = show_ip_bgp_neighbor_json[neighbor_ip]\
                    ["bgpTimerKeepAliveIntervalMsecs"]
                if bgpKeepAliveTimeMsecs != keepalivetimer * 1000:
                    errormsg = "Verifying keepalivetimer for bgp neighbor {} under dut {},\
                    found: {} but expected: {}".format(neighbor_ip, router,
                                                       bgpKeepAliveTimeMsecs,
                                                       keepalivetimer * 1000)
                    return errormsg

                # Keep alive message count before shutting down neighbor interface
                show_ip_bgp_neighbor_json = rnode.vtysh_cmd("show ip bgp neighbor json",
                                                            isjson=True)
                keepalive_msg_count_before = show_ip_bgp_neighbor_json[neighbor_ip]\
                    ["messageStats"]["keepalivesSent"]
		
                # Shutdown interface
		logger.info("Shutting down interface r2-r1-eth0 on router: {}..".format(bgp_neighbor))
                topotest.interface_set_status(router_list[bgp_neighbor], "r2-r1-eth0",
                                              ifaceaction=False)

                # Verifying functionality
                for timer in range(keepalivetimer, holddowntimer + keepalivetimer,
                                   int(holddowntimer/3)):
                    logger.info("Waiting for {} sec..".format(keepalivetimer))
                    sleep (keepalivetimer)
                    show_bgp_json = rnode.vtysh_cmd("show bgp summary json", isjson=True)
                    dest_link = topo['routers'][router]['bgp']["bgp_neighbors"][bgp_neighbor]\
                        ["peer"]["dest_link"]
                    # Loopback interface
                    if "source_link" in topo['routers'][router]['bgp']["bgp_neighbors"]\
                            [bgp_neighbor]["peer"] and \
                        topo['routers'][router]['bgp']["bgp_neighbors"][bgp_neighbor]\
                                ["peer"]["source_link"] == 'lo':
                        neighbor_ip = topo['routers'][bgp_neighbor]['lo'][ADDR_TYPE].\
                            split("/")[0]
                        if ADDR_TYPE  == 'ipv4':
                            nh_state = show_bgp_json["ipv4Unicast"]["peers"][neighbor_ip]\
                                ["state"]
                        else:
                            nh_state = show_bgp_json["ipv6Unicast"]["peers"][neighbor_ip]\
                                ["state"]

                        if timer == holddowntimer:
                            if nh_state == "Established":
                                errormsg = ("BGP neighborship has not gone down in {} sec for"
                                            " neighbor {}".format(timer, bgp_neighbor))
                                return errormsg
                            else:
                                logger.info("BGP neighborship has gone down in {} sec for "
                                            "neighbor {}".format(timer, bgp_neighbor))
                    else:
                        # Physical interface
                        for neighborLink in topo['routers'][bgp_neighbor]['links'].iteritems():
                            if dest_link == neighborLink[0]:
                                neighbor_ip = topo['routers'][bgp_neighbor]['links'][neighborLink[0]]\
                                    [ADDR_TYPE].split("/")[0]
                                if ADDR_TYPE  == 'ipv4':
                                    nh_state = show_bgp_json["ipv4Unicast"]["peers"][neighbor_ip]\
                                        ["state"]
                                else:
                                    nh_state = show_bgp_json["ipv6Unicast"]["peers"][neighbor_ip]\
                                        ["state"]

                                if timer == holddowntimer:
                                    if nh_state == "Established":
                                        errormsg = ("BGP neighborship has not gone down in {} sec for "
                                                    "neighbor {}".format(timer, bgp_neighbor))
                                        return errormsg
                                    else:
                                        logger.info("BGP neighborship has gone down in {} sec for "
                                                    "neighbor {}".format(timer, bgp_neighbor))

                # Keep alive message count before shutting down neighbor interface
                show_ip_bgp_neighbor_json = rnode.vtysh_cmd("show ip bgp neighbor json", isjson=True)
                keepalive_msg_count_after = show_ip_bgp_neighbor_json[neighbor_ip]["messageStats"]\
                    ["keepalivesSent"]

                # Verifying  keepalive msg count
                if keepalive_msg_count_after - keepalive_msg_count_before == 3:
                    logger.info("Total 3 keepAlive messages are sent to neighbor, untill bgp "
                                "neighborship is down")
                else:
                    errormsg = ("Inconsistancy in keepAlive messages, which  are sent to "
                                "neighbor, untill bgp neighborship is down, \n"
				"keep_alive_msg_count_after: {} \n"
				"keep_alive_msg_count_before: {}".
				format(keepalive_msg_count_after, keepalive_msg_count_before))
                    return errormsg

    logger.info("Exiting lib API: verify_bgp_timers_and_functionality()")
    return True

def verify_AS_numbers(ADDR_TYPE, tgen, input_dict, topo):
    """
    This API is to verify AS numbers

    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `tgen`: topogen object
    * `input_dict`: having details like - for which router, AS numbers needs to
                    be verified
    * `topo`: input json file data
    """

    logger.info("Entering lib API: verify_AS_numbers()")

    for dut in input_dict.keys():
        for router, rnode in tgen.routers().iteritems():
            if router != dut:
                continue

            logger.info('Verifying AS numbers for  dut {}:'.format(router))

            show_ip_bgp_neighbor_json = rnode.vtysh_cmd(
                "show ip bgp neighbor json", isjson=True)
            local_as = input_dict[router]["local_as"]
            bgp_neighbors = topo['routers'][router]['bgp']["bgp_neighbors"]

            for bgp_neighbor, data in bgp_neighbors.iteritems():
                dest_link = bgp_neighbors[bgp_neighbor]["peer"]["dest_link"]
                router_data = topo['routers'][bgp_neighbor]
                remote_as = input_dict[router]["bgp_neighbors"][bgp_neighbor]["remote_as"]

                # Loopback interface
                if "source_link" in bgp_neighbors[bgp_neighbor]["peer"] \
                    and bgp_neighbors[bgp_neighbor]["peer"]["source_link"] == 'lo':
                    if ADDR_TYPE == "ipv4":
                        neighbor_ip = router_data['lo'][ADDR_TYPE].split("/")[0]
                    else:
                        ADDR_TYPE = 'ipv6'
                        neighbor_ip = router_data['lo'][ADDR_TYPE].split("/")[0]
                # Physical interface
                else:
                    for neighborLink in router_data['links'].iteritems():
                        if dest_link == neighborLink[0]:
                            if ADDR_TYPE == 'ipv4':
                                neighbor_ip = router_data['links'][
                                    neighborLink[0]][ADDR_TYPE].split("/")[0]
                            else:
                                ADDR_TYPE = 'ipv6'
                                neighbor_ip = router_data['links'][
                                    neighborLink[0]][ADDR_TYPE].split("/")[0]

                # Verify Local AS for router
                if show_ip_bgp_neighbor_json[neighbor_ip]["localAs"] != local_as:
                    errormsg = "Failed: Verify local_as for dut {}, found: {}" \
                               " but expected: {}".format(router,
                                show_ip_bgp_neighbor_json[neighbor_ip]["localAs"],
                                local_as)
                    return errormsg
                else:
                    logger.info("Verified local_as for dut {}, found expected:"
                                " {}".format(router, local_as))

                # Verify Remote AS for neighbor
                if show_ip_bgp_neighbor_json[neighbor_ip]["remoteAs"] != remote_as:
                    errormsg = "Failed: Verify remote_as for dut {}'s" \
                               " neighbor {}, found: {} but expected: {}".\
                        format(router, bgp_neighbor,
                               show_ip_bgp_neighbor_json[neighbor_ip]["remoteAs"],
                               remote_as)
                    return errormsg
                else:
                    logger.info("Verified remote_as for dut {}'s neighbor {},"
                                " found expected: {}".format(router,
                                                             bgp_neighbor,
                                                             remote_as))

    logger.info("Exiting lib API: verify_AS_numbers()")
    return True


def verify_bgp_attributes(ADDR_TYPE, dut, tgen, static_routes, rmap_name,
                          input_dict):
    """
    This API is to verify AS numbers

    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `tgen`: topogen object
    * `static_routes`: Static Routes for which BGP set attributes needs to be
                       verified
    * `rmap_name`: route map name for which set criteria needs to be verified
    * `input_dict`: having details like - for which router, AS numbers needs
                    to be verified
    """

    logger.info("Entering lib API: verify_bgp_attributes()")

    for router, rnode in tgen.routers().iteritems():
        if router != dut:
            continue

        logger.info('Verifying BGP set attributes for dut {}:'.format(router))

        for static_route in static_routes:
	    cmd = "show bgp {} {} json".format(ADDR_TYPE, static_route)
            show_bgp_json = rnode.vtysh_cmd(cmd, isjson=True)
            logger.info(show_bgp_json)

            for rmap_router in input_dict.keys():
                for rmap in input_dict[rmap_router]["route_maps"].keys():
                    if rmap == rmap_name:
                        for rmap_dict in input_dict[rmap_router]["route_maps"][
                                rmap_name]:
                            if "set" in rmap_dict:
                                for criteria in rmap_dict["set"].keys():
                                    if rmap_dict["set"][criteria] == \
                                            show_bgp_json["paths"][0][criteria]:
                                        logger.info("Verifying BGP attribute"
                                                    " {} for route: {} in"
                                                    " router: {}, found"
                                                    " expected value: {}".
                                                    format(criteria,
                                                           static_route,
                                                           dut,
                                                           rmap_dict["set"][
                                                           criteria]))
                                    else:
                                        errormsg=("Failed: Verifying BGP"
                                                  " attribute {} for route:{}"
                                                  " in router: {}, expected"
                                                  " value: {} but found: {}".
                                                  format(criteria, static_route,
                                                         dut,
                                                         rmap_dict["set"][criteria],
                                                         show_bgp_json['paths'][0][criteria]))
                                        return errormsg

    logger.info("Exiting lib API: verify_bgp_attributes()")
    return True

def verify_best_path_as_per_bgp_attribute(ADDR_TYPE, dut, input_dict, tgen, attribute):
    """ 
    This API is to find and verify best path according to BGP attributes.

    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `dut`: Device Under Test, for which user wants to test the data
    * `input_dict`: having route details, which will help to calculate best path
    * `tgen` : topogen object
    * `attribute` : calculate best path using this attribute
    """

    logger.info("Entering lib API: verify_best_path_as_per_bgp_attribute()")

    router_list = tgen.routers()
    for router, rnode in router_list.iteritems():
        if router != dut:
            continue

        # Verifying show bgp json
	command = "show bgp {} json".format(ADDR_TYPE)

        sleep(2)
        logger.info('Verifying router {} RIB for best path:'.format(router))
        sh_ip_bgp_json = rnode.vtysh_cmd(command, isjson=True)

        for routes_from_router in input_dict.keys():
            networks = input_dict[routes_from_router]["advertise_networks"]
            for network in networks:
                route = network["start_ip"]

                route_attributes = sh_ip_bgp_json["routes"][route]
                _next_hop = None
                compare = None
                attribute_dict = {}
                for route_attribute in route_attributes:
                    next_hops = route_attribute["nexthops"]
                    for next_hop in next_hops:
                        next_hop_ip = next_hop["ip"]
                    attribute_dict[next_hop_ip] = route_attribute[attribute]

                # AS_PATH attribute
                if attribute == "aspath":
                    # Find next_hop for the route have minimum as_path 
                    _next_hop = min(attribute_dict, key= lambda x: len(set(
                        attribute_dict[x])))
                    compare = "SHORTEST"

                # LOCAL_PREF attribute 
                elif attribute == "localpref":
                    # Find next_hop for the route have highest local preference
                    _next_hop = max(attribute_dict, key=(lambda k:
                                                         attribute_dict[k]))
                    compare = "HIGHEST"

                # WEIGHT attribute 
                elif attribute == "weight":
                    # Find next_hop for the route have highest weight
                    _next_hop = max(attribute_dict, key=(lambda k:
                                                         attribute_dict[k]))
                    compare = "HIGHEST"

                # ORIGIN attribute 
                elif attribute == "origin":
                    # Find next_hop for the route have IGP as origin, -
                    # - rule is IGP>EGP>INCOMPLETE
                    _next_hop = [key  for (key, value) in attribute_dict.\
                        iteritems() if value == "IGP"][0]
                    compare = ""

                # MED  attribute 
                elif attribute == "med":
                    # Find next_hop for the route have LOWEST MED
                    _next_hop = min(attribute_dict, key=(lambda k:
                                                         attribute_dict[k]))
                    compare = "LOWEST"

                # Show ip route
		if ADDR_TYPE == "ipv4":
                    command = "show ip route json"
		else:
                    command = "show ipv6 route json"
	
                rib_routes_json = rnode.vtysh_cmd(command, isjson=True)

                # Verifying output dictionary rib_routes_json is not empty
                if bool(rib_routes_json) == False:
                    errormsg = "No {} route found in RIB of router {}..".\
                        format(protocol, router)
                    return errormsg

                st_found = False
                nh_found = False
                # Find best is installed in RIB
                if route in rib_routes_json:
                    st_found = True
                    # Verify next_hop in rib_routes_json
                    if rib_routes_json[route][0]['nexthops'][0]['ip'] == \
                            _next_hop:
                        nh_found = True
                    else:
                        errormsg = ("Incorrect Nexthop for BGP route {}"
                                    " in RIB of router {}, Expected: {}, Found: {}\n".\
			format(route, dut, rib_routes_json[route][0]['nexthops'][0]['ip'], _next_hop))
                        return errormsg

                if st_found and nh_found:
                    logger.info("Best path for prefix: {} is installed according"
                                " to {} {}: ({}) in RIB of router {} \n".
                                format(route, compare, attribute,
                                       attribute_dict[_next_hop], dut))

        logger.info("Exiting lib API: verify_best_path_as_per_bgp_attribute()")
    return True

def verify_best_path_as_per_admin_distance(ADDR_TYPE, dut, input_dict, tgen, attribute):
    """ 
    This API is to find and verify best path as per admin distance

    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `dut`: Device Under Test, for which user wants to test the data
    * `input_dict`: having route details, which will help to calculate best path
    * `tgen` : topogen object
    * `attribute` : calculate best path using this attribute
    """

    logger.info("Entering lib API: verify_best_path_as_per_admin_distance()")

    router_list = tgen.routers()
    for router, rnode in router_list.iteritems():
        if router != dut:
            continue

        sleep(2)
        logger.info('Verifying router {} RIB for best path:'.
                   format(router))

        # Show ip route cmd
        if ADDR_TYPE == "ipv4":
            command = "show ip route json"
        else:
            command = "show ipv6 route json"

        for routes_from_router in input_dict.keys():
            sh_ip_route_json = router_list[routes_from_router].vtysh_cmd(\
                               command, isjson=True)
            networks = input_dict[routes_from_router]["static_routes"]
            for network in networks:
                route = network["network"]

                route_attributes = sh_ip_route_json[route]
                _next_hop = None
                compare = None
                attribute_dict = {}
                for route_attribute in route_attributes:
                    next_hops = route_attribute["nexthops"]
                    for next_hop in next_hops:
                        next_hop_ip = next_hop["ip"]
                    attribute_dict[next_hop_ip] = route_attribute["distance"]

                # Find next_hop for the route have LOWEST Admin Distance 
                _next_hop = min(attribute_dict, key=(lambda k: \
                                attribute_dict[k]))
                compare = "LOWEST"

            # Show ip route
            rib_routes_json = rnode.vtysh_cmd(command, isjson=True)

            # Verifying output dictionary rib_routes_json is not empty
            if bool(rib_routes_json) == False:
                errormsg = "No {} route found in RIB of router {}..".\
                               format(protocol, router)
                return errormsg

            st_found = False
            nh_found = False
            # Find best is installed in RIB
            if route in rib_routes_json:
                st_found = True
                # Verify next_hop in rib_routes_json
                if rib_routes_json[route][0]['nexthops'][0]['ip'] == \
                    _next_hop:
                    nh_found = True
                else:
                    errormsg = ("Nexthop {} is Missing for BGP route {}"
                    " in RIB of router {}\n".format(_next_hop, route, dut))
                    return errormsg

            if st_found and nh_found:
                logger.info("Best path for prefix: {} is installed according"
                            " to {} {}: ({}) in RIB of router {} \n".\
                            format(route, compare, attribute, \
                            attribute_dict[_next_hop], dut))

        logger.info("Exiting lib API: verify_best_path_as_per_admin_distance()")
        return True


def verify_bgp_community(addr_type, dut, tgen, network, input_dict = None):
    """
    This API is to BGP communitiess

    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `tgen`: topogen object
    * `network`: network for which set criteria needs to be verified
    * `input_dict`: having details like - for which router, AS numbers needs
                    to be verified
    """

    logger.info("Entering lib API: verify_bgp_community()")

    for router, rnode in tgen.routers().iteritems():
        if router != dut:
            continue

        logger.info('Verifying BGP set attributes for dut {}:'.format(router))

	sleep(5)
        for net in network:
            cmd = "show bgp {} {} json".format(addr_type, net)
            show_bgp_json = rnode.vtysh_cmd(cmd, isjson=True)
            logger.info(show_bgp_json)
            if "paths" not in show_bgp_json:
                return "No prefix path found on router: {}".format(dut)

	    as_paths = show_bgp_json["paths"]
	    found = False
	    for i in range(len(as_paths)):  
	        if "largeCommunity" in show_bgp_json["paths"][i]:
		    found = True
        	    logger.info("Large Community attribute is found for route: "
				   "{} in router: {} ".format(net, dut))
		    if input_dict != None:
                        for criteria, comm_val in input_dict.items():
		            show_val = show_bgp_json["paths"][i][criteria]['string']
                            if comm_val == show_val:
                                logger.info("Verifying BGP {} for prefix: {} in"
                                        " router: {}, found expected value: {}" .
                                        format(criteria, net, dut, comm_val))
                    	    else:
			        errormsg = \
				("Failed: Verifying BGP attribute {} for route:"
                                 "{} in router: {}, expected  value: {} but "
                                 "found: {}".format(criteria, net, dut, comm_val,
                                  show_val))
                    	        return errormsg

            if not found: 
                errormsg = ("Large Community attribute is not found for route: "
                                           "{} in router: {} ".format(net, dut))
                return errormsg

        logger.info("Exiting lib API: verify_bgp_community()")
        return True
