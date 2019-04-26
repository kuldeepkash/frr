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
    """BGP configuration backup builder"""

    def __init__(self, router_id):
	"""
        BGP configuration backup initialization function.
     
        Parameters
        ----------
        * `router_id` : Router-id for DUT
        """

        self.bgp_config = None
        self.community_lists = []
        self.redistribute_static = None
	self.redistribute_static_route_map = None
        self.redistribute_connected = None
	self.redistribute_connected_route_map = None
        self.routing_global = {'router_id': router_id}


class BGPConfig:
    """ BGP configuration builder class """

    def __init__(self, router, routing_cfg_msg, bgpcfg_file):
	"""
        BGP configuration initialization function. Configuration
        will be saved in defined class variables.

	Parameters
        ----------
        * `router` : Device Under Test

        """
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
        """ BGP configurations reset to None/Null """

        self.bgp_global = get_StringIO()
        self.bgp_neighbors = get_StringIO()
        self.bgp_address_family = {}
        self.as_path_prepend = False
        self.bgp_address_family[IPv4_UNICAST] = get_StringIO()
        self.bgp_address_family[IPv6_UNICAST] = get_StringIO()
        self.bgp_address_family[VPNv4_UNICAST] = get_StringIO()
        self.community_list = get_StringIO()

    def print_bgp_config_to_file(self, topo):
        """
        API will read values from BGPConfig class variables and print
	to bgp_json.conf file.

        Parameters
        ----------
	* `topo` : Input json data
        """
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

def create_bgp_cfg(router, topo):
    """
    Create BGP configuration for the topology defined in input
    JSON file and save config to variables of class BGPConfig.

    Parameters
    ----------
    * `router` : router for which bgp config should be created
    * `topo` : json file data
    
    Returns
    -------
    errormsg(str) or object of BGPConfig class which has BGP
    configuration
    """

    logger.info("Entering lib API: create_bgp_cfg()")
    try:
        # Setting key to bgp to read data from json file for bgp
	# configuration
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
            nh_details = topo['routers'][neighbor_name]
            # Loopback interface
            if "source_link" in peer and peer['source_link'] == 'lo':
	        for destRouterLink, data in sorted(nh_details['links'].\
                    iteritems()):
	            if 'type' in data and data['type'] == 'loopback':
                        if dest_link == destRouterLink:
                            ip_addr = nh_details['links'][destRouterLink][ADDR_TYPE].\
				      split('/')[0]
                            update_source = topo['routers']['{}'.format(router)][
			    'links'][destRouterLink][ADDR_TYPE].split('/')[0]
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
	        for destRouterLink in sorted(nh_details['links'].\
                                                   iteritems()):
                    if dest_link == destRouterLink[0]:
                        ip_addr = nh_details['links'][destRouterLink[0]][ADDR_TYPE].\
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

    logger.info("Exiting lib API: create_bgp_cfg()")
    return bgp

def create_bgp_configuration(ADDR_TYPE, tgen, topo, router):
    """
    API to create object of class BGPConfig and also create bgp_json.conf
    file. It will create BGP and related configurations and save it to
    bgp_json.conf and load to router

    Parameters
    ----------
    * `ADDR_TYPE` : ip type ipv4/ipv6
    * `tgen` : Topogen object
    * `topo` : json file data
    * `router` : current router
    
    Returns
    -------
    errormsg(str) or True
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

                fname = '{}/{}/{}'.format(tmpdir, router, BGPCFG_FILE)
                bgp_cfg[router] = BGPConfig(router, rt_cfg, fname)
                bgp_cfg[router].is_standby = False

                input_dict = topo['routers']
                bgp_cfg[router].routing_pb.bgp_config = create_bgp_cfg(router, topo)
                Bgp_cfg(bgp_cfg[router])
                bgp_cfg[router].print_bgp_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, router)

                if 'redistribute' in topo['routers'][router]:
                    result = redistribute_static_routes(ADDR_TYPE, input_dict,
                                                    tgen, topo)
                    assert result is True, ("API: redistribute_static_routes() "
                                        ":Failed \n Error: {}".format(result))

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return True

# Helper class for Address type  configuration
class Address:
    """ Address family type """

    def __init__(self, afi, ipv4 = None, ipv6 = None):
	""" Initializaton function for Address family
	
	Parameters
	----------
	* `afi` : Address familty identifier
	* `ipv4` : address type, ipv4, default None
	* `ipv6` : address type, ipv6, default is None
        """
        self.afi = afi
        self.ipv4 = ipv4
        self.ipv6 = ipv6

# Helper class for Address family configuration
class AddressFamily:
    """ BGP address-family configuration builder """

    def __init__(self, ad_family, enabled=None, filter_in_prefix_list=None,
                 filter_out_prefix_list=None, filter_in_rmap=None,
                 filter_out_rmap=None, next_hop_self = None, 
		 no_send_community = None):
	"""
	Initialization function for BGP address-family configuration

	Parameters
	----------
        * `ad_family`:  Address family, IPv4_UNICAST/IPv6_UNICAST
        * `enabled`: If true then BGP will be configured, true/false,
		     default is None  
        * `filter_in_prefix_list`: Prefix list name, which will applied to 
			           BGP neighbor IN direction, default is None
        * `filter_out_prefix_list`: Prefix list name, which will applied to 
                                    BGP neighbor OUT direction, default is None
        * `filter_in_rmap`: Route-map name, which will applied to BGP
                            neighbor IN direction, default is None
        * `filter_out_rmap`: Route-map name, which will applied to BGP
                             neighbor OUT direction, default is None
        * `next_hop_self`: Apply next_hop_self for BGP neighbor, default None
        * `no_send_community` : Set no send_community config for neighbor
        """

        self.type = ad_family
        self.enabled = enabled
        self.filter_in_prefix_list = filter_in_prefix_list
        self.filter_out_prefix_list = filter_out_prefix_list
        self.filter_in_rmap = filter_in_rmap
        self.filter_out_rmap = filter_out_rmap
	self.next_hop_self = next_hop_self
	self.no_send_community = no_send_community

# Helper class for BGP Neighbor configuration
class Neighbor:
    """ BGP neighbor configuration builder """

    def __init__(self, afi, ip_address, remote_as, keep_alive_time=None,
                 hold_down_time=None, password=None, update_source=None,
                 max_hop_limit = 0):
	"""
	Initialization function for BGP neighbor configuration

	Parameters
	----------
        * `afi`:  Address family, IPv4_UNICAST/IPv6_UNICAST
        * `ip_address`: Neighbor address
        * `remote_as`: Remote_as for neighbor
        * `keep_alive_time`: Keep Alive Time for neighbor, default None
        * `hold_down_time`: Hold Down Time for neighbor, default None
        * `password`: Password for neighbor, default None
        * `update_source`: enable update source for loopback neighborship,
			   default None
        * `max_hop_limit`: ebgp multihop limit, default None
        """

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
			   next_hop_self = None,
			   no_send_community = None, 
                           max_hop_limit = 0):
	""" 
        Add address-family configuration for BGP 
	
	Parameters
	----------
        * `afi`:  Address family, IPv4_UNICAST/IPv6_UNICAST
        * `ip_address`: Neighbor address
        * `remote_as`: Remote_as for neighbor
        * `keep_alive_time`: Keep Alive Time for neighbor, default None
        * `hold_down_time`: Hold Down Time for neighbor, default None
        * `password`: Password for neighbor, default None
        * `update_source`: enable update source for loopback neighborship,
                           default None
        * `max_hop_limit`: ebgp multihop limit, default None
        """

        for f in self.address_families:
            if f.type == ad_family:
                f.enabled = enabled
                f.filter_in_prefix_list = filter_in_prefix_list
                f.filter_out_prefix_list = filter_out_prefix_list
                f.filter_in_rmap = filter_in_rmap
                f.filter_out_rmap = filter_out_rmap
		f.next_hop_self = next_hop_self
		f.no_send_community = no_send_community
                return

        family = AddressFamily(ad_family, enabled, filter_in_prefix_list,
                               filter_out_prefix_list, filter_in_rmap,
                               filter_out_rmap, next_hop_self, 
			       no_send_community)
        self.address_families.append(family)

    def del_address_family(self, ad_family):
	""" Delete address family confiuration for given address-family

	Parameters
	----------
        * `ad_family`:  Address family, IPv4_UNICAST/IPv6_UNICAST
	"""

        for f in self.address_families:
            if f.type == ad_family:
                self.address_families.remove(f)

# Helper class for BGP configuration
class Bgp:
    """ BGP configuration helper class """

    def __init__(self, local_as, graceful_restart, ecmp):
	"""
	Initialization function for BGP global and address
	family configurations
	
	Parameters
	* `local_as` : Local AS number
	* `graceful_restart` : BGP global graceful-restart config
	* `ecmp` : ECMP, max path config
	"""
        
	self.local_as = local_as
        self.graceful_restart = graceful_restart
        self.ecmp = ecmp
        self.neighbors = []

    def add_neighbor(self, afi, ip_address, remote_as, keep_alive_time=None,
                     hold_down_time=None, password=None, update_source=None,
                     max_hop_limit=None):
	"""
	Add neighbor for given router with the given configuration

	Parameters
	----------
        * `afi`:  Address family, IPv4_UNICAST/IPv6_UNICAST
        * `ip_address`: Neighbor address
        * `remote_as`: Remote_as for neighbor
        * `keep_alive_time`: Keep Alive Time for neighbor, default None
        * `hold_down_time`: Hold Down Time for neighbor, default None
        * `password`: Password for neighbor, default None
        * `update_source`: enable update source for loopback neighborship,
                           default None
        * `max_hop_limit`: ebgp multihop limit, default None
        """

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
	""" 
	Fetch and returns neighbor and its details from BGP configuration

	Parameters
        * `afi`:  Address family, IPv4_UNICAST/IPv6_UNICAST
        * `ip_address`: Neighbor address
	"""
        for n in self.neighbors:
            if n.afi == afi and n.ip_address.ipv4 == ip_address.ipv4:
                return n

    def del_neighbor(self, afi, ip_address):
	"""
	Delete neighbor from BGP configuration
	
        Parameters
        * `afi`:  Address family, IPv4_UNICAST/IPv6_UNICAST
        * `ip_address`: Neighbor address
	"""

        for n in self.neighbors:
            if n.afi == afi and n.ip_address == ip_address:
                self.neighbors.remove(n)


def _print_bgp_global_cfg(bgp_cfg, local_as_no, router_id, ecmp_path,
                          gr_enable):
    """
    API prints bgp global config to bgp_json file.

    Parameters
    ----------
    * `bgp_cfg` : BGP class variables have BGP config saved in it for 
                  particular router,
    * `local_as_no` : Local as number
    * `router_id` : Router-id
    * `ecmp_path` : ECMP max path
    * `gr_enable` : BGP global gracefull restart config
    """
    
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
    """
    API prints bgp address-family config to bgp_json file.

    Parameters
    ----------
    * `bgp_cfg` : BGP class variables have BGP config saved in it for 
                  particular router,
    * `neigh_ip` : Neighbor ip for which config needs to be written
    * `addr_family` : Address family, ipv4/6 unicast
    """

    out_filter_or_rmap = False
    neigh_cxt = 'neighbor ' + neigh_ip + ' '

    # next-hop-self
    if addr_family.next_hop_self != None:
       bgp_cfg.bgp_address_family[addr_family.type].write(
            neigh_cxt + 'next-hop-self' '\n')

    # no_send_community
    if addr_family.no_send_community != None:
       bgp_cfg.bgp_address_family[addr_family.type].write(
            'no ' + neigh_cxt + 'send-community ' + addr_family.no_send_community + '\n')

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
    """
    API prints bgp neighbor config to bgp_json file.

    Parameters
    ----------
    * `bgp_cfg` : BGP class variables have BGP config saved in it for 
                  particular router,
    * `neighbor` : Neighbor for which config needs to be written
    """

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

def Bgp_cfg(bgp_cfg):
    """
    API calls internal APIs to print bgp config to bgp_json file.

    Parameters
    ----------
    * `bgp_cfg` : BGP class variables have BGP config saved in it for 
                  particular router,
    """

    if not bgp_cfg.is_bgp_configured:
        logger.debug('BGP is disabled')
        return
    bgp = bgp_cfg.routing_pb.bgp_config
    _print_bgp_global_cfg(bgp_cfg, bgp.local_as,
                          bgp_cfg.routing_pb.routing_global['router_id'],
                          bgp.ecmp, bgp.graceful_restart)
    for neighbor in bgp.neighbors:
        _print_bgp_neighbors_cfg(bgp_cfg, neighbor)

def redist_cfg(bgp_cfg, ADDR_TYPE):
    """
    API to redistribute static and/or connected routes to BGP 
    for any router.

    Parameters
    ----------
    * `bgp_cfg` : bgp config file to save router's bgp config
    * `ADDR_TYPE` : ip type, ipv4/6
    
    Returns
    -------
    errormsg(str) or True
    """

    try:
        if bgp_cfg.is_bgp_configured:
            if ADDR_TYPE == "ipv4":
                af_modifier = IPv4_UNICAST
            else:
                af_modifier = IPv6_UNICAST
	    if bgp_cfg.routing_pb.redistribute_static == True:
		bgp_cfg.bgp_address_family[af_modifier].write(
                              'redistribute static \n')
	    elif bgp_cfg.routing_pb.redistribute_static_route_map != None:
                bgp_cfg.bgp_address_family[af_modifier].write(
                   'redistribute static route-map {} \n'.\
	 	   format(bgp_cfg.routing_pb.redistribute_static_route_map))

            if bgp_cfg.routing_pb.redistribute_connected == True:
                bgp_cfg.bgp_address_family[af_modifier].write(
                          'redistribute connected\n')	
	    elif bgp_cfg.routing_pb.redistribute_connected_route_map != None:
                bgp_cfg.bgp_address_family[af_modifier].write(
                    'redistribute connected route-map {} \n'.\
	 	    format(bgp_cfg.routing_pb.redistribute_connected_route_map))

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
	return errormsg

    return True

# Helper class for Community list configuration
class Community:
    """ BGP community list configuration builder helper class """

    def __init__(self, community, community_type, community_action, \
	community_number):
	""" Initialization function for community list config creation
	
	Parameters
	----------
	* `community` :  Community-list dentifier, large-community-list 
	* `community_type` :  Standard or Expanded
	* `community_action` : Permit or Deny
	* `community_number` :  Community number/attribute
	"""

        self.community = community
        self.community_type = community_type
        self.community_action = community_action
        self.community_number = community_number

class CommunityList:
    """ BGP Community-list name configuration """

    def __init__(self, name):
	"""
	Initialization function 

	Parameters
	----------
	* `name` : Community-list name
	"""

        self.comm_list_uuid_name = name
        self.community = []

    def add_community(self, community):
	""" 
	Add new community-list to BGP configuration 
       
	Parameters
	----------
	* `community` : Object of Community class
	"""

	self.community.append(community)

def community_list_cfg(bgp_cfg):
    """
    API prints community list config to bgp_json file.

    Parameters
    ----------
    * `bgp_cfg` : BGP class variables have BGP config saved in it for 
                  particular router,
    """

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
                'bgp', str(community.community) , str(community.community_type),\
			 name, action, str(community.community_number), '\n']))

# These APIs will be used by testcases
def find_ibgp_and_ebgp_peers_in_topology(peer_type, topo):
    """
    API to find ebgp/ibgp peers.

    Parameters
    ----------
    * `peer_type` : type of bgp neighborship, ebgp/ibgp
    * `topo`  : json file data

    Returns
    -------
    peer dict, having ebgp/ibgp peers name.
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

def modify_delete_router_id(action, input_dict, tgen, topo):
    """
    Modify: existing router-id would be modified to user defined
    router-id
    Delete: statically assigned router-id would be deleted
    Once config is modified it will be loaded to router.

    Parameters
    ----------
    * `action :  action to be performed, modify/delete
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` : defines for which router/s router-id should
		      modified or deleted
    Usage
    -----
    # Modify router-id to 1.1.1.1 for router r1 and 2,2,2,2 for router r2
    input_dict = {
        'r1': { 'router_id': '1.1.1.1' }},
        'r2': { 'router_id': '2.2.2.2' }}
    result = modify_delete_router_id('modify', input_dict, tgen, topo)

    # Delete router-id for router r1 and r2
    input_dict = {
 	"router_ids": ["r1", "r2"] }
    result = modify_delete_router_id('delete', input_dict, tgen, topo)    

    Returns
    -------
    errormsg(str) or True
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
                load_config_to_router(tgen, router)
        elif action == 'delete':
            for router in input_dict["router_ids"]:
                # Reset FRR config
                bgp_cfg[router].reset_it()

                router_id = None
                bgp_cfg[router].routing_pb.routing_global['router_id'] = router_id

                Bgp_cfg(bgp_cfg[router])
                bgp_cfg[router].print_bgp_config_to_file(topo)
                # Load config to router
                load_config_to_router(tgen, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_delete_router_id()")
    return True

def modify_bgp_timers(ADDR_TYPE, input_dict, tgen, topo):
    """
    User will pass input_dict, to define for which router and neighbor
    keepalivetimer and holddowntimer needs to be modified. 

    Parameters
    ----------
    * `ADDR_TYPE` :  ip_type, ipv4/ipv6
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` : defines for router's neighbor user wants to 
                     modify BGP timers
    Usage
    -----
    # Modify BGP timers for neighbors r2 and r3 of router r1
    input_dict = {
        "r1": {
           "bgp": {
               "bgp_neighbors":{
                  "r2":{
                      "keepalivetimer": 90,
                      "holddowntimer": 270, },
                  "r3":{
                      "keepalivetimer": 50,
                      "holddowntimer": 150, }
                   }}}}

    result = modify_bgp_timers('ipv4', input_dict, tgen, topo)
    
    Returns
    -------
    errormsg(str) or True
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
                        for destRouterLink, data in topo['routers'][bgp_neighbor][
			    'links'].iteritems():
			    if 'type' in data and data['type'] == 'loopback':
                                if dest_link == destRouterLink:
                                    neighbor_ip = topo['routers'][bgp_neighbor][
				    'links'][destRouterLink][ADDR_TYPE].split('/')[0]
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
                load_config_to_router(tgen, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_bgp_timers()")
    return True

def advertise_networks_using_network_command(ADDR_TYPE, input_dict, tgen, 
                                             topo):
    """
    API to advertise defined networks to BGP. Configuration would be updated
    to BGP address-family for given router.

    Parameters
    ----------
    * `ADDR_TYPE` : ip type, ipv4/6
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` :  defines how many networks needs to be advertised for any given 
		      router
    Usage
    -----
    To advertise network from router r1
    * start_ip : Start ip to generate IPs
    * no_of_network(Optional) : Number of IPs needs to be generated, which will 
    be advertised using network command, it can be ignored if only one network
    (ex - 200.50.1.0/32) needs to advertised.
    input_dict = {
      'r1': {
         'advertise_networks': [{'start_ip': '100.50.1.0/32', 'no_of_network': 5},
         			{'start_ip': '150.50.1.0/32', 'no_of_network': 5},
         			{'start_ip': '200.50.1.0/32'}]
        }}
    
    result = advertise_networks_using_network_command('ipv4', input_dict, tgen, topo)

    Returns
    -------
    errormsg(str) or True
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
            load_config_to_router(tgen, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: advertise_networks_using_network_command()")
    return True

def modify_AS_number(ADDR_TYPE, input_dict, tgen, topo):
    """
    API reads local_as and remote_as from user defined input_dict and 
    modify router's ASNs accordingly. Router's config is modified and
    recent/changed config is loadeded to router.

    Parameters
    ----------
    * `ADDR_TYPE` : ip type, ipv4/6
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` :  defines for which router ASNs needs to be modified

    Usage
    -----
    To modify ASNs for router r1
    input_dict = {
       "r1": {
            "local_as": 131079,
            "bgp_neighbors": {
                    "r2": {
                        "remote_as": 131079,
                    }}}}
    result = modify_AS_number('ipv4', input_dict, tgen, topo)   
 
    Returns
    -------
    errormsg(str) or True
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

                bgp_neighbors = topo['routers'][router]["bgp"]["bgp_neighbors"]
		peer_json = bgp_neighbors[neighbor]['peer']
                dest_link = peer_json['dest_link']

                # loopback interface
                if "source_link" in peer_json and peer_json['source_link'] == 'lo':
                    for destRouterLink, data in topo['routers'][neighbor]['links'].\
                            iteritems():
			if 'type' in data and data['type'] == 'loopback':
                            if dest_link == destRouterLink:
                                ip_address = topo['routers'][neighbor]['links'][
                                destRouterLink][ADDR_TYPE].split("/")[0]
                else:
                    # Physical interface
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
            load_config_to_router(tgen, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: modify_AS_number()")
    return True

def redistribute_static_routes(ADDR_TYPE, input_dict, tgen, topo):
    """
    API will read config from input dictionary and create redistribute
    static, connected or with route maps config. Recent/changef config 
    will be loaded to router.

    Paramters
    ---------
    * `ADDR_TYPE` : ip type, ipv4/6
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` : defines for which router, static, connnected and 
                     route maps needs to be redistributed
    
    Usage
    -----
    # To redistribute static and connected both
    input_dict = {
        'r1': {
            "redistribute": [{"static": True}, \
                                {"connected": True}]
        }}
    # To redistribute static routes with route-map
    input_dict = {
         'r1': {
            "redistribute": [{"static": {"route-map": "RMAP_NAME"}},\
                                 {"connected": True}]
    }}
    result = redistribute_static_routes('ipv4', input_dict, tgen, topo) 

    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: redistribute_static_routes_to_bgp()")
    try:
        global bgp_cfg
        for router in input_dict.keys():
            if "redistribute" in input_dict[router]:

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
                load_config_to_router(tgen, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: redistribute_static_routes_to_bgp()")
    return True

def configure_bgp_neighbors(ADDR_TYPE, input_dict, tgen, topo):
    """
    API to create BGP address-family configuration for any given router.
    User will define config from input_dict which will be applied to 
    particular bgp neighbor and loaded to router.

    Paramaters
    ----------
    * `ADDR_TYPE` : ip type ipv4/ipv6
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` :  defines for which bgp neighbor config needs to 
  		      applied

    Usage
    ------
    # To apply route-map "RMAP_OUT" to neighbor r2 of router r1 in OUT
    direction
    input_dict = {
        'r1': {
           'neighbor_config': {
                'r2': {
                    "route_map":{
                           'RMAP_OUT': 'OUT'
                    }}}}}
    # To apply prefix-list "pf_list1" to neighbor r2 of router r1 in OUT
    direction
    input_dict = {
        'r1': {
           'neighbor_config': {
                'r2': {
                    "prefix_list":{
                           'pf_list1': 'OUT'
                    }}}}}
    # To enable next-hop-self to neighbor r2 of router r1
    input_dict = {
        'r1': {
           'neighbor_config': {
                'r2': {
                    "next_hop_self": True 
                    }}}}
    result = configure_bgp_neighbors('ipv4', input_dict, tgen, topo)   
 
    Returns
    -------
    errormsg(str) or True
    """
    
    logger.info("Entering lib API: configure_bgp_neighbors()")
    try:
        for router in input_dict.keys():
            for neighbor in input_dict[router]['neighbor_config'].keys():

                # Peer details
                bgp_neighbors = topo['routers'][router]["bgp"]["bgp_neighbors"]
                peer_json = bgp_neighbors[neighbor]['peer']
                dest_link = peer_json['dest_link']
                
		# Loopback interface
                if "source_link" in peer_json and peer_json['source_link'] == 'lo':
                    for destRouterLink, data in topo['routers'][neighbor]['links'].\
                            iteritems():
			if 'type' in data and data['type'] == 'loopback':
                            if dest_link == destRouterLink[0]:
                                nh_ip = topo['routers'][neighbor]['links'][
					destRouterLink][ADDR_TYPE].split("/")[0]
                else:
                    # Physical interface
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
                        af_modifier = IPv4_UNICAST
                        addr = Address(ADDR_TYPE_IPv4, nh_ip, None)
                    else:
                        af_modifier = IPv6_UNICAST
                        addr = Address(ADDR_TYPE_IPv6, None, nh_ip)

                    neighbor = bgp_cfg[router].routing_pb.bgp_config.get_neighbor(\
				   IPv4_UNICAST, addr)
                    neighbor.add_address_family(af_modifier, True, None, None,\
				    None, None, next_hop_self = nh_self)

                # Apply no send-community
                elif "no_send_community" in input_dict[router]['neighbor_config']\
                                        [neighbor]:
                    community = input_dict[router]['neighbor_config'][neighbor]\
                                        ["no_send_community"]

                    if ADDR_TYPE == "ipv4":
                        af_modifier = IPv4_UNICAST
                        addr = Address(ADDR_TYPE_IPv4, nh_ip, None)
                    else:
                        af_modifier = IPv6_UNICAST
                        addr = Address(ADDR_TYPE_IPv6, None, nh_ip)

                    neighbor = bgp_cfg[router].routing_pb.bgp_config.get_neighbor(\
                                   IPv4_UNICAST, addr)
                    neighbor.add_address_family(IPv4_UNICAST, True, None, None,\
                                    None, None, no_send_community = community)

            Bgp_cfg(bgp_cfg[router])
            redist_cfg(bgp_cfg[router], ADDR_TYPE)
            bgp_cfg[router].print_bgp_config_to_file(topo)
            # Load config to router
            load_config_to_router(tgen, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: configure_bgp_neighbors()")
    return True

def create_community_lists(ADDR_TYPE, input_dict, tgen, topo):
    """
    API reads data from user defined input_dict dictionary and create bgp
    community list config. Recent/changed config will be loaded to router.

    Parameters
    ----------
    * `ADDR_TYPE`  : ip type, ipv4/ipv6
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` :  defines for which router community list needs to be 
		      created
    Usage
    -----
    # To create standard large-community-lists named LC_1_STD and LC_1_STD
    for router r1
    input_dict = {
        'r1': {
            'large-community-list': {
                'standard': {
                     'LC_1_STD': [{"action": "PERMIT", "attribute":\
                                    "2:1:1 2:1:2 1:2:3"}],
                     'LC_2_STD': [{"action": "PERMIT", "attribute":\
                                    "3:1:1 3:1:2"}]
                }}}}

    # To create expanded large-community-list named LC_1_EXP for
    router r1
    input_dict = {
        'r4': {
            'large-community-list': {
                'expanded': {
                     'LC_1_EXP': [{"action": "PERMIT", "attribute":\
                                    "1:1:200 1:2:* 3:2:1"}]
                }}}}
    result = create_community_lists('ipv4', input_dict, tgen, topo)
    
    Returns
    -------
    errormsg(str) or True
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
                load_config_to_router(tgen, router)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.info("Exiting lib API: create_community_lists()")
    return True

#############################################
## Verification APIs
#############################################
def verify_router_id(input_dict, tgen, topo):
    """
    Running command "show ip bgp json" for DUT and reading router-id
    from input_dict and verifying with command output.

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `input_dict`: input dictionary, have details of Device Under Test, for
                    which user wants to test the data
    Usage
    -----
    # Verify if router-id for r1 is 12.12.12.12
    input_dict = {
        'r1':{
            'router_id': '12.12.12.12'
        }
    # Verify that router-id for r1 is highest interface ip
    input_dict = {
        "router_ids": ["r1"]
    }
    result = verify_router_id(input_dict, tgen, topo) 

    Returns
    -------
    errormsg(str) or True 
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
                router_id = find_interface_with_greater_ip(topo, dut)
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
    API will verify if BGP is converged with in the given time frame.
    Running "show bgp summary json" command and verify bgp neighbor
    state is established,

    Parameters
    ----------
    * `ADDR_TYPE`: ip_type, ipv4/ipv6
    * `tgen`: topogen object
    * `topo`: input json file data

    Usage
    -----
    # To veriry is BGP is converged for all the routers used in 
    topology
    results = verify_bgp_convergence('ipv4', tgen, topo)
    
    Returns
    -------
    errormsg(str) or True 
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
                    for neighborLink, data in topo['routers'][bgp_neighbor]['links'].\
                            iteritems():
			if 'type' in data and data['type'] == 'loopback':
                            if dest_link == neighborLink:
                                neighbor_ip = \
			        topo['routers'][bgp_neighbor]['links'][neighborLink][
				    ADDR_TYPE].split("/")[0]
                                if ADDR_TYPE == 'ipv4':
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
    This API is to clear bgp neighborship by running
    clear ip bgp */clear bgp ipv6 * command, 

    Parameters
    ----------
    * `ADDR_TYPE`: ip type ipv4/ipv6
    * `tgen`: topogen object
    * `dut`: device under test
  
    Usage
    -----
    clear_bgp('ipv4', tgen, 'r1') 
    """

    logger.info("Entering lib API: clear_bgp()")
    for router, rnode in tgen.routers().iteritems():
        if router != dut:
            continue

        # Clearing BGP
        logger.info('Clearing BGP neighborship for router {}..'.\
               format(router))
        if ADDR_TYPE == "ipv4":
            rnode.vtysh_cmd("clear ip bgp *")
	elif ADDR_TYPE == "ipv6":
            rnode.vtysh_cmd("clear bgp ipv6 *")
	sleep(5)

    logger.info("Exiting lib API: clear_bgp()")

def clear_bgp_and_verify(ADDR_TYPE, tgen, dut, topo):
    """
    This API is to clear bgp neighborship and verify bgp neighborship
    is coming up(BGP is converged) usinf "show bgp summary json" command
    and also verifying for all bgp neighbors uptime before and after
    clear bgp sessions is different as the uptime must be changed once
    bgp sessions are cleared using "clear ip bgp */clear bgp ipv6 *" cmd. 

    Parameters
    ----------
    * `ADDR_TYPE`: ip type ipv4/ipv6
    * `tgen`: topogen object
    * `dut`: device under test
    * `topo`: input json file data

    Usage
    -----
    result = clear_bgp_and_verify('ipv4', tgen, 'r1', topo)

    Returns
    -------
    errormsg(str) or True 
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
		peer_json = bgp_neighbors[bgp_neighbor]['peer']
                if "source_link" in peer_json and peer_json['source_link'] == 'lo':
                    for neighborLink, data in topo['routers'][bgp_neighbor]['links'].\
                            iteritems():
			if 'type' in data and data['type'] == 'loopback':
                            if dest_link == neighborLink:
                                neighbor_ip = topo['routers'][bgp_neighbor][
				'links'][neighborLink][ADDR_TYPE].split("/")[0]
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
		peer_json = bgp_neighbors[bgp_neighbor]['peer']
                if "source_link" in peer_json and peer_json['source_link'] == 'lo':
                    for neighborLink, data in topo['routers'][bgp_neighbor]['links'].\
                            iteritems():
			if 'type' in data and data['type'] == 'loopback':
                            if dest_link == neighborLink:
                                neighbor_ip = topo['routers'][bgp_neighbor][
				'links'][neighborLink][ADDR_TYPE].split("/")[0]
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
    API will run "show ip bgp neighbor json" command and get bgp timers for 
    DUT and verify with input_dict data. To veirfy bgp timers functonality
    we are shutting down peer interface and verifying BGP neighborship is 
    going down exactly at hold down timer. 

    Parameters
    ----------
    * `ADDR_TYPE`: ip type, ipv4/ipv6
    * `tgen`: topogen object
    * `topo`: input json file data
    * `input_dict`: defines for which router, bgp timers needs to be verified

    Usage:
    # To verify BGP timers for neighbor r2 of router r1
    input_dict = {
        "r1": {
           "bgp": {
               "bgp_neighbors":{
                  "r2":{
                      "keepalivetimer": 5,
                      "holddowntimer": 15,
                   }}}}}
    result = verify_bgp_timers_and_functionality('ipv4', tgen, input_dict, topo)

    Returns
    -------
    errormsg(str) or True 
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
                    for destRouterLink, data in topo['routers'][bgp_neighbor]['links'].\
                            iteritems():
			if 'type' in data and data['type'] == 'loopback':
                            if dest_link == destRouterLink:
                                neighbor_ip = topo['routers'][bgp_neighbor]['links']\
					[destRouterLink][ADDR_TYPE].split('/')[0]
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
		logger.info("Shutting down interface r2-r1-eth0 on router: {}..".\
			format(bgp_neighbor))
                topotest.interface_set_status(router_list[bgp_neighbor], "r2-r1-eth0",
                                              ifaceaction=False)

                # Verifying functionality
                for timer in range(keepalivetimer, holddowntimer + keepalivetimer,
                                   int(holddowntimer/3)):
                    logger.info("Waiting for {} sec..".format(keepalivetimer))
                    sleep (keepalivetimer)
                    show_bgp_json = rnode.vtysh_cmd("show bgp summary json", isjson=True)
		    
		    # Peer details
		    peer_json = \
		    topo['routers'][router]['bgp']["bgp_neighbors"][bgp_neighbor]["peer"]
                    dest_link = peer_json["dest_link"]

                    # Loopback interface
                    if "source_link" in peer_json and peer_json["source_link"] == 'lo':
                        for neighborLink, data in topo['routers'][bgp_neighbor]['links'].\
			    iteritems():
			    if 'type' in data and data['type'] == 'loopback':
                                if dest_link == neighborLink:
                                    neighbor_ip = topo['routers'][bgp_neighbor]['links'][
	    				neighborLink][ADDR_TYPE].split("/")[0]
                                    if ADDR_TYPE  == 'ipv4':
                                        nh_state = show_bgp_json["ipv4Unicast"]["peers"][
		  				neighbor_ip]["state"]
                            	    else:
                            	        nh_state = show_bgp_json["ipv6Unicast"]["peers"][
					        neighbor_ip]["state"]

	                            if timer == holddowntimer:
                                        if nh_state == "Established":
                                             errormsg = ("BGP neighborship has not gone down "
					     "in {} sec for neighbor {}".format(timer, bgp_neighbor))
                                             return errormsg
                            	        else:
                                	    logger.info("BGP neighborship has gone down in {} sec for"
                                                 " neighbor {}".format(timer, bgp_neighbor))
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

                # Keep alive message count after shutting down neighbor interface
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
    This API is to verify AS numbers for given DUT by running 
    "show ip bgp neighbor json" command. Local AS and Remote AS 
    will ve verified with input_dict data and command output.

    Parameters
    ----------
    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `tgen`: topogen object
    * `topo`: input json file data
    * `input_dict`: defines - for which router, AS numbers needs to be verified

    Usage
    -----
    input_dict = {
        "r1": {
            "local_as": 131079,
            "bgp_neighbors": {
                    "r2": {
                        "remote_as": 131079,
                    }}}}
    result = verify_AS_numbers('ipv4', tgen, input_dict, topo)

    Returns
    -------
    errormsg(str) or True
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
                    for neighborLink, data in router_data['links'].iteritems():
			if 'type' in data and data['type'] == 'loopback':
			    if dest_link == neighborLink:
                                neighbor_ip = router_data['links'][
				   neighborLink][ADDR_TYPE].split("/")[0]
                # Physical interface
                else:
                    for neighborLink in router_data['links'].iteritems():
                        if dest_link == neighborLink[0]:
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
    API will verify BGP attributes set by Route-map for given prefix and
    DUT. it will run "show bgp ipv4/ipv6 {prefix_address} json" command 
    in DUT to verify BGP attributes set by route-map, Set attributes 
    values will be read from input_dict and verified with command output. 

    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `tgen`: topogen object
    * `static_routes`: Static Routes for which BGP set attributes needs to be
                       verified
    * `rmap_name`: route map name for which set criteria needs to be verified
    * `input_dict`: defines for which router, AS numbers needs
                    to be verified
    Usage
    -----
    # To verify BGP attribute "localpref" set to 150 and "med" set to 30
    for prefix 10.0.20.1/32 in router r3.
    input_dict = {
      "r3": {
         "route_maps": {
            "rmap_match_pf_list1": [{"action": "PERMIT", \
				   "match": {"prefix_list": "pf_list_1"},\
			           "set": {"localpref": 150, "med": 30}}],
            }}}
    static_routes (list) = ["10.0.20.1/32"]
    result = verify_bgp_attributes('ipv4', "r4", tgen, static_routes, \
			          "rmap_match_pf_list1", input_dict)
  
    Returns
    -------
    errormsg(str) or True
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
                                        errormsg = \
					 ("Failed: Verifying BGP"
                                         "attribute {} for route:{}"
                                         " in router: {}, expected"
                                         " value: {} but found: {}".
                                         format(criteria, static_route,
                                               dut,
                                               rmap_dict["set"][criteria],
                                               show_bgp_json['paths'][0][criteria]))
                                        return errormsg

    logger.info("Exiting lib API: verify_bgp_attributes()")
    return True

def verify_best_path_as_per_bgp_attribute(ADDR_TYPE, dut, input_dict, tgen,\
					  attribute):
    """ 
    API is to verify best path according to BGP attributes for given routes.
    "show bgp ipv4/6 json" command will be run and verify best path according
    to shortest as-path, highest local-preference and med, lowest weight and 
    route origin IGP>EGP>INCOMPLETE. 

    Parameters
    ----------
    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `tgen` : topogen object
    * `attribute` : calculate best path using this attribute
    * `input_dict`: defines different routes to calculate for which route
                    best path is selected

    Usage
    -----
    # To verify best path for routes 200.50.2.0/32 and 200.60.2.0/32 from 
    router r7 to router r1(DUT) as per shortest as-path attribute
    input_dict = {
        'r7': {
            'advertise_networks': [{'start_ip': '200.50.2.0/32'},
                                   {'start_ip': '200.60.2.0/32'}]
        }}
    attribute = "localpref"
    result = verify_best_path_as_per_bgp_attribute('ipv4', "r1", input_dict,\
				                    tgen,  attribute)
    Returns
    -------
    errormsg(str) or True
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

def verify_best_path_as_per_admin_distance(ADDR_TYPE, dut, input_dict, \
						     tgen, attribute):
    """ 
    API is to verify best path according to admin distance for given
    route. "show ip/ipv6 route json" command will be run and verify
    best path accoring to shortest admin distanc.

    Parameters
    ----------
    * `ADDR_TYPE` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `tgen` : topogen object
    * `attribute` : calculate best path using admin distance
    * `input_dict`: defines different routes with different admin distance
                    to calculate for which route best path is selected
    Usage
    -----
    # To verify best path for route 200.50.2.0/32 from  router r2 to 
    router r1(DUT) as per shortest admin distance which is 60.
    input_dict = {
        "r2": {
            "static_routes": [{"network": "200.50.2.0/32", \
			     "admin_distance": 80, "next_hop": "10.0.0.14"},
                              {"network": "200.50.2.0/32", \
			     "admin_distance": 60, "next_hop": "10.0.0.18"}]
        }}
    attribute = "localpref"
    result = verify_best_path_as_per_bgp_attribute('ipv4', "r1", input_dict,\
                                                    tgen,  attribute)
    Returns
    -------
    errormsg(str) or True
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
    API to veiryf BGP large community is attached in route for any given 
    DUT by running "show bgp ipv4/6 {route address} json" command.

    Parameters
    ----------
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `tgen`: topogen object
    * `network`: network for which set criteria needs to be verified
    * `input_dict`: having details like - for which router, community and 
		    values needs to be verified
    Usage
    -----
    networks = ['200.50.2.0/32']
    input_dict = {
        'largeCommunity': '2:1:1 2:2:2 2:3:3 2:4:4 2:5:5'
    }
    result = verify_bgp_community('ipv4', "r4", tgen, networks, input_dict)

    Returns
    -------
    errormsg(str) or True
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

def verify_create_community_list(input_dict, tgen):
    """
    API is to verify if large community list is created for any given DUT in
    input_dict by running "sh bgp large-community-list {"comm_name"} detail"
    command.

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict`: having details like - for which router, large community
                    needs to be verified
    Usage
    -----
    input_dict = {
        'r1': {
            'large-community-list': {
                'standard': {
                     'Test1': [{"action": "PERMIT", "attribute":\
                                    ""}]
                }}}}
    result = verify_create_community_list(input_dict, tgen)

    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: verify_create_community_list()")


    for dut in input_dict.keys():
        for router, rnode in tgen.routers().iteritems():
            if router != dut:
                continue

            logger.info('Verifying large-community is created for dut {}:'\
			.format(router))

	    for comm_type in  input_dict[router]["large-community-list"].keys():
	        for comm_name in input_dict[router]["large-community-list"]\
		    [comm_type].keys():	
                    show_bgp_community = \
		    rnode.vtysh_cmd("show bgp large-community-list {} detail".\
		    format(comm_name))
		    logger.info(show_bgp_community)

		    # Verify community list and type
		    if comm_type in show_bgp_community and comm_type in show_bgp_community: 
		        logger.info("BGP {} large-community-list {} is created".\
			format(comm_type, comm_name))
		    else:
                        errormsg = ("BGP {} large-community-list {} is not created".\
                        format(comm_type, comm_name))
			return errormsg
		    
        logger.info("Exiting lib API: verify_create_community_list()")
        return True


