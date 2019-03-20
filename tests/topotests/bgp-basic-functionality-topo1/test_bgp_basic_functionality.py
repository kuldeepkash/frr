#!/usr/bin/env python

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

"""
Following tests are covered to test BGP basic functionality:

Test steps
- Create topology (setup module) 
  Creating 4 routers topology, r1, r2, r3 are in IBGP and r3, r4 are in EBGP
- Bring up topology 
- Verify for bgp to converge
- Modify/Delete and verify router-id
- Modify and verify bgp timers
- Create and verify static routes
- Modify and verify admin distance for existing static routes
- Test advertise network using network command
- Verify clear bgp
- Test bgp convergence with loopback interface
- Test advertise network using network command
"""


import os
import sys
import pdb
import json
import pytest
import inspect
import ipaddress
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))
sys.path.append(os.path.join(CWD, '../lib/'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from mininet.topo import Topo

# Required to instantiate the topology builder class.
from mininet.topo import Topo
from lib.topojson import *

# Reading the data from JSON File for topology creation
jsonFile = "test_bgp_basic_functionality.json"
try:
    with open(jsonFile, 'r') as topoJson:
        topo = json.load(topoJson)
except IOError:
    logger.info("Could not read file:", jsonFile)

# Global variables
bgp_convergence = None

# input_dict, dictionary would be used to provide input to APIs
input_dict = {}

class BGPBasicTopo(Topo):
    """
    Test BGPBasicTopo - topology 1
   
    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

	# Building topology and configuration from json file
 	build_topo_from_json(tgen, topo)

def setup_module(mod):
    """
    Sets up the pytest environment
    
    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("="*40)

    logger.info("Running setup_module to create topology")
   
    # This function initiates the topology build with Topogen...
    tgen = Topogen(BGPBasicTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    
    tgen.start_topology()
    
    # Uncomment following line to enable debug logs and comment - tgen.start_topology() 
    #tgen.start_topology(log_level='debug')

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
	try:
	    os.chdir(CWD)
	    # Deleting router named dirs if exists
	    if os.path.exists('{}'.format(rname)):
		os.system("rm -rf {}".format(rname))
	    
	    # Creating rouer named dir and emoty zebra.conf bgpd.conf files inside the current directory    
	    os.mkdir('{}'.format(rname))
    	    os.chdir("{}/{}".format(CWD, rname))
  	    os.system('touch zebra.conf bgpd.conf')
        except IOError as (errno, strerror):
	    logger.error("I/O error({0}): {1}".format(errno, strerror))

 	router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    # After loading the configurations, this function starts configured daemons.
    logger.info("Starting all routers once topology is created")
    tgen.start_router()

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, CWD)
    
    logger.info("Running setup_module() done")

def teardown_module(mod):
    """
    Teardown the pytest environment
   
    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")    
    
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

    # Removing tmp dirs and files
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        try:
            os.chdir(CWD)
            os.system("rm -rf {}".format(rname))
        except IOError as (errno, strerror):
            logger.error("I/O error({0}): {1}".format(errno, strerror))

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite end time: {}".format(testsuite_run_time))
    logger.info("="*40)


#####################################################
##
##   Testcases
##
#####################################################

def test_bgp_convergence():
    " Test BGP daemon convergence "
	
    tgen = get_topogen()
    global bgp_convergence

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence('ipv4', tgen, topo)
    if bgp_convergence != True: assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(bgp_convergence)  
    
    logger.info("Testcase " + tc_name + " :Passed \n")
    
    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_modify_and_delete_router_id():
    " Test to modify, delete and verify router-id. "

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence != True:
	pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    ## API call to modify router id
    # input_dict dictionary to be provided to modify_delete_router_id()
    input_dict = {
	'r1':{
	    'router_id': '12.12.12.12'
	},
	'r2':{
	    'router_id': '22.22.22.22'
	},
	'r3':{
	    'router_id': '33.33.33.33'
	},
    }
    result = modify_delete_router_id('modify', input_dict, CWD, tgen, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Verifying router id once modified
    result = verify_router_id(input_dict, tgen, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Errnor: {}".format(result)

    ## API call to delete router id
    # input_dict dictionary to be provided to modify_delete_router_id()
    input_dict = {
	"router_ids": ["r1", "r2", "r3"],
    }
    result = modify_delete_router_id('delete', input_dict, CWD, tgen, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Verifying router id once deleted
    # Once router-id is deleted, highest interface ip should become router-id
    result = verify_router_id(input_dict, tgen, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_BGP_config_with_4byte_AS_number():
    """ 
    Test advertise networks using network command.
    """

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Api call to modify AS number
    input_dict = {
        "r1": {
            "as_number": 131079,
            "bgp_neighbors": {
                    "r2": {
                        "remoteas": 131079,
                    },
                    "r3": {
                        "remoteas": 131079,
                    }
            }
        },
        "r2": {
            "as_number": 131079,
            "bgp_neighbors": {
                    "r1": {
                        "remoteas": 131079,
                    },
                    "r3": {
                        "remoteas": 131079,
                    }
            }
        },
        "r3": {
            "as_number": 131079,
            "bgp_neighbors": {
                    "r1": {
                        "remoteas": 131079,
                    },
                    "r2": {
                        "remoteas": 131079,
                    },
                    "r4": {
                        "remoteas": 131080,
                    }
            }
        },
        "r4": {
            "as_number": 131080,
            "bgp_neighbors": {
                    "r3": {
                        "remoteas": 131079,
                    }
            }
        }
    }
    result = modify_AS_number('ipv4', input_dict, tgen, CWD, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    result = verify_AS_numbers('ipv4', tgen, input_dict, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)    

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_bgp_timers():
    """
    Test to modify bgp timers and verify in running config.
    
    Usage:
    * If user wants to modify BGP timers for all the neighbors for  any router then we can pass input_dict
        as below:
    input_dict = {
        "r1(any router)": {
            "BGP_Global_Timers": {
                "keepalivetimer": 90(as per test),
                "holddowntimer": 270(as per test)
            } // can provide data for multiple/all routers in topology

    * If user wants to modify BGP timers to any specific neighbor of router then we can pass input_dict
        as below:
    input_dict = {
        "r1": {
            "bgp_neighbors":{
               "r2":{ 
                    "keepalivetimer": 90,
                    "holddowntimer": 270,
               }
            }
        }
    }
    """

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, CWD)

    # Api call to modfiy/delete admin distance
    input_dict = {
        "r1": {
            "bgp_neighbors":{
               "r2":{ 
                    "keepalivetimer": 90,
                    "holddowntimer": 270,
               }
            }
        }
    }
    result = modify_bgp_timers('ipv4', input_dict, CWD, tgen, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Verifying bgp timers once modified
    result = verify_bgp_timers('ipv4', tgen, input_dict, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_static_routes():
    " Test to create and verify static routes. "

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # Test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Api call to create static routes
    input_dict = {
        "r1": {
            "static_routes": [{"network": "10.0.20.1/32", "no_of_ip": 9, "admin_distance": 100, "next_hop": "10.0.0.2", "tag": 4001}]
        }
    }
    result = create_static_routes('ipv4', input_dict, tgen, CWD, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Api call to redistribute static routes
    input_dict_1 = {
        'r1': {
	    'redistribute': {
		  'static': True,
		  'connected': True,
	    }
	}
    }
    result = redistribute_static_routes('ipv4', input_dict_1, tgen, CWD, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    next_hop = '10.0.0.2'
    result = verify_rib('ipv4', dut, tgen, input_dict, next_hop = next_hop, protocol = protocol)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_admin_distance_for_existing_static_routes():
    " Test to modify and verify admin distance for static routes."

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Api call to modfiy/delete admin distance
    input_dict = {
        'r1': {
            '10.0.20.1/32':{
                'admin_distance': 10,
                'next_hop': '10.0.0.2'
            }
        }
    }
    result = modify_admin_distance_for_static_routes(input_dict, CWD, tgen, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Verifying admin distance  once modified
    result = verify_admin_distance_for_static_routes(input_dict, tgen)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_advertise_network_using_network_command():
    "Test advertise networks using network command."

    tgen = get_topogen()
    global frr_cfg, bgp_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Api call to advertise networks
    input_dict = {
        'r1': {
            'advertise_networks': [{'start_ip': '20.0.0.0/32', 'no_of_network': 10},
				   {'start_ip': '30.0.0.0/32'}]
    	}
    }
    result = advertise_networks_using_network_command('ipv4', input_dict, tgen, CWD, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Verifying RIB routes
    dut = 'r2'
    protocol = "bgp"
    result = verify_rib('ipv4', dut, tgen, input_dict, protocol = protocol)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_clear_bgp():
    " Test clear bgp functionality. "

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    # Api call to modfiy/delete admin distance
    dut = 'r1'
    result = clear_bgp_and_verify('ipv4', tgen, dut, topo)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_bgp_with_loopback_interface():
    """ 
    Test BGP with loopback interface
    
    We are adding "source": "lo" in input json file to all the router's neighbors and creating config using loopback interface.
    Once tested we are deleting key "source": "lo" from input json file for all the router's neighbors and creating config using physical interface.
    """

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    logger.info("Testcase started: {} \n".format(tc_name))

    for routerN in sorted(topo['routers'].iteritems()):
        for bgp_neighbor in topo['routers'][routerN[0]]['bgp']['bgp_neighbors'].iteritems():
            topo['routers'][routerN[0]]['bgp']['bgp_neighbors'][bgp_neighbor[0]]['peer']['source'] = 'lo'

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, CWD)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence('ipv4', tgen, topo)
    if bgp_convergence != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(bgp_convergence)

    # Cleanup to bring config back to physical interface from loopback interface
    for routerN in sorted(topo['routers'].iteritems()):
        for bgp_neighbor in topo['routers'][routerN[0]]['bgp']['bgp_neighbors'].iteritems():
            try:
                del topo['routers'][routerN[0]]['bgp']['bgp_neighbors'][bgp_neighbor[0]]['peer']['source']
            except KeyError:
                logger.error("Key: source is not found \n")

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, CWD)
    
    bgp_convergence = verify_bgp_convergence('ipv4', tgen, topo)
    if bgp_convergence != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(bgp_convergence)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
