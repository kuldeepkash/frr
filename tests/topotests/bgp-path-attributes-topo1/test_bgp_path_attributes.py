#!/usr/bin/env python

#
# Modified work Copyright (c) 2019 by VMware, Inc. ("VMware")
# Original work Copyright (c) 2018 by Network Device Education
# Foundation, Inc. ("NetDEF")
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
Following tests are covered to test AS-Path functionality:

Setup module:
- Create topology (setup module)
- Bring up topology
- Verify BGP convergence

Test cases:
1. Test next_hop attribute and verify best path is installed as per
   reachable next_hop
2. Test aspath attribute and verify best path is installed as per
   shortest AS-Path
3. Test localpref attribute and verify best path is installed as per
   shortest local-preference
4. Test weight attribute and and verify best path is installed as per
   highest weight
5. Test origin attribute and verify best path is installed as per
   IGP>EGP>INCOMPLETE rule
6. Test med attribute and verify best path is installed as per lowest
   med value
7. Test admin distance and verify best path is installed as per lowest
   admin distance

Teardown module:
- Bring down the topology
- stop routers

"""

import os
import sys
import pdb
import json
import time
import inspect
import ipaddress
from time import sleep
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from mininet.topo import Topo
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

# Required to instantiate the topology builder class.
from lib.topojson import *

# Reading the data from JSON File for topology creation
jsonFile = "{}/bgp_path_attributes.json".format(CWD)

try:
    with open(jsonFile, 'r') as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

####
class CreateTopo(Topo):
    """
    Test CreateTopo - topology 1

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
    logger.info("Testsuite start time: %s", testsuite_run_time)
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(CreateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Checking BGP convergence
    result = verify_bgp_convergence(tgen, topo, 'ipv4')
    assert result is True, ('setup_module :Failed \n Error:'
                            ' {}'.format(result))

    logger.info("Running setup_module() done")


def teardown_module():
    """
    Teardown the pytest environment
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    stop_topology(tgen)

    logger.info("Testsuite end time: %s",
                time.asctime(time.localtime(time.time())))
    logger.info("=" * 40)


#####################################################
##
##   Testcases
##
#####################################################
def test_next_hop_attribute():
    """
    Verifying route are not getting installed in, as next_hop is
    unreachable, Making next hop reachable using next_hop_self
    command and verifying routes are installed.
    """

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Api call to advertise networks
    input_dict = {
        'r7': {
            'advertise_networks': [
                {
                    'start_ip': '200.50.2.0/32'
                },
                {
                    'start_ip': '200.60.2.0/32'
                }
            ]
        }
    }
    result = advertise_networks_using_network_command(tgen, topo, 'ipv4',
                                                      input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r1'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    try:
        assert result is True
    except AssertionError:
        logger.info("Expected behaviour: %s", result)

    # Configure next-hop-self to bgp neighbor
    input_dict_1 = {
        'r2': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        },
        'r3': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r1'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase %s :Passed \n", tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_aspath_attribute():
    " Verifying AS_PATH attribute functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, )

    # Api call to advertise networks
    input_dict = {
        'r7': {
            'advertise_networks': [
                {
                    'start_ip': '200.50.2.0/32'
                },
                {
                    'start_ip': '200.60.2.0/32'
                }
            ]
        }
    }
    result = advertise_networks_using_network_command(tgen, topo, 'ipv4',
                                                      input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure next-hop-self to bgp neighbor
    input_dict_1 = {
        'r2': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        },
        'r3': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying best path
    dut = 'r1'
    attribute = "aspath"
    result = verify_best_path_as_per_bgp_attribute(tgen, 'ipv4', dut,
                                                   input_dict, attribute)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase %s :Passed \n", tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_localpref_attribute():
    " Verifying LOCAL PREFERENCE attribute functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, )

    # Api call to advertise networks
    input_dict = {
        'r7': {
            'advertise_networks': [
                {
                    'start_ip': '200.50.2.0/32'
                },
                {
                    'start_ip': '200.60.2.0/32'
                }
            ]
        }
    }
    result = advertise_networks_using_network_command(tgen, topo, 'ipv4',
                                                      input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure next-hop-self to bgp neighbor
    input_dict_1 = {
        'r2': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        },
        'r3': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create Prefix list
    input_dict_2 = {
        'r2': {
            'prefix_lists': {
                'pf_ls_1': [{
                    'seqid': 10,
                    'network': '200.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    input_dict_3 = {
        "r2": {
            "route_maps": {
                "RMAP_LOCAL_PREF": [{
                    "action": "PERMIT",
                    "match": {
                        "prefix_list": "pf_ls_1"
                    },
                    "set": {
                        "localpref": 1000
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        'r2': {
            'neighbor_config': {
                'r4': {
                    "route_map": {
                        'RMAP_LOCAL_PREF': 'IN'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying best path
    dut = 'r1'
    attribute = "localpref"
    result = verify_best_path_as_per_bgp_attribute(tgen, 'ipv4', dut,
                                                   input_dict, attribute)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase %s :Passed \n", tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_weight_attribute():
    " Verifying WEIGHT attribute functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, )

    # Api call to advertise networks
    input_dict = {
        'r7': {
            'advertise_networks': [
                {
                    'start_ip': '200.50.2.0/32'
                },
                {
                    'start_ip': '200.60.2.0/32'
                }
            ]
        }
    }
    result = advertise_networks_using_network_command(tgen, topo, 'ipv4',
                                                      input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure next-hop-self to bgp neighbor
    input_dict_1 = {
        'r2': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        },
        'r3': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create Prefix list
    input_dict_2 = {
        'r1': {
            'prefix_lists': {
                'pf_ls_1': [{
                    'seqid': 10,
                    'network': '200.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    input_dict_3 = {
        "r1": {
            "route_maps": {
                "RMAP_WEIGHT": [{
                    "action": "PERMIT",
                    "match": {
                        "prefix_list": "pf_ls_1"
                    },
                    "set": {
                        "weight": 500
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        'r1': {
            'neighbor_config': {
                'r2': {
                    "route_map": {
                        'RMAP_WEIGHT': 'IN'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying best path
    dut = 'r1'
    attribute = "weight"
    result = verify_best_path_as_per_bgp_attribute(tgen, 'ipv4', dut,
                                                   input_dict, attribute)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase %s :Passed \n", tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_origin_attribute():
    " Verifying ORIGIN attribute functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, )

    # Api call to advertise networks
    input_dict = {
        'r4': {
            'advertise_networks': [
                {
                    'start_ip': '200.50.2.0/32'
                },
                {
                    'start_ip': '200.60.2.0/32'
                }
            ]
        }
    }
    result = advertise_networks_using_network_command(tgen, topo, 'ipv4',
                                                      input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to create static routes
    input_dict_3 = {
        "r5": {
            "static_routes": [
                {
                    "network": "200.50.2.0/32",
                    "next_hop": "10.0.0.26"
                },
                {
                    "network": "200.60.2.0/32",
                    "next_hop": "10.0.0.26"
                }
            ]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_4 = {
        'r5': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure next-hop-self to bgp neighbor
    input_dict_1 = {
        'r2': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        },
        'r3': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying best path
    dut = 'r1'
    attribute = "origin"
    result = verify_best_path_as_per_bgp_attribute(tgen, 'ipv4', dut,
                                                   input_dict, attribute)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase %s :Passed \n", tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_med_attribute():
    " Verifying MED attribute functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo, )

    # Api call to advertise networks
    input_dict = {
        'r4': {
            'advertise_networks': [
                {
                    'start_ip': '200.50.2.0/32'
                },
                {
                    'start_ip': '200.60.2.0/32'
                }
            ]
        }
    }
    result = advertise_networks_using_network_command(tgen, topo, 'ipv4',
                                                      input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to advertise networks
    input_dict_1 = {
        'r5': {
            'advertise_networks': [
                {
                    'start_ip': '200.50.2.0/32'
                },
                {
                    'start_ip': '200.60.2.0/32'
                }
            ]
        }
    }
    result = advertise_networks_using_network_command(tgen, topo, 'ipv4',
                                                      input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure next-hop-self to bgp neighbor
    input_dict_2 = {
        'r2': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        },
        'r3': {
            'neighbor_config': {
                'r1': {
                    "next_hop_self": True
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create Prefix list
    input_dict_3 = {
        'r2': {
            'prefix_lists': {
                'pf_ls_r2': [{
                    'seqid': 10,
                    'network': '200.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        },
        'r3': {
            'prefix_lists': {
                'pf_ls_r3': [{
                    'seqid': 10,
                    'network': '200.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create route map
    input_dict_3 = {
        "r2": {
            "route_maps": {
                "RMAP_MED_R2": [{
                    "action": "PERMIT",
                    "match": {
                        "prefix_list": "pf_ls_r2"
                    },
                    "set": {
                        "med": 100
                    }
                }]
            }
        },
        "r3": {
            "route_maps": {
                "RMAP_MED_R3": [{
                    "action": "PERMIT",
                    "match": {
                        "prefix_list": "pf_ls_r3"
                    },
                    "set": {
                        "med": 10
                    }
                }]
            }
        }
    }
    result = create_route_maps(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure neighbor for route map
    input_dict_4 = {
        'r2': {
            'neighbor_config': {
                'r4': {
                    "route_map": {
                        'RMAP_MED_R2': 'IN'
                    }
                }
            }
        },
        'r3': {
            'neighbor_config': {
                'r5': {
                    "route_map": {
                        'RMAP_MED_R3': 'IN'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying best path
    dut = 'r1'
    attribute = "med"
    result = verify_best_path_as_per_bgp_attribute(tgen, 'ipv4', dut,
                                                   input_dict, attribute)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase %s :Passed \n", tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


def test_admin_distance():
    " Verifying admin distance functionality"

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Api call to create static routes
    input_dict = {
        "r2": {
            "static_routes": [
                {
                    "network": "200.50.2.0/32",
                    "admin_distance": 80,
                    "next_hop": "10.0.0.14"
                },
                {
                    "network": "200.50.2.0/32",
                    "admin_distance": 60,
                    "next_hop": "10.0.0.18"
                }
            ]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict, )
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_2 = {
        'r2': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying best path
    dut = 'r1'
    attribute = "admin_distance"
    result = verify_best_path_as_per_admin_distance(tgen, 'ipv4', dut,
                                                    input_dict, attribute)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase %s :Passed \n", tc_name)

    # Uncomment next line for debugging
    # tgen.mininet_cli()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
