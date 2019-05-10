#!/usr/bin/python

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
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
Following tests are covered to test prefix-list functionality:

Test steps
- Create topology (setup module)
  Creating 4 routers topology, r1, r2, r3 are in IBGP and
  r3, r4 are in EBGP
- Bring up topology
- Verify for bgp to converge

IP prefix-list tests
- Test ip prefix-lists IN permit
- Test ip prefix-lists OUT permit
- Test ip prefix-lists IN deny and permit any
- Test delete ip prefix-lists
- Test ip prefix-lists OUT deny and permit any
- Test modify ip prefix-lists IN permit to deny
- Test modify ip prefix-lists IN deny to permit
- Test modify ip prefix-lists OUT permit to deny
- Test modify prefix-lists OUT deny to permit
- Test ip prefix-lists implicit deny
"""

import re
import sys
import pdb
import json
import time
import inspect
import StringIO
import ipaddress
import os, fnmatch
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))
#sys.path.append(os.path.join(CWD, '../lib/'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from mininet.topo import Topo
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

# Import topoJson from lib, to create topology and initial configuration
from lib.topojson import *

# Reading the data from JSON File for topology creation
jsonFile = "{}/prefix_lists.json".format(CWD)

try:
    with open(jsonFile, 'r') as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

# Global variables
bgp_convergence = False

class BGPPrefixListTopo(Topo):
    """
    Test BGPPrefixListTopo - topology 1

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Building topology from json file
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
    tgen = Topogen(BGPPrefixListTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Checking BGP convergence
    global bgp_convergence

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence(tgen, topo, 'ipv4')
    assert bgp_convergence is True, ('setup_module :Failed \n Error:'
                                     ' {}'.format(bgp_convergence))

    logger.info("Running setup_module() done")

def teardown_module(mod):
    """
    Teardown the pytest environment

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    stop_topology(tgen)

    logger.info("Testsuite end time: {}".\
                format(time.asctime(time.localtime(time.time()))))
    logger.info("="*40)

#####################################################
##
##   Tests starting
##
#####################################################
def test_ip_prefix_lists_IN_permit():
    """
    Create ip prefix list and test permit prefixes IN direction
    """

    tgen = get_topogen()
    global bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Create Static routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure bgp neighbor with prefix list
    input_dict_3 = {
        'r3': {
            'neighbor_config': {
                'r1': {
                    "prefix_list": {
                        'pf_list_1': 'IN'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_ip_prefix_lists_OUT_permit():
    """
    Create ip prefix list and test permit prefixes IN direction
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Create Static routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        'r1': {
            'prefix_lists': {
                'pf_list_1': [{
                    'seqid': 10,
                    'network': 'any',
                    'action': 'permit'
                }]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_3 = {
        'r1': {
            'neighbor_config': {
                'r3': {
                    "prefix_list": {
                        'pf_list_1': 'OUT'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_ip_prefix_lists_IN_deny_and_permit_any():
    """
    Create ip prefix list and test permit/deny prefixes IN direction
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Create Static Routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        'r1': {
            'prefix_lists': {
                'pf_list_1': [
                    {
                        'seqid': '10',
                        'network': '10.0.20.1/32',
                        'action': 'deny'
                    },
                    {
                        'seqid': '11',
                        'network': 'any',
                        'action': 'permit'
                    }
                ]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_3 = {
        'r3': {
            'neighbor_config': {
                'r1': {
                    "prefix_list": {
                        'pf_list_1': 'IN'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is not True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_delete_prefix_lists():
    """
    Delete ip prefix list
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Delete prefix list
    input_dict = {
        'r3': {
            'prefix_lists': ['pf_list_1']
        },
        'r1': {
            'prefix_lists': ['pf_list_1']
        }
    }
    result = delete_prefix_lists(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    result = verify_prefix_lists(tgen, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_ip_prefix_lists_OUT_deny_and_permit_any():
    """
    Create ip prefix list and test deny/permit any prefixes OUT direction
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Create Static Routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create Static Routes
    input_dict_1 = {
        'r2': {
            "static_routes": [{
                "network": "20.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.1"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_2 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]
        },
        'r2': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_3 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [
                    {
                        'seqid': '10',
                        'network': '10.0.0.0/8',
                        'le': '32',
                        'action': 'deny'
                    },
                    {
                        'seqid': '11',
                        'network': 'any',
                        'action': 'permit'
                    }
                ]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_4 = {
        'r3': {
            'neighbor_config': {
                'r4': {
                    "prefix_list": {
                        'pf_list_1': 'OUT'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict_1, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is not True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_modify_prefix_lists_IN_permit_to_deny():
    """
    Modify ip prefix list and test permit to deny prefixes IN direction
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Create Static Routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_2 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [{
                    'seqid': '10',
                    'network': '10.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_3 = {
        'r3': {
            'neighbor_config': {
                'r1': {
                    "prefix_list": {
                        'pf_list_1': 'IN'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Modify prefix list
    input_dict_1 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [
                    {
                        'seqid': '10',
                        'network': '10.0.0.0/8',
                        'le': '32',
                        'action': 'deny'
                    },
                    {
                        'seqid': '11',
                        'network': 'any',
                        'action': 'permit'
                    }
                ]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = 'r3'
    result = clear_bgp_and_verify(tgen, topo, 'ipv4', dut)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is not True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_modify_prefix_lists_IN_deny_to_permit():
    """
    Modify ip prefix list and test deny to permit prefixes IN direction
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Create Static Routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_1 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [
                    {
                        'seqid': '10',
                        'network': '10.0.0.0/8',
                        'le': '32',
                        'action': 'deny'
                    },
                    {
                        'seqid': '11',
                        'network': 'any',
                        'action': 'permit'
                    }
                ]
            }
        }
    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_2 = {
        'r3': {
            'neighbor_config': {
                'r1': {
                    "prefix_list": {
                        'pf_list_1': 'IN'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is not True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Modify  ip prefix list
    input_dict_1 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [{
                    'seqid': '10',
                    'network': '10.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        }

    }
    result = modify_prefix_lists(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = 'r3'
    result = clear_bgp_and_verify(tgen, topo, 'ipv4', dut)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r3'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_modify_prefix_lists_OUT_permit_to_deny():
    """
    Modify ip prefix list and test permit to deny prefixes OUT direction
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Create Static Routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_1 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [{
                    'seqid': '10',
                    'network': '10.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        }

    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_2 = {
        'r3': {
            'neighbor_config': {
                'r4': {
                    "prefix_list": {
                        'pf_list_1': 'OUT'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Modify ip prefix list
    input_dict_1 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [
                    {
                        'seqid': '10',
                        'network': '10.0.0.0/8',
                        'le': '32',
                        'action': 'deny'
                    },
                    {
                        'seqid': '11',
                        'network': 'any',
                        'action': 'permit'
                    }
                ]
            }
        }

    }
    result = modify_prefix_lists(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = 'r3'
    result = clear_bgp_and_verify(tgen, topo, 'ipv4', dut)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is not True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_modify_prefix_lists_OUT_deny_to_permit():
    """
    Modify ip prefix list and test deny to permit prefixes OUT direction
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Create Static Routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]}
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_1 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [
                    {
                        'seqid': '10',
                        'network': '10.0.0.0/8',
                        'le': '32',
                        'action': 'deny'
                    },
                    {
                        'seqid': '11',
                        'network': 'any',
                        'action': 'permit'
                    }
                ]
            }
        }

    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Configure prefix list to bgp neighbor
    input_dict_2 = {
        'r3': {
            'neighbor_config': {
                'r4': {
                    "prefix_list": {
                        'pf_list_1': 'OUT'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is not True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Modify ip prefix list
    input_dict_1 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [{
                    'seqid': '10',
                    'network': '10.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        }

    }
    result = modify_prefix_lists(tgen, topo, 'ipv4', input_dict_1)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to clear bgp, so config changes would be reflected
    dut = 'r3'
    result = clear_bgp_and_verify(tgen, topo, 'ipv4', dut)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

def test_ip_prefix_lists_implicit_deny():
    """
    Create ip prefix list and test implicit deny
    """

    tgen = get_topogen()
    global frr_cfg, bgp_convergence

    if bgp_convergence != True:
        pytest.skip('skipped because of BGP Convergence failure')

    # test case name
    tc_name = inspect.stack()[0][3]
    write_test_header(tc_name)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Create Static Routes
    input_dict = {
        'r1': {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create Static Routes
    input_dict_1 = {
        'r2': {
            "static_routes": [{
                "network": "20.0.20.1/32",
                "no_of_ip": 9,
                "next_hop": "10.0.0.1"
            }]
        }
    }
    result = create_static_routes(tgen, topo, 'ipv4', input_dict)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Api call to redistribute static routes
    input_dict_2 = {
        'r1': {
            "redistribute": [{"static": True}, {"connected": True}]
        },
        'r2': {
            "redistribute": [{"static": True}, {"connected": True}]
        }
    }
    result = redistribute_static_routes(tgen, topo, 'ipv4', input_dict_2)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Create ip prefix list
    input_dict_3 = {
        'r3': {
            'prefix_lists': {
                'pf_list_1': [{
                    'seqid': '10',
                    'network': '10.0.0.0/8',
                    'le': '32',
                    'action': 'permit'
                }]
            }
        }

    }
    result = create_prefix_lists(tgen, topo, 'ipv4', input_dict_3)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)


    # Configure prefix list to bgp neighbor
    input_dict_4 = {
        'r3': {
            'neighbor_config': {
                'r4': {
                    "prefix_list": {
                        'pf_list_1': 'OUT'
                    }
                }
            }
        }
    }
    result = configure_bgp_neighbors(tgen, topo, 'ipv4', input_dict_4)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict, protocol=protocol)
    assert result is True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    # Verifying RIB routes
    dut = 'r4'
    protocol = 'bgp'
    result = verify_rib(tgen, 'ipv4', dut, input_dict_1, protocol=protocol)
    assert result is not True, 'Testcase {} : Failed \n Error: {}'.format(
        tc_name, result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    #tgen.mininet_cli()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
