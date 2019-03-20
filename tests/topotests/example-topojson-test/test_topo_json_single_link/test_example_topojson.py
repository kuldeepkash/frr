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
<example>.py: Test <example tests>.
"""

import os
import sys
import json
import inspect
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

# Import topoJson from lib, to create topology and initial configuration
from lib.topojson import *

# Reading the data from JSON File for topology and configuration creation
jsonFile = "test_example_topojson.json"
try:
    with open(jsonFile, 'r') as topoJson:
        topo = json.load(topoJson)
except IOError:
    logger.info("Could not read file:", jsonFile)

# Global variables
bgp_convergence = False
input_dict = {}

class TemplateTopo(Topo):
    """
    Test topology builder
   
    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to create topology
        # as defined in input json file.
        #
        # Example
        #
        # Creating 2 routers having single links in between,
        # which is used to establised BGP neighborship

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
    tgen = Topogen(TemplateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology
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

        # Loading empty zebra.conf file to router, to start the zebra deamon
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        # Loading empty bgpd.conf file to router, to start the bgp deamon
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    # After loading the configurations, this function starts configured daemons.
    logger.info("Starting all routers once topology is created")
    tgen.start_router()

    # This function only purpose is to create configuration
    # as defined in input json file.
    #
    # Example
    #
    # Creating configuration defined in input JSON
    # file, example, BGP config, interface config, static routes
    # config, prefix list config

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

def test_bgp_convergence():
    " Test BGP daemon convergence "

    tgen = get_topogen()
    global bgp_convergence

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    bgp_convergence = verify_bgp_convergence('ipv4', tgen, topo)
    if bgp_convergence != True: assert False, "test_bgp_convergence failed.. \n Error: {}".format(bgp_convergence)

    logger.info("BGP is converged successfully \n")

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

    # Static routes are created as part of initial configuration, verifying RIB
    dut = 'r2'
    next_hop = '10.0.0.1'
    input_dict = topo["routers"]
    result = verify_rib('ipv4', dut, tgen, input_dict, next_hop = next_hop)
    if result != True : assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    logger.info("Testcase " + tc_name + " :Passed \n")

    # Uncomment next line for debugging
    tgen.mininet_cli()


if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
