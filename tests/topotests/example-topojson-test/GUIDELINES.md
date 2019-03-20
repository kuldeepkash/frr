#### Guidelines

This document describes how to make use of newly added libraries to topotests..


### Executing Tests
To run the whole suite of tests the following commands to be executed at the top 
level directory of topotest:

```shell
$ # Change to the top level directory of topotests.
$ cd path/to/topotests
$ # Tests must be run as root, since Mininet requires it.
$ sudo pytest
```

In order to run a specific test, you can use the following command:

```shell
$ # running a specific topology
$ sudo pytest example-topojson-test/
$ # or inside the test folder
$ cd example-topojson-test
$ sudo pytest # to run all tests inside the directory
$ sudo pytest test_bgp_convergence_.py # to run a specific test
$ # or outside the test folder
$ cd ..
$ sudo pytest example-topojson-test/test_example_topojson.py # to run a specific 
testsuite
```

### File Hierarchy
Before starting to write any tests one must know the file hierarchy. The 
repository hierarchy looks like this:

```shell
$ cd path/to/topotests
$ find ./*
...
./README.md  # repository read me
./conftest.py # test hooks - pytest related functions

...
./example-topojson-test  # the basic example test topology-1
./example-topojson-test/test_example_topojson.json # input json file, having 
topology, interfaces, bgp and other configuration
./example-topojson-test/test_example_topojson.py # test script to write and 
execute testcases
...
./lib # shared test/topology functions
./lib/topojson.py # library to create topology and configurations dynamically 
from json file
./lib/common.py # library to create protocol's common configurations ex- 
static_routes, prefix_lists, route_maps etc.
./lib/bgp.py # library to create only bgp configurations
 
```

### Defining the Topology and initial configuration in JSON file
The first step to write a new test is to define the topology and initial 
configuration. User has to define topology and initial configuration in JSON 
file. Here is an example of JSON file. 


```shell

Single link between routers, sample JSON file:
{
"ipv4base": "10.0.0.0",
"ipv4mask": 30,
"ipv6base": "fd00::",
"ipv6mask": 64,
"link_ip_start": {"ipv4": "10.0.0.0", "v4mask": 30, "ipv6": "fd00::", "v6mask": 
64},
"lo_prefix": {"ipv4": "1.0.", "v4mask": 32, "ipv6": "2001:DB8:F::", "v6mask": 
128},
"routers":
{
    "r1": {
	"lo": {"ipv4": "auto", "ipv6": "auto"},
	"links": {
		"r2": {"ipv4": "auto", "ipv6": "auto"}
	},
	"router-id": "11.11.11.11",
	"bgp": {
		"as_number": "100",
		"enabled": true,
		"ecmpenabled": true,
		"bgp_neighbors": {
		    "r2": {
			"keepalivetimer": 60,
			"holddowntimer": 180,
			"remoteas": "100",
			"peer": {
			    "link": "r1",
			    "addr_type": "ipv4"
			}
		    }
		}
		"gracefulrestart":true
	}
    },
    "r2": {
	"lo": { "ipv4": "auto", "ipv6": "auto"},
	"links": {
		"r1": {"ipv4": "auto", "ipv6": "auto"}
	},
	"bgp": {
		"as_number": "100",
		"enabled": true,
		"ecmpenabled": true,
		"bgp_neighbors": {
		    "r1": {
			"keepalivetimer": 60,
			"holddowntimer": 180,
			"remoteas": "100",
			"peer": {
			    "link": "r2",
			    "addr_type": "ipv4"
			}
		    }
		},
		"gracefulrestart":true
	 }
     }
    ...

Multiple link between routers, sample JSON file:
"ipv4base": "10.0.0.0",
"ipv4mask": 30,
"ipv6base": "fd00::",
"ipv6mask": 64,
"link_ip_start": {"ipv4": "10.0.0.0", "v4mask": 30, "ipv6": "fd00::", "v6mask": 
64},
"lo_prefix": {"ipv4": "1.0.", "v4mask": 32, "ipv6": "2001:DB8:F::", "v6mask": 
128},
"routers":
{
    "r1": {
	"lo": {"ipv4": "auto", "ipv6": "auto"},
	"links": {
		"r2-link1": {"ipv4": "auto", "ipv6": "auto"},
		"r2-link2": {"ipv4": "auto", "ipv6": "auto"}
	},
	"bgp": {
		"as_number": "100",
		"enabled": true,
		"ecmpenabled": true,
		"bgp_neighbors": {
		    "r2": {
			"keepalivetimer": 60,
			"holddowntimer": 180,
			"remoteas": "100",
			"peer": {
			    "link": "r1-link1",
			    "addr_type": "ipv4"
			}
		    }
		},
		"gracefulrestart":true
	},
	"static_routes": [{"network": "10.0.20.1/32", "no_of_ip": 9, 
"admin_distance": 100, "next_hop": "10.0.0.1", "tag": 4001}],
	"redistribute": {
		  "static": true,
		  "connected": true
	},
	"prefix_lists": {
	       "pf_list_1": [{"seqid": 10, "network": "10.10.0.1/32", "action": 
"deny"},
			     {"seqid": 11, "network": "any", "action": 
"permit"}]
	}
    },

    "r2": {
	"lo": { "ipv4": "auto", "ipv6": "auto"},
	"links": {
		"r1-link1": {"ipv4": "auto", "ipv6": "auto"},
		"r1-link2": {"ipv4": "auto", "ipv6": "auto"}
	},
	"bgp": {
		"as_number": "100",
		"enabled": true,
		"ecmpenabled": true,
		"bgp_neighbors": {
		    "r1": {
			"keepalivetimer": 60,
			"holddowntimer": 180,
			"remoteas": "100",
			"peer": {
			    "link": "r2-link1",
			    "addr_type": "ipv4"
			}
		    }

		},
		"gracefulrestart":true
	 }
    }
    ...

```

## JSON file explained

- "ipv4base" : base ipv4 address to generate ips,  ex - 10.0.0.0
- "ipv4mask" : mask for ipv4 address, which will help to generates ips, ex - 30
- "ipv6base" : base ipv6 address to generate ips,  ex - fd00::
- "ipv6mask" : mask for ipv6 address, which will help to generates ips, ex - 64
- "link_ip_start" : physical interface base ipv4 and ipv6 address
- "lo_prefix" : loopback interface base ipv4 and ipv6 address
- "routers"   : user can add number of routers as per topology, router's name 
  can be any logical name, ex- r1 or a0. 
- "r1" : router1 
- "lo" : loopback interface, can have ipv4 and ipv6 address dynamically 
- "links" : physical interface, can have ipv4 and ipv6 address dynamically
- "r2-link1" : physical interface link name between routers, link name can be 
  any logical name but seperated by hyphen ("-"), ex- a0-peer1
- "router-id" : router-id
- "bgp" : bgp configuration
- "label" : label is used to established bgp neighborship, label will be matched 
  with link name
- "addr_type" : address type, which will be used to create bgp configuration, 
  ex- ipv4/ipv6


### Building topology and configurations

Topology and initial configuration will be created in setup_module(). Following 
is the sample code:


```
class BGPBasicTopo(Topo):
    def build(self, *_args, **_opts):
	"Build function"
	tgen = get_topogen(self)

	# Building topology from json file
	build_topo_from_json(tgen, topo)

def setup_module(mod):
    tgen = Topogen(BGPBasicTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
	try:
	    os.chdir(CWD)
	    # Deleting router named dirs if exists
	    if os.path.exists('{}'.format(rname)):
		os.system("rm -rf {}".format(rname))

	    # Creating rouer named dir and emoty zebra.conf bgpd.conf files 
	    # inside the current directory    
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

def teardown_module(mod):
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

```

- Note: Topology will  be created in setup module but routers will not be 
  started until we load zebra.conf and bgpd.conf to routers. For all routers 
  folder will be created in current working directory and under router's folder 
  zebra.conf and bgpd.conf empty file will be created and laoded to routers. All 
  folder and files are deleted in teardown module.. 


### Creating configuration files

Router's configuration would be saved in config files accordingly, all common 
configurations are saved in frr.conf file whereas all bgp configurations are 
saved in bgp.conf file. Common configurations are like, static routes, prefix 
lists and route maps etc configs, these configs can be used by any other 
protocols as it is. BGP config will be specific to BGP protocol testing.

Example: creation of bgp configuration:

Following code snippet taken from bgp.py file:

# RoutingPB class is made for backup purpose, suppose user creates BGP config, 
# first config will be stored into FRRConfig.routingPB.bgp_config then it will be 
# saved to FRRConfig. Use of keeping data in RoutingPB class is, if FRRConfig is 
# reset for any router then the configuration can be retained back from RoutingPB 
# class variables.

class BGPRoutingPB:

    def __init__(self, router_id):
	self.bgp_config = None
	self.routing_global = {'router_id': router_id}
	self.community_list = []

## FRRConfig class is used to save all config FRRConfig variables and these 
variable data is read and printed to frr.conf file.
class BGPConfig:

    def __init__(self, router, routing_cfg_msg, frrcfg_file):
	self.router = router
	self.routing_pb = routing_cfg_msg
	self.errors = []
	self.bgp_global = get_StringIO()
	self.bgp_neighbors = get_StringIO()
	self.bgp_address_family = {}
	self.bgp_address_family[IPv4_UNICAST] = get_StringIO()
	self.bgp_address_family[IPv6_UNICAST] = get_StringIO()
	self.bgp_address_family[VPNv4_UNICAST] = get_StringIO()
	self.community_list = get_StringIO()
	self._community_list_regex_index = 0
	self.bgpcfg_file = bgpcfg_file

- Once configurations are saved in BGPRoutingPB and BGPConfig, all configs will 
  be read from these class variables and print to file. API used 
  print_bgp_config_to_file() from bgp.py
- Once configurations are printed to files, it will be loaded to the router with 
  the help of frr "reload.py" utility, which calculates the difference between 
  router's running config and user's config and loads delta file to router. API 
  used - load_config_to_router() from config.py


### Writing Tests

Test topologies should always be bootstrapped from the 
example-test/test_example.py, because it contains important boilerplate code 
that can't be avoided, like:

imports: os, sys, pytest, topotest/topogen and mininet topology class

The global variable CWD (Current Working directory): which is most likely going 
to be used to reference the routers configuration file location

Example:

- For all registered routers, load the zebra configuration file

```
    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
	try:
	    os.chdir(CWD)
	    # Deleting router named dirs if exists
	    if os.path.exists('{}'.format(rname)):
		os.system("rm -rf {}".format(rname))

	    # Creating rouer named dir and emoty zebra.conf bgpd.conf files 
	    # inside the current directory    
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

```

- The topology class that inherits from Mininet Topo class

```
class TemplateTopo(Topo):
  def build(self, *_args, **_opts):
    tgen = get_topogen(self)
    # topology build code
```

- pytest setup_module() and teardown_module() to start the topology
```
def setup_module(_m):
    tgen = Topogen(TemplateTopo)
    tgen.start_topology('debug')

def teardown_module(_m):
    tgen = get_topogen()
    tgen.stop_topology()
```

- __main__ initialization code (to support running the script directly)
```
if __name__ == '__main__':
    sys.exit(pytest.main(["-s"]))
```

## Requirements:

- Test code should always be declared inside functions that begin with the test_ 
  prefix. Functions beginning with different prefixes will not be run by pytest.
- Configuration files and long output commands should go into separated files 
  inside folders named after the equipment.
- Tests must be able to run without any interaction. To make sure your test 
  conforms with this, run it without the -s parameter.
- All bgp configuration creation/modification/verification changes should go to 
  bgp.py
- Common configuration creation/modification/verification changes should go to 
  common_config.py


###  TODO:
1. Enhance generate_ips() API  to generate ips for any mask given.
2. Add support for multiple loopback addresses.

