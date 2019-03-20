#### FRRouting Topology Tests with Mininet

### Overview

On top of current topotests framework following enhancements are done: 

1. Creating the topology and assigning IPs to router' interfaces dynamically.  
It is achieved by using json file, in which user specify the number of routers, 
links to each router, interfaces for the routers and protocol configurations for 
all routers. 

2. Creating the configurations dynamically.  It is achieved by using 
/usr/lib/frr/frr-reload.py utility, which takes running configuration and the 
newly created configuration for any particular router and creates a delta 
file(diff file) and loads it to  router.


### Required packages for running tests

pip install ipaddress
pip install mininet
pip install pytest (tested with pytest version == 3.6.3)
pip install json
pip install errno
pip install traceback
pip install StringIO
pip install ConfigParser

### Logging of test case executions

1. User can enable logging of testcases execution messages into log file by 
adding "frrtest_log_dir = /tmp/topotests/" in pytest.ini file
2. Router's current configuration can be displyed on console or sent to logs by 
adding "show_router_config = True" in pytest.ini file 

```
pytest.ini`:

[topogen]
### By default logs will be displayed to console, enable the below line to save 
execution logs to log file
frrtest_log_dir = /tmp/topotests/
show_router_config = True
```

Log file name will be displayed when we start execution:
root@test:~/topotests/example-topojson-test/test_topo_json_single_link# python 
test_topo_json_single_link.py Logs will be sent to logfile: 
/tmp/topotests/test_topo_json_single_link_11:57:01.353797

# Note: directory "/tmp/topotests/" is created by topotests by default, making 
# use of same directory to save execution logs. 


### example-topojson-test

1. test_topo_json_single_link: This example is to create topology of routers 
having single link in-between.
2. test_topo_json_multiple_links: This example is to create topology of routers 
having multiple links in-between. Only one links is been used to create bgp 
neighborship.

- test_topo_json_single_link.py : code to call APIs, to create topology and 
  configurations and verify bgp convergence once configuration is build and test 
static routes functionality..
- test_topo_json_single_link.json : input JSON file, where user will defined 
  topology and configguration in pre-defined format as explained in 
GUIDELINCE.md file.
 
