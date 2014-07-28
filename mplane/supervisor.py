# mPlane Protocol Reference Implementation
# Simple mPlane Supervisor and CLI (JSON over HTTP)
#
# (c) 2013-2014 mPlane Consortium (http://www.ict-mplane.eu)
#               Author: Stefano Pentassuglia
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#

from threading import Thread
import mplane.model
import mplane.utils
import mplane.sec
import mplane.sv_handlers
import ssl
import sys
import cmd
import copy
import math
from collections import OrderedDict
import tornado.web
import tornado.httpserver
import argparse
DEFAULT_LISTEN_PORT = 8888
DEFAULT_LISTEN_IP4 = '192.168.3.197'

REGISTRATION_PATH = "registration"
SPECIFICATION_PATH = "specification"
RESULT_PATH = "result"
S_CAPABILITY_PATH = "s_capability"
S_AGGREGATED_CAPABILITY_PATH = "s_aggregated_capability"
S_SPECIFICATION_PATH = "s_specification"
S_RESULT_PATH = "s_result"

"""
Generic mPlane Supervisor for cap-push, spec-pull workflows.
Actually it is an HTTP server

"""
    
def parse_args():
    global args
    parser = argparse.ArgumentParser(description="run mPlane Supervisor")

    parser.add_argument('-p', '--listen-port', metavar='port', dest='LISTEN_PORT', default=DEFAULT_LISTEN_PORT, type=int, \
                        help = 'run the service on the specified port [default=%d]' % DEFAULT_LISTEN_PORT)
    parser.add_argument('-H', '--listen-ipaddr', metavar='ip', dest='LISTEN_IP4', default=DEFAULT_LISTEN_IP4, \
                        help = 'run the service on the specified IP address [default=%s]' % DEFAULT_LISTEN_IP4)

    parser.add_argument('--disable-sec', action='store_true', default=False, dest='DISABLE_SEC',
                        help='Disable secure communication')
    parser.add_argument('-c', '--certfile', metavar="path", default=None, dest='CERTFILE',
                        help="Location of the configuration file for certificates")
    args = parser.parse_args()

    if args.DISABLE_SEC == False and not args.CERTFILE:
        print('\nerror: missing -c|--certfile option\n')
        parser.print_help()
        sys.exit(1)
        #raise ValueError("Need --logdir and --fileconf as parameters")

def listen_in_background():
    tornado.ioloop.IOLoop.instance().start()

def get_net_info(cap):
    # retrieve subnet mask and ip from the parameters in the capability
    params = [v._as_tuple() for v in cap._params.values()]
    subnet_ip4 = None
    subnet_mask = None
    for param in params:
        if param[0] == 'subnet.ip4':
            subnet_ip4 = param[1]
        elif param[0] == 'subnet.netmask':
            subnet_mask = int(param[1])
    if (subnet_ip4 is None or subnet_mask is None):
        print("Missing subnet.ip4 or subnet.netmask parameters")
        return None
    else:
        return [subnet_ip4, subnet_mask]
        
class AggregatedCapability(object):
    
    def __init__(self, cap, dn_list, interval, netmask, dn_to_nets):
        self.dn_list = dn_list
        self.dn_to_nets = dn_to_nets
        self.net_interval = interval
        self.netmask = netmask
        
        cap.remove_parameter("subnet.ip4")
        cap.add_parameter("aggregate.ip4", interval[0] + " ... " + interval[1])
        self.schema = cap
        
    def aggregate_cap(self, dn, ip4, mask):
        self.dn_list.append(dn)
        if math.fabs(mplane.utils.get_distance(self.net_interval[0], self.netmask, ip4, mask)) == 1:
            self.net_interval[0] = ip4
        elif math.fabs(mplane.utils.get_distance(self.net_interval[1], self.netmask, ip4, mask)) == 1:
            self.net_interval[1] = ip4
        else:
            print("Error: new capability should be adjacent, but is not!")
            
    def further_aggregate(self, aggr_cap):
        self.dn_list.append(aggr_cap.dn_list)
        if math.fabs(mplane.utils.get_distance(self.net_interval[0], self.netmask, aggr_cap.net_interval[1], aggr_cap.netmask)) == 1:
            self.net_interval[0] = aggr_cap.net_interval[0]
        elif math.fabs(mplane.utils.get_distance(self.net_interval[1], self.netmask, aggr_cap.net_interval[0], aggr_cap.netmask)) == 1:
            self.net_interval[1] = aggr_cap.net_interval[1]

    def is_adjacent(self, other_ip4, other_mask):
        if self.netmask == other_mask:
            if (math.fabs(mplane.utils.get_distance(self.net_interval[0], self.netmask, other_ip4, other_mask)) == 1 or
                math.fabs(mplane.utils.get_distance(self.net_interval[1], self.netmask, other_ip4, other_mask)) == -1):
                return True
            else:
                return False
        else:
            return False

class HttpSupervisor(object):
    """
    Implements an mPlane HTTP supervisor endpoint for component-push workflows. 
    This supervisor endpoint can register capabilities sent by components, then expose 
    Specifications for which the component will periodically check, and receive Results or Receipts

    Caches retrieved Capabilities, Receipts, and Results.

    """
    def __init__(self):
        parse_args()
                
        application = tornado.web.Application([
                (r"/" + REGISTRATION_PATH, mplane.sv_handlers.RegistrationHandler, {'supervisor': self}),
                (r"/" + SPECIFICATION_PATH, mplane.sv_handlers.SpecificationHandler, {'supervisor': self}),
                (r"/" + RESULT_PATH, mplane.sv_handlers.ResultHandler, {'supervisor': self}),
                (r"/" + S_CAPABILITY_PATH, mplane.sv_handlers.S_CapabilityHandler, {'supervisor': self}),
                (r"/" + S_CAPABILITY_PATH + "/.*", mplane.sv_handlers.S_CapabilityHandler, {'supervisor': self}),
                (r"/" + S_SPECIFICATION_PATH, mplane.sv_handlers.S_SpecificationHandler, {'supervisor': self}),
                (r"/" + S_RESULT_PATH, mplane.sv_handlers.S_ResultHandler, {'supervisor': self}),
            ])
        self._sec = not args.DISABLE_SEC    
        if self._sec == True:
            self.ac = mplane.sec.Authorization(self._sec)
            self.base_url = "https://" + args.LISTEN_IP4 + ":" + str(args.LISTEN_PORT) + "/"
            cert = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "cert"))
            key = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "key"))
            ca = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "ca-chain"))
            mplane.utils.check_file(cert)
            mplane.utils.check_file(key)
            mplane.utils.check_file(ca)
            http_server = tornado.httpserver.HTTPServer(application, ssl_options=dict(certfile=cert, keyfile=key, cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca))
        else:
            self.base_url = "http://" + args.LISTEN_IP4 + ":" + str(args.LISTEN_PORT) + "/"
            http_server = tornado.httpserver.HTTPServer(application)
            
        http_server.listen(args.LISTEN_PORT, args.LISTEN_IP4)
        t = Thread(target=listen_in_background)
        t.start()

        print("new Supervisor: "+str(args.LISTEN_IP4)+":"+str(args.LISTEN_PORT))

        # empty capability and measurement lists
        self._capabilities = OrderedDict()
        self._aggregated_caps = []
        self._single_in_aggr = OrderedDict()
        self._specifications = OrderedDict()
        self._receipts = OrderedDict()
        self._results = OrderedDict()
        self._aggregated_meas = dict()
        self._dn_to_ip = dict()
        self._info_by_label = dict()
        
    def register(self, cap, dn):
        net_info = get_net_info(cap)
        if net_info is not None:
            subnet_ip4 = net_info[0]
            subnet_mask = net_info[1]
        else:  
            label = cap.get_label()
            if label not in self._info_by_label:
                self._info_by_label[label] = [[dn, subnet_ip4, subnet_mask]]
            else:
                self._info_by_label[label].append([dn, subnet_ip4, subnet_mask])
            if dn not in self._capabilities:
                self._capabilities[dn] = [cap]
            else:
                self._capabilities[dn].append(cap)
            return
                
        aggregation_success = False
        for aggr_cap in self._aggregated_caps:
            if (aggr_cap.is_adjacent(subnet_ip4, subnet_mask) and aggr_cap.schema.get_label() == cap.get_label()):
                aggr_cap.aggregate_cap(dn, subnet_ip4, subnet_mask)
                print("registering")
                if dn not in self._single_in_aggr:
                    self._single_in_aggr[dn] = [cap]
                else:
                    self._single_in_aggr[dn].append(cap)
                self.check_single_caps(aggr_cap)
                self.check_aggregated_caps(aggr_cap)
                aggregation_success = True
                break
        if aggregation_success is False:
            for check_dn in self._capabilities:
                for single_cap in self._capabilities[check_dn]:
                    if single_cap.get_label() == cap.get_label():
                        net_info = get_net_info(single_cap)
                        if net_info is not None:
                            check_ip4 = net_info[0]
                            check_mask = net_info[1]
                        else:
                            break
                        dn_to_nets = dict()
                        dn_to_nets[dn] = subnet_ip4
                        dn_to_nets[check_dn] = check_ip4
                        if mplane.utils.get_distance(subnet_ip4, subnet_mask, check_ip4, check_mask) == 1:
                            new_aggr = AggregatedCapability(cap, [dn, check_dn], [subnet_ip4, check_ip4], subnet_mask, dn_to_nets)
                            aggregation_success = True
                        elif mplane.utils.get_distance(subnet_ip4, subnet_mask, check_ip4, check_mask) == -1:
                            new_aggr = AggregatedCapability(cap, [dn, check_dn], [check_ip4, subnet_ip4], subnet_mask, dn_to_nets)
                            aggregation_success = True
                            
                        if aggregation_success is True:
                            self._aggregated_caps.append(new_aggr)
                            if check_dn not in self._single_in_aggr:
                                self._single_in_aggr[check_dn] = [single_cap]
                            else:
                                self._single_in_aggr[check_dn].append(single_cap)
                            if dn not in self._single_in_aggr:
                                self._single_in_aggr[dn] = [cap]
                            else:
                                self._single_in_aggr[dn].append(cap)
                            self._capabilities[check_dn].remove(single_cap)
                            break
                if aggregation_success is True:
                    self.check_single_caps(new_aggr)
                    self.check_aggregated_caps(new_aggr)
                    break
        if aggregation_success is False:
            if dn not in self._capabilities:
                self._capabilities[dn] = [cap]
            else:
                self._capabilities[dn].append(cap)

    def check_single_caps(self, aggr_cap):
        to_be_removed = []
        for dn in self._capabilities:
            for cap in self._capabilities[dn]:
                if cap.get_label() == aggr_cap.schema.get_label():
                    net_info = get_net_info(cap)
                    if net_info is not None:
                        ip4 = net_info[0]
                        mask = net_info[1]
                    else:
                        break
                    if aggr_cap.is_adjacent(ip4, mask):
                        aggr_cap.aggregate_cap(dn, ip4, mask)
                        to_be_removed.append([dn, cap])
        for dn, cap in to_be_removed:
            if dn not in self._single_in_aggr:
                self._single_in_aggr[dn] = [cap]
            else:
                self._single_in_aggr[dn].append(cap)
            self._capabilities[dn].remove(cap)
    
    def check_aggregated_caps(self, aggr_cap):
        to_be_removed = []
        for cap in self._aggregated_caps:
            if (cap.schema.get_label() == aggr_cap.schema.get_label() and 
                cap.net_interval[0] != aggr_cap.net_interval[0]):
                if aggr_cap.is_adjacent(cap.net_interval[0], cap.netmask):
                    aggr_cap.further_aggregate(cap)
                    to_be_removed.append(cap)
                elif aggr_cap.is_adjacent(cap.net_interval[1], cap.netmask):
                    aggr_cap.further_aggregate(cap)
                    to_be_removed.append(cap)
        for cap in to_be_removed:
            self._aggregated_caps.remove(cap)
    
    def add_result(self, msg, dn):
        """Add a result. Check for duplicates and if result is expected."""
        if dn in self._receipts:
            for receipt in self._receipts[dn]:
                if str(receipt.get_token()) == str(msg.get_token()):
                    if dn not in self._results:
                        self._results[dn] = [msg]
                    else:
                        for result in self._results[dn]:
                            if str(result.get_token()) == str(msg.get_token):
                                print("WARNING: Duplicated result received!")
                                return False
                        self._results[dn].append(msg)
                    
                    self._receipts[dn].remove(receipt)
                    return True
                
        print("WARNING: Received an unexpected Result!")
        return False
        
    def add_spec(self, spec, dn):
        if dn not in self._specifications:
            if dn in self._receipts:
                for rec in self._receipts[dn]:
                    if str(rec.get_token()) == str(spec.get_token()):
                        print("There is already a Measurement running for this Capability. Try again later")
                        return False
            self._specifications[dn] = [spec]
            return True
        else:
            # Check for concurrent specifications
            for prev_spec in self._specifications[dn]:
                if spec.fulfills(prev_spec):
                    print("There is already a Specification for this Capability. Try again later")
                    return False
            self._specifications[dn].append(spec)
            return True
            
    def dn_from_ip(self, ip):
        for dn in self._dn_to_ip:
            if ip == self._dn_to_ip[dn]:
                return dn

    def measurements(self):
        """Iterate over all measurements (receipts and results)"""
        measurements = OrderedDict()
        
        for dn in self._specifications:
            if dn not in measurements:
                measurements[dn] = copy.deepcopy(self._specifications[dn])
            else:
                for spec in self._specifications[dn]:
                    measurements[dn].append(spec)
        
        for dn in self._receipts:
            if dn not in measurements:
                measurements[dn] = copy.deepcopy(self._receipts[dn])
            else:
                for receipt in self._receipts[dn]:
                    measurements[dn].append(receipt)
                
        for dn in self._results:
            if dn not in measurements:
                measurements[dn] = copy.deepcopy(self._results[dn])
            else:
                for result in self._results[dn]:
                    measurements[dn].append(result)
                
        return measurements

    def _handle_exception(self, exc):
        print(repr(exc))

class SupervisorShell(cmd.Cmd):

    intro = 'Welcome to the mPlane Supervisor shell.   Type help or ? to list commands.\n'
    prompt = '|mplane| '

    def preloop(self):
        self._supervisor = HttpSupervisor()
        self._defaults = {}
        self._when = None

    def do_listcap(self, arg):
        """List available capabilities by index"""
        i = 1
        for key in self._supervisor._capabilities:
            for cap in self._supervisor._capabilities[key]:
                print(str(i) + " - " + cap.get_label() + " from " + self._supervisor._dn_to_ip[key])
                i = i + 1
                
        for cap in self._supervisor._aggregated_caps:
            print(str(i) + " - " + cap.schema.get_label() + " from:")
            for dn in cap.dn_list:
                print("        " + self._supervisor._dn_to_ip[dn])
            i = i + 1

    def do_showcap(self, arg):
        """
        Show a capability given a capability index; 
        without an index, shows all capabilities

        """
        if len(arg) > 0:
            i = 1
            for key in self._supervisor._capabilities:
                for cap in self._supervisor._capabilities[key]:
                    if str(i) == arg:
                        self._show_stmt(cap)
                        return
                    i = i + 1
            for cap in self._supervisor._aggregated_caps:
                if str(i) == arg:
                    self._show_stmt(cap.schema)
                    ips = ""
                    for dn in cap.dn_list:
                        if ips == "":
                            ips = self._supervisor._dn_to_ip[dn]
                        else:
                            ips = ips + ", " + self._supervisor._dn_to_ip[dn]
                    print("from: " + ips + "\n")
                    return
                i = i + 1
            print("No such capability: " + arg)
            
        else:
            for key in self._supervisor._capabilities:
                for cap in self._supervisor._capabilities[key]:
                    self._show_stmt(cap)
            for cap in self._supervisor._aggregated_caps:
                self._show_stmt(cap.schema)
                ips = ""
                for dn in cap.dn_list:
                    if ips == "":
                        ips = self._supervisor._dn_to_ip[dn]
                    else:
                        ips = ips + ", " + self._supervisor._dn_to_ip[dn]
                print("from: " + ips + "\n")

    def do_listmeas(self, arg):
        """List running/completed measurements by index"""
        i = 1
        meas = self._supervisor.measurements()
        for dn in meas:
            for m in meas[dn]:
                print(str(i) + " - " + repr(m))
                i = i + 1

    def do_showmeas(self, arg):
        """Show receipt/results for a measurement, given a measurement index"""
        meas = self._supervisor.measurements()
        if len(arg) > 0:
            i = 1
            for dn in meas:
                for m in meas[dn]:
                    if str(i) == arg:
                        self._show_stmt(m)
                        return
                    i = i + 1
            print("No such measurement: " + arg)
        else:
            for dn in meas:
                for m in meas[dn]:
                    self._show_stmt(m)

    def _show_stmt(self, stmt):
        print(mplane.model.unparse_yaml(stmt))

    def do_runcap(self, arg):
        """
        Run a capability given an index, filling in temporal 
        scope and defaults for parameters. Prompts for parameters 
        not yet entered.

        """
        # Retrieve a capability and create a specification
        i = 1
        for key in self._supervisor._capabilities:
            for cap in self._supervisor._capabilities[key]:
                if str(i) == arg:
                    self.schedule_spec(cap, key)
                    return
                i = i + 1
        for cap in self._supervisor._aggregated_caps:
            if str(i) == arg:
                #ip_list = self._supervisor._aggregated_caps[label].ip_to_string(self._supervisor._dn_to_ip)
                #self._supervisor._aggregated_caps[label].schema.add_parameter("list.ip4", ip_list)
                self._show_stmt(cap.schema)
                return
            i = i + 1
        print("No such capability: " + arg)
            
    def schedule_spec(self, cap, dn):
        spec = mplane.model.Specification(capability=cap)
        
        # Set temporal scope or prompt for new one  
        while self._when is None or \
              not self._when.follows(cap.when()) or \
              (self._when.period is None and cap.when().period() is not None):
            sys.stdout.write("|when| = ")
            self._when = mplane.model.When(input())

        spec.set_when(self._when)

        # Fill in single values
        spec.set_single_values()

        # Fill in parameter values
        for pname in spec.parameter_names():
            if spec.get_parameter_value(pname) is None:
                if pname in self._defaults:
                    # set parameter value from defaults
                    print("|param| "+pname+" = "+self._defaults[pname])
                    spec.set_parameter_value(pname, self._defaults[pname])
                else:
                    # set parameter value with input
                    sys.stdout.write("|param| "+pname+" = ")
                    spec.set_parameter_value(pname, input())
            else:
                # FIXME we really want to unparse this
                print("|param| "+pname+" = "+str(spec.get_parameter_value(pname)))

        # Validate specification
        spec.validate()

        # And send it to the server
        self._supervisor.add_spec(spec, dn)
        
    def do_show(self, arg):
        """Show a default parameter value, or all values if no parameter name given"""
        if len(arg) > 0:
            try:
                key = arg.split()[0]
                val = self._defaults[key]
                print(key + " = " + val)
            except:
                print("No such default "+key)
        else:
            print("%4u defaults" % len(self._defaults))
            for key, val in self._defaults.items():
                print(key + " = " + val)

    def do_set(self, arg):
        """Set a default parameter value"""
        try:
            sarg = arg.split()
            key = sarg.pop(0)
            val = " ".join(sarg)
            self._defaults[key] = val
            print(key + " = " + val)
        except:
            print("Couldn't set default "+arg)

    def do_when(self, arg):
        """Set a default temporal scope"""
        if len(arg) > 0:
            try:
                self._when = mplane.model.When(arg)
            except:
                print("Invalid temporal scope "+arg)
        else:
            print("when = "+str(self._when))

    def do_unset(self, arg):
        """Unset a default parameter value"""
        try:
            keys = arg.split()
            for key in keys:
                del self._defaults[key]
        except:
            print("Couldn't unset default(s) "+arg)
    
if __name__ == "__main__":
    mplane.model.initialize_registry()
    SupervisorShell().cmdloop()