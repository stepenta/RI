# mPlane Protocol Reference Implementation
# tStat component code
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

"""
Implements tStat prototype for integration into 
the mPlane reference implementation.

"""

import threading
from datetime import datetime
from time import sleep
import mplane.model
import mplane.scheduler
import mplane.utils
import mplane.tstat_caps
from urllib3 import HTTPSConnectionPool
from urllib3 import HTTPConnectionPool
import argparse
import sys
import re

DEFAULT_IP4_NET = "192.168.4.0/24"
DEFAULT_SUPERVISOR_IP4 = '192.168.3.197'
DEFAULT_SUPERVISOR_PORT = 8888
REGISTRATION_PATH = "registration"
SPECIFICATION_PATH = "specification"
RESULT_PATH = "result"

class tStatService(mplane.scheduler.Service):
    def __init__(self, cap, fileconf):
        # verify the capability is acceptable
        mplane.tstat_caps.check_cap(cap)
        super(tStatService, self).__init__(cap)
        #self._logdir = logdir
        self._fileconf = fileconf

    def change_conf(self, cap_label, enable):
        newlines = []
        f = open(self._fileconf, 'r')
        for line in f:

            if (line[0] != '[' and line[0] != '#' and
                line[0] != '\n' and line[0] != ' '):    # discard useless lines
                param = line.split('#')[0]
                param_name = param.split(' = ')[0]
                
                if enable == True:
                    if (cap_label == "tstat-log_tcp_complete-core" and param_name == 'log_tcp_complete'):
                        newlines.append(line.replace('0', '1'))

                    # in order to activate optional sets, the basic set (log_tcp_complete) must be active too
                    elif (cap_label == "tstat-log_tcp_complete-end_to_end" and (
                        param_name == 'tcplog_end_to_end' 
                        or param_name == 'log_tcp_complete')):
                        newlines.append(line.replace('0', '1'))

                    elif (cap_label == "tstat-log_tcp_complete-tcp_options" and (
                        param_name == 'tcplog_options' or
                        param_name == 'log_tcp_complete')):
                        newlines.append(line.replace('0', '1'))

                    elif (cap_label == "tstat-log_tcp_complete-p2p_stats" and (
                        param_name == 'tcplog_p2p' or
                        param_name == 'log_tcp_complete')):
                        newlines.append(line.replace('0', '1'))

                    elif (cap_label == "tstat-log_tcp_complete-layer7" and (
                        param_name == 'tcplog_layer7' or
                        param_name == 'log_tcp_complete')):
                        newlines.append(line.replace('0', '1'))
                    else:
                        newlines.append(line)
                else:
                    if (cap_label == "tstat-log_tcp_complete-end_to_end" and param_name == 'tcplog_end_to_end'):
                        newlines.append(line.replace('1', '0'))

                    elif (cap_label == "tstat-log_tcp_complete-tcp_options" and param_name == 'tcplog_options'):
                        newlines.append(line.replace('1', '0'))

                    elif (cap_label == "tstat-log_tcp_complete-p2p_stats" and param_name == 'tcplog_p2p'):
                        newlines.append(line.replace('1', '0'))

                    elif (cap_label == "tstat-log_tcp_complete-layer7" and param_name == 'tcplog_layer7'):
                        newlines.append(line.replace('1', '0'))

                    else:
                        newlines.append(line) 
            else:
                newlines.append(line)
        f.close()
        
        f = open(self._fileconf, 'w')
        f.writelines(newlines)
        f.close
        
    def fill_res(self, spec, start, end):

        # derive a result from the specification
        res = mplane.model.Result(specification=spec)

        # put actual start and end time into result
        res.set_when(mplane.model.When(a = start, b = end))
        
        # fill result columns with DUMMY values
        for column_name in res.result_column_names():
            prim = res._resultcolumns[column_name].primitive_name()
            if prim == "natural":
                res.set_result_value(column_name, 0)
            elif prim == "string":
                res.set_result_value(column_name, "hello")
            elif prim == "real":
                res.set_result_value(column_name, 0.0)
            elif prim == "boolean":
                res.set_result_value(column_name, True)
            elif prim == "time":
                res.set_result_value(column_name, start)
            elif prim == "address":
                res.set_result_value(column_name, args.SUPERVISOR_IP4)
            elif prim == "url":
                res.set_result_value(column_name, "www.google.com")
        
        return res

    def run(self, spec, check_interrupt):
        start_time = datetime.utcnow()

        #change runtime.conf
        self.change_conf(spec._label, True)

        # wait for specification execution
        wait_time = spec._when.timer_delays()
        wait_seconds = wait_time[1]
        if wait_seconds != None:
            sleep(wait_seconds)
        end_time = datetime.utcnow()

        # fill result message from tStat log
        self.change_conf(spec._label, False)
        print("specification " + spec._label + ": start = " + str(start_time) + ", end = " + str(end_time))
        res = self.fill_res(spec, start_time, end_time)
        return res

def parse_args():
    global args
    parser = argparse.ArgumentParser(description='run a Tstat mPlane proxy')
    parser.add_argument('-n', '--net-address', metavar='net-address', default=DEFAULT_IP4_NET, dest='IP4_NET',
                        help='Subnet address/Netmask of this probe')
    parser.add_argument('-d', '--supervisor-ip4', metavar='supervisor-ip4', default=DEFAULT_SUPERVISOR_IP4, dest='SUPERVISOR_IP4',
                        help='Supervisor IP address')
    parser.add_argument('-p', '--supervisor-port', metavar='supervisor-port', default=DEFAULT_SUPERVISOR_PORT, dest='SUPERVISOR_PORT',
                        help='Supervisor port number')
    parser.add_argument('--disable-sec', action='store_true', default=False, dest='DISABLE_SEC',
                        help='Disable secure communication')
    parser.add_argument('-c', '--certfile', metavar="path", dest='CERTFILE', default = None,
                        help="Location of the configuration file for certificates")
    parser.add_argument('-T', '--tstat-runtimeconf', metavar = 'path', dest = 'TSTAT_RUNTIMECONF', required = True,
                        help = 'Tstat runtime.conf configuration file path')
    args = parser.parse_args()


    net_pattern = re.compile("^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}[/]\d{1,2}$")
    if not net_pattern.match(args.IP4_NET):
        print('\nERROR: Invalid network address format. The format must be: x.x.x.x/n\n')
        parser.print_help()
        sys.exit(1)
    else:
        slash = args.IP4_NET.find("/")
        if slash > 0:
            netmask = int(args.IP4_NET[slash+1:])
            if (netmask < 8 or netmask > 24):
                print('\nERROR: Invalid netmask. It must be a number between 8 and 24\n')
                parser.print_help()
                sys.exit(1)

    ip4_pattern = re.compile("^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$")
    if not ip4_pattern.match(args.SUPERVISOR_IP4):
        print('\nERROR: invalid Supervisor IP format \n')
        parser.print_help()
        sys.exit(1)

    args.SUPERVISOR_PORT = int(args.SUPERVISOR_PORT)
    if (args.SUPERVISOR_PORT <= 0 or args.SUPERVISOR_PORT > 65536):
        print('\nERROR: invalid port number \n')
        parser.print_help()
        sys.exit(1)
    
    if not args.TSTAT_RUNTIMECONF:
        print('\nERROR: missing -T|--tstat-runtimeconf\n')
        parser.print_help()
        sys.exit(1)

    if args.DISABLE_SEC == False and not args.CERTFILE:
        print('\nERROR: missing -C|--certfile\n')
        parser.print_help()
        sys.exit(1)

class HttpProbe():
    
    def __init__(self, immediate_ms = 5000):
        self.spec_path = "/" + SPECIFICATION_PATH
        parse_args()
        
        security = not args.DISABLE_SEC
        if security:
            mplane.utils.check_file(args.CERTFILE)
            cert = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "cert"))
            key = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "key"))
            ca = mplane.utils.normalize_path(mplane.utils.read_setting(args.CERTFILE, "ca-chain"))
            mplane.utils.check_file(cert)
            mplane.utils.check_file(key)
            mplane.utils.check_file(ca)
            self.pool = HTTPSConnectionPool(args.SUPERVISOR_IP4, args.SUPERVISOR_PORT, key_file=key, cert_file=cert, ca_certs=ca) 
            #self.user = "mPlane-Client"
        else: 
            self.pool = HTTPConnectionPool(args.SUPERVISOR_IP4, args.SUPERVISOR_PORT)
            #self.user = None
                
        self.immediate_ms = immediate_ms
        self.scheduler = mplane.scheduler.Scheduler() #(security)
        self.scheduler.add_service(tStatService(mplane.tstat_caps.tcp_flows_capability(args.IP4_NET), args.TSTAT_RUNTIMECONF))
        self.scheduler.add_service(tStatService(mplane.tstat_caps.e2e_tcp_flows_capability(args.IP4_NET), args.TSTAT_RUNTIMECONF))
        self.scheduler.add_service(tStatService(mplane.tstat_caps.tcp_options_capability(args.IP4_NET), args.TSTAT_RUNTIMECONF))
        self.scheduler.add_service(tStatService(mplane.tstat_caps.tcp_p2p_stats_capability(args.IP4_NET), args.TSTAT_RUNTIMECONF))
        self.scheduler.add_service(tStatService(mplane.tstat_caps.tcp_layer7_capability(args.IP4_NET), args.TSTAT_RUNTIMECONF))
          
    def register_to_supervisor(self):
        url = "/" + REGISTRATION_PATH
        caps_list = ""
        for key in self.scheduler.capability_keys():  
            cap = self.scheduler.capability_for_key(key)
            caps_list = caps_list + mplane.model.unparse_json(cap)
        connected = False
        while not connected:
            try:
                res = self.pool.urlopen('POST', url, 
                    body=caps_list.encode("utf-8"), 
                    headers={"content-type": "application/x-mplane+json"})
                connected = True
            except:
                print("Supervisor unreachable. Retrying connection in 5 seconds")
                sleep(5)
        if res.status == 200:
            print("Capabilities successfully registered:")
            for key in self.scheduler.capability_keys():  
                cap = self.scheduler.capability_for_key(key)
                print("    " + cap.get_label())
        else:
            print("Error registering capabilities, Supervisor said: " + str(res.status) + " - " + res.data.decode("utf-8"))
            exit(1)
            
    
    def return_results(self, job):
        url = "/" + RESULT_PATH
        reply = job.get_reply()
        while job.finished() is not True:
            if job.failed():
                reply = job.get_reply()
                break
            sleep(1)
        if isinstance (reply, mplane.model.Receipt):
            reply = job.get_reply()
            
        res = self.pool.urlopen('POST', url, 
                body=mplane.model.unparse_json(reply).encode("utf-8"), 
                headers={"content-type": "application/x-mplane+json"})
        if res.status == 200:
            print("Result for " + reply.get_label() + " successfully returned!")
        else:
            print("Error returning Result for " + reply.get_label())
            print("Supervisor said: " + str(res.status) + " - " + res.data.decode("utf-8"))
        pass
    
    def check_for_specs(self):
        for token in self.scheduler.capability_keys():
            res = self.pool.request('GET', self.spec_path)
            if res.status == 200:
                specs = self.split_specs(res.data.decode("utf-8"))
                for spec in specs:
                    msg = mplane.model.parse_json(spec)
        
                    # hand message to scheduler
                    reply = self.scheduler.receive_message(msg) # (self.user, msg)
                    job = self.scheduler.job_for_message(reply)
                    t = threading.Thread(target=self.return_results, args=[job])
                    t.start()
        pass
    
    def split_specs(self, msg):
        specs = []
        spec_start = 0
        spec_end = msg.find('}', spec_start)
        while spec_end != -1:
            specs.append(msg[spec_start:spec_end+1])
            spec_start = spec_end + 1
            spec_end = msg.find('}', spec_start)
        return specs

if __name__ == "__main__":
    mplane.model.initialize_registry()
    probe = HttpProbe()
    probe.register_to_supervisor()
    
    print("Checking for Specifications...")
    while(True):
        probe.check_for_specs()
        sleep(5)