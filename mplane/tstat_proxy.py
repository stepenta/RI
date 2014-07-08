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

SUPERVISOR_IP4 = 'mplane.org'
SUPERVISOR_PORT = 8888
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
    parser.add_argument('--disable-sec', action='store_true', default=False, dest='DISABLE_SEC',
                        help='Disable secure communication')
    parser.add_argument('-c', '--certfile', metavar="path", dest='CERTFILE', default = None,
                        help="Location of the configuration file for certificates")
    parser.add_argument('-T', '--tstat-runtimeconf', metavar = 'path', dest = 'TSTAT_RUNTIMECONF', required = True,
                        help = 'Tstat runtime.conf configuration file path')
    args = parser.parse_args()

    if not args.TSTAT_RUNTIMECONF:
        print('error: missing -T|--tstat-runtimeconf\n')
        parser.print_help()
        sys.exit(1)

    if args.DISABLE_SEC == False and not args.CERTFILE:
        print('error: missing -C|--certfile\n')
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
            self.pool = HTTPSConnectionPool(SUPERVISOR_IP4, SUPERVISOR_PORT, key_file=key, cert_file=cert, ca_certs=ca) 
            self.user = "mPlane-Client"
        else: 
            self.pool = HTTPConnectionPool(SUPERVISOR_IP4, SUPERVISOR_PORT)
            self.user = None
                
        self.immediate_ms = immediate_ms
        self.scheduler = mplane.scheduler.Scheduler() #(security)
        self.scheduler.add_service(tStatService(mplane.tstat_caps.tcp_flows_capability(), args.TSTAT_RUNTIMECONF))
        self.scheduler.add_service(tStatService(mplane.tstat_caps.e2e_tcp_flows_capability(), args.TSTAT_RUNTIMECONF))
        self.scheduler.add_service(tStatService(mplane.tstat_caps.tcp_options_capability(), args.TSTAT_RUNTIMECONF))
        self.scheduler.add_service(tStatService(mplane.tstat_caps.tcp_p2p_stats_capability(), args.TSTAT_RUNTIMECONF))
        self.scheduler.add_service(tStatService(mplane.tstat_caps.tcp_layer7_capability(), args.TSTAT_RUNTIMECONF))
          
    def register_to_supervisor(self):
        url = "/" + REGISTRATION_PATH
        caps_list = ""
        for key in self.scheduler.capability_keys():  
            cap = self.scheduler.capability_for_key(key)
            caps_list = caps_list + mplane.model.unparse_json(cap)
        res = self.pool.urlopen('POST', url, 
            body=caps_list.encode("utf-8"), 
            headers={"content-type": "application/x-mplane+json"})
        if res.status == 200:
            print("Capabilities successfully registered:")
            for key in self.scheduler.capability_keys():  
                cap = self.scheduler.capability_for_key(key)
                print("    " + cap.get_label())
        elif res.status == 403:
            print("Invalid registration format!")
        else:
            print("Error registering capabilities, Supervisor said: " + str(res.status) + " - " + res.data.decode("utf-8"))
    
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
            print("Result for " + job.service._capability.get_label() + " successfully returned!")
        else:
            print("Error returning Result for " + job.service._capability.get_label())
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
                    reply = self.scheduler.receive_message(self.user, msg)
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