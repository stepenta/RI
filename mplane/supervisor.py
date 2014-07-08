#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
##
# mPlane Protocol Reference Implementation
# Simple mPlane Supervisor and CLI (JSON over HTTP)
#
# (c) 2013-2014 mPlane Consortium (http://www.ict-mplane.eu)
#               Author: Pentassuglia Stefano
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
import ssl
import sys
import cmd
import readline
import collections
from collections import OrderedDict
import html.parser
import urllib3
from urllib3 import HTTPSConnectionPool
from urllib3 import HTTPConnectionPool
import tornado.web
import tornado.httpserver
import os.path
import argparse
from datetime import datetime, timedelta
DEFAULT_LISTEN_PORT = 8888
DEFAULT_LISTEN_IP4 = '192.168.3.193'

REGISTRATION_PATH = "registration"
SPECIFICATION_PATH = "specification"
RESULT_PATH = "result"
S_CAPABILITY_PATH = "s_capability"
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
    
def print_then_prompt(line):
    print(line)
    print('|mplane| ', end="", flush = True)
    pass

def get_dn(supervisor, request):      
    if supervisor._sec == True:
        dn = ""
        for elem in request.get_ssl_certificate().get('subject'):
            if dn == "":
                dn = dn + str(elem[0][1])
            else: 
                dn = dn + "." + str(elem[0][1])
    else:
        dn = "org.mplane.Test PKI.Test Clients.mPlane-Client"
    return dn

class MPlaneHandler(tornado.web.RequestHandler):
    """
    Abstract tornado RequestHandler that allows a 
    handler to respond with an mPlane Message.

    """
    def _respond_message(self, msg):
        self.set_status(200)
        self.set_header("Content-Type", "application/x-mplane+json")
        self.write(mplane.model.unparse_json(msg))
        self.finish()
        
    def _redirect(self, msg):             
        if isinstance(msg, mplane.model.Capability):
            self.set_status(302)
            self.set_header("Location", self._supervisor.base_url + REGISTRATION_PATH)
            self.finish()
        elif isinstance(msg, mplane.model.Result):
            self.set_status(302)
            self.set_header("Location", self._supervisor.base_url + RESULT_PATH)
            self.finish()
        elif isinstance(msg, mplane.model.Exception):
            self.set_status(302)
            self.set_header("Location", self._supervisor.base_url + RESULT_PATH)
            self.finish()
        else:
            print_then_prompt("WARNING: Unknown message received!")
            pass
                
class RegistrationHandler(MPlaneHandler):
    """
    Handles the probes that want to register to this supervisor
    Each capability is registered indipendently

    """
    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)
        

    def post(self):
        # unwrap json message from body
        if (self.request.headers["Content-Type"] == "application/x-mplane+json"):
            new_caps = self.split_caps(self.request.body.decode("utf-8"))
        else:
            raise ValueError("I only know how to handle mPlane JSON messages via HTTP POST")

        success = False
        
        # register capabilities
        for new_cap in new_caps:
            if isinstance(new_cap, mplane.model.Capability):
                if len(self._supervisor._capabilities) == 0:
                    self._supervisor._capabilities[self.dn] = [new_cap]
                    self._supervisor.add_ip_to_label(new_cap.get_label(), self.request.remote_ip)
                    self._supervisor.add_cap_to_label(new_cap)
                    self._supervisor._dn_to_ip[self.dn] = self.request.remote_ip
                    print_then_prompt("Capability " + new_cap.get_label() + " received from " + self.dn)
                    success = True
                else:
                    found = False
                    if self.dn in self._supervisor._capabilities:
                        for cap in self._supervisor._capabilities[self.dn]:
                            if str(cap.get_token()) == str(new_cap.get_token()):
                                print("WARNING: Capability " + new_cap.get_label() + " already registered!")
                                found = True
                    if found is False:
                        if self.dn not in self._supervisor._capabilities:
                            self._supervisor._capabilities[self.dn] = [new_cap]
                        else:
                            self._supervisor._capabilities[self.dn].append(new_cap)
                        self._supervisor.add_ip_to_label(new_cap.get_label(), self.request.remote_ip)
                        self._supervisor.add_cap_to_label(new_cap)
                        self._supervisor._dn_to_ip[self.dn] = self.request.remote_ip
                        print_then_prompt("Capability " + new_cap.get_label() + " received from " + self.dn)
                        success = True
                        
        # reply to the component
        if success == True:
            self.set_status(200)
            self.finish()
        else:
            self.set_status(403)
            self.set_header("Content-Type", "text/plain")
            self.write("Invalid registration format")
            self.finish()
    
    def split_caps(self, msg):
        caps = []
        cap_start = 0
        cap_end = msg.find('}', cap_start)
        while cap_end != -1:
            caps.append(mplane.model.parse_json(msg[cap_start:cap_end+1]))
            cap_start = cap_end + 1
            cap_end = msg.find('}', cap_start)
        return caps
        
class SpecificationHandler(MPlaneHandler):
    """
    Exposes the specifications, that will be periodically pulled by the
    probes

    """
    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)

    def get(self):
        specs = self._supervisor._specifications.pop(self.dn, [])
        if len(specs) != 0:
            self.set_status(200)
            self.set_header("Content-Type", "application/x-mplane+json")
            for spec in specs:
                    self.write(mplane.model.unparse_json(spec))
                    if self.dn not in self._supervisor._receipts:
                        self._supervisor._receipts[self.dn] = [mplane.model.Receipt(specification=spec)]
                    else:
                        self._supervisor._receipts[self.dn].append(mplane.model.Receipt(specification=spec))
                    print_then_prompt("Specification " + spec.get_label() + " successfully pulled by " + self.dn)
            self.finish()
        else:
            self.set_status(204)
            self.finish()
        pass
        
class ResultHandler(MPlaneHandler):
    """
    Receives results of specifications, when available 

    """

    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)
        pass

    def post(self):
        # unwrap json message from body
        if (self.request.headers["Content-Type"] == "application/x-mplane+json"):
            msg = mplane.model.parse_json(self.request.body.decode("utf-8"))
        else:
            raise ValueError("I only know how to handle mPlane JSON messages via HTTP POST")
            
        if isinstance(msg, mplane.model.Result):
            # hand message to supervisor
            if self._supervisor.add_result(msg, self.dn):
                print_then_prompt("Result received by " + self.dn)
            else:
                self.set_status(403)
                self.set_header("Content-Type", "text/plain")
                self.write("Result unexpected")
                self.finish()
        elif isinstance(msg, mplane.model.Exception):
            # hand message to supervisor
            self._supervisor._handle_exception(msg)
            print_then_prompt("Exception Received! (instead of Result)")
        else:
            self._redirect(msg)
        pass

class S_CapabilityHandler(MPlaneHandler):
    """
    Exposes the capabilities registered to this supervisor. 
    URIs ending with "capability" will result in an HTML page 
    listing links to each capability. 

    """

    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)
        pass

    def get(self):
        # capabilities
        path = self.request.path.split("/")[1:]
        if path[0] == S_CAPABILITY_PATH:
            if (len(path) == 1 or path[1] is None):
                self._respond_capability_links()
            else:
                self._respond_capability(path[1])
        else:
            # FIXME how do we tell tornado we don't want to handle this?
            raise ValueError("I only know how to handle /" + S_CAPABILITY_PATH + " URLs via HTTP GET")

    def _respond_capability_links(self):
        self.set_status(200)
        self.set_header("Content-Type", "text/html")
        self.write("<html><head><title>Capabilities</title></head><body>")
        for key in self._supervisor._capabilities:
            for cap in self._supervisor._capabilities[key]:
                if self._supervisor.ac.check_azn(cap.get_label(), self.dn):
                    self.write("<a href='/" + S_CAPABILITY_PATH + "/" + cap.get_token() + "'>" + cap.get_label() + "</a><br/>")
        self.write("</body></html>")
        self.finish()

    def _respond_capability(self, token):
        for cap in self._supervisor._capabilities[self.dn]:
            if (token == str(cap.get_token()) and
                self._supervisor.ac.check_azn(cap.get_label(), self.dn)):
                    self._respond_message(cap)

class S_SpecificationHandler(MPlaneHandler):
    """
    Receives specifications from a client. If the client is
    authorized to run the spec, this supervisor forwards it 
    to the probe.

    """

    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)
        pass
    
    def post(self):
        # unwrap json message from body
        if (self.request.headers["Content-Type"] == "application/x-mplane+json"):
            msg = mplane.model.parse_json(self.request.body.decode("utf-8"))
        else:
            raise ValueError("I only know how to handle mPlane JSON messages via HTTP POST")

#class CrawlParser(html.parser.HTMLParser):
#    """
#    HTML parser class to extract all URLS in a href attributes in
#    an HTML page. Used to extract links to Capabilities exposed
#    as link collections.
#
#    """
#    def __init__(self, **kwargs):
#        super(CrawlParser, self).__init__(**kwargs)
#        self.urls = []
#
#    def handle_starttag(self, tag, attrs):
#        attrs = {k: v for (k,v) in attrs}
#        if tag == "a" and "href" in attrs:
#            self.urls.append(attrs["href"])

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
                (r"/" + REGISTRATION_PATH, RegistrationHandler, {'supervisor': self}),
                (r"/" + SPECIFICATION_PATH, SpecificationHandler, {'supervisor': self}),
                (r"/" + RESULT_PATH, ResultHandler, {'supervisor': self}),
                (r"/" + S_CAPABILITY_PATH, S_CapabilityHandler, {'supervisor': self}),
                (r"/" + S_CAPABILITY_PATH + "/.*", S_CapabilityHandler, {'supervisor': self}),
                (r"/" + S_SPECIFICATION_PATH, S_SpecificationHandler, {'supervisor': self}),
                #(r"/" + S_RESULT_PATH, S_ResultHandler, {'supervisor': self}),
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
        self._specifications = OrderedDict()
        self._receipts = OrderedDict()
        self._results = OrderedDict()
        
        self._label_to_ip = dict()
        self._label_to_cap = dict()
        self._dn_to_ip = dict()
        
    def add_result(self, msg, dn):
        """Add a receipt. Check for duplicates and if result is expected."""
        if dn in self._receipts:
            for receipt in self._receipts[dn]:
                if str(receipt.get_token()) == str(msg.get_token()):
                    if dn not in self._results:
                        self._results[dn] = [msg]
                    else:
                        self._results[dn].append(msg)
                    
                    self._receipts[dn].remove(receipt)
                    return True
        print("WARNING: Received an unexpected Result!")
        return False

    def measurements(self):
        """Iterate over all measurements (receipts and results)"""
        measurements = OrderedDict()
        
        for key in self._receipts:
            if key not in measurements:
                measurements[key] = [self._receipts[key]]
            else:
                measurements[key].append(self._receipts[key])
                
        for key in self._results:
            if key not in measurements:
                measurements[key] = [self._results[key]]
            else:
                measurements[key].append(self._results[key])
                
        return measurements

    def _handle_exception(self, exc):
        print(repr(exc))
        
    def add_ip_to_label(self, label, ip):
        if label in self._label_to_ip:
            self._label_to_ip[label].append(ip)
        else:
            self._label_to_ip[label] = [ip]

    def add_cap_to_label(self, cap):
        if cap.get_label() not in self._label_to_cap:
            self._label_to_cap[cap.get_label()] = cap

    def dn_from_ip(self, ip):
        for dn, value in self._dn_to_ip:
            if value == ip:
                return dn
    
    def ip_to_string(self, ip_list):
        ip_string = ""
        for ip in ip_list:
            if len(ip_string) == 0:
                ip_string = ip
            else:
                ip_string = ip_string + "," + ip
        return ip_string
    
    def aggregated_caps(self):
        aggregated = []
        for label in self._label_to_ip:
            if len(self._label_to_ip[label]) > 1:
                cap = self._label_to_cap[label]
                ip_string = self.ip_to_string(self._label_to_ip[label])
                cap.add_parameter("source.ip4", ip_string)
                aggregated.append(cap)
        if len(aggregated) > 0:
            return aggregated
        else:
            return None              
    
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
                
        aggregated = self._supervisor.aggregated_caps()
        if aggregated is not None:
            print("\nAggregated Capabilities:")
            for cap in aggregated:
                print(str(i) + " ------------------------------------------------------")
                self._show_stmt(cap)
                i = i + 1

    def do_showcap(self, arg):
        """
        Show a capability given a capability index; 
        without an index, shows all capabilities

        """
        if len(arg) > 0:
            try:
                i = 1
                for key in self._supervisor._capabilities:
                    for cap in self._supervisor._capabilities[key]:
                        if str(i) == arg:
                            self._show_stmt(cap)
                        i = i + 1
            except:
                print("No such capability: " + arg)
        else:
            for key in self._supervisor._capabilities:
                for cap in self._supervisor._capabilities[key]:
                    self._show_stmt(cap)

    def do_listmeas(self, arg):
        """List running/completed measurements by index"""
        i = 1
        for key in self._supervisor._receipts:
            if len(self._supervisor._receipts[key]) > 0:
                for receipt in self._supervisor._receipts[key]:
                    print(str(i) + " - " + repr(receipt))
                    i = i + 1
        for key in self._supervisor._results:
            if len(self._supervisor._results[key]) > 0:
                for result in self._supervisor._results[key]:
                    print(str(i) + " - " + repr(result))
                    i = i + 1

    def do_showmeas(self, arg):
        """Show receipt/results for a measurement, given a measurement index"""
        if len(arg) > 0:
            i = 1
            for key in self._supervisor._receipts:
                if len(self._supervisor._receipts[key]) > 0:
                    for receipt in self._supervisor._receipts[key]:
                        if str(i) == arg:
                            self._show_stmt(receipt)
                            return
                        i = i + 1
            for key in self._supervisor._results:
                if len(self._supervisor._results[key]) > 0:
                    for result in self._supervisor._results[key]:
                        if str(i) == arg:
                            self._show_stmt(result)
                            return
                        i = i + 1
            print("No such measurement: " + arg)
        else:
            for key in self._supervisor._receipts:
                if len(self._supervisor._receipts[key]) > 0:
                    for receipt in self._supervisor._receipts[key]:
                        self._show_stmt(receipt)
            for key in self._supervisor._results:
                if len(self._supervisor._results[key]) > 0:
                    for result in self._supervisor._results[key]:
                        self._show_stmt(result)

    def _show_stmt(self, stmt):
        print(mplane.model.unparse_yaml(stmt))

    def do_runcap(self, arg):
        """
        Run a capability given an index, filling in temporal 
        scope and defaults for parameters. Prompts for parameters 
        not yet entered.

        """
        # Retrieve a capability and create a specification
        dn = None
        cap = None
        try:
            i = 1
            for key in self._supervisor._capabilities:
                for c in self._supervisor._capabilities[key]:
                    if str(i) == arg:
                        dn = key
                        cap = c
                    i = i + 1
        except:
            print("No such capability: " + arg)
            
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
        
        if dn not in self._supervisor._specifications:
            self._supervisor._specifications[dn] = [spec]
        else:
            # Check for concurrent specifications
            for spec in self._supervisor._specifications[dn]:
                if spec.fulfills(cap):
                    print("There is already a Specification for this Capability. Try again later")
                    return 
            self._supervisor._specifications[dn].append(spec)
        print("ok")

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
