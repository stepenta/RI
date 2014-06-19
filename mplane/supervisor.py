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
import ssl
import sys
import cmd
import readline
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
DEFAULT_LISTEN_IP4 = '127.0.0.1'

REGISTRATION_PATH = "registration"
SPECIFICATION_PATH = "specification"
RESULT_PATH = "result"

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

class ComplexSpecification(object):
    """
    An High-Level Specification contains additional informations about
    a Specification, such as the IPv4 address of the component to which 
    the Specification is directed.

    """
    
    def __init__(self, spec, ip4):
        self._spec = spec
        self._ip4 = ip4
        
    def simple_spec(self):
        return self._spec
        
    def ip4(self):
        return self._ip4
        
    def fulfills(self, cap):
        return (self.simple_spec().fulfills(cap.simple_cap()) and self.ip4() == cap.ip4())

class ComplexCapability(object):
    """
    An High-Level Capability contains additional informations about
    a Capability, such as the IPv4 address of the component.

    """
    
    def __init__(self, cap, ip4):
        self._cap = cap
        self._ip4 = ip4
        
    def simple_cap(self):
        return self._cap
        
    def ip4(self):
        return self._ip4  
   
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
        pass

    def post(self):
        # unwrap json message from body
        if (self.request.headers["Content-Type"] == "application/x-mplane+json"):
            msg = mplane.model.parse_json(self.request.body.decode("utf-8"))
        else:
            raise ValueError("I only know how to handle mPlane JSON messages via HTTP POST")

        if isinstance(msg, mplane.model.Capability):
            found = False
            for complex_cap in self._supervisor.capabilities():
                if (complex_cap.simple_cap().__repr__() == msg.__repr__() and
                    complex_cap.ip4() == self.request.remote_ip):
                    print("WARNING: Capability " + msg.get_label() + " already registered!")
                    found = True
                    self.set_status(403)
                    self.set_header("Content-Type", "text/plain")
                    self.write("Already registered")
                    self.finish()
            if found is False:
                spec_url = self._supervisor.base_url + SPECIFICATION_PATH
                complex_cap = ComplexCapability(msg, self.request.remote_ip)
                self._supervisor.add_capability(complex_cap)
                self.set_status(200)
                self.set_header("Content-Type", "text/plain")
                self.write(spec_url)
                self.finish()
                print_then_prompt("Capability " + msg.get_label() + " received from " + self.request.remote_ip)
        else:
            self._redirect(msg)
        pass
        
class SpecificationHandler(MPlaneHandler):
    """
    Exposes the specifications, that will be periodically pulled by the
    probes

    """
    def initialize(self, supervisor):
        self._supervisor = supervisor
        pass

    def get(self):
        cap = self._supervisor.capability_by_token_and_ip(self.get_argument('token'), self.request.remote_ip)
        if len(self._supervisor._specifications) != 0:
            self.set_status(200)
            self.set_header("Content-Type", "application/x-mplane+json")
            for spec in self._supervisor._specifications:
                if spec.fulfills(cap):
                    self.write(mplane.model.unparse_json(spec.simple_spec()))
                    self._supervisor.add_receipt(mplane.model.Receipt(specification=spec.simple_spec()))
                    print_then_prompt("Capability " + cap.simple_cap().get_label() + " successfully pulled!")
            self.finish()
            updated_specs = [spec for spec in self._supervisor._specifications if not spec.fulfills(cap)]
            self._supervisor._specifications = updated_specs
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
        pass

    def post(self):
        # unwrap json message from body
        if (self.request.headers["Content-Type"] == "application/x-mplane+json"):
            msg = mplane.model.parse_json(self.request.body.decode("utf-8"))
        else:
            raise ValueError("I only know how to handle mPlane JSON messages via HTTP POST")
            
        if isinstance(msg, mplane.model.Result):
            # hand message to supervisor
            if self._supervisor.add_result(msg):
                print_then_prompt("Result Received!")
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

class CrawlParser(html.parser.HTMLParser):
    """
    HTML parser class to extract all URLS in a href attributes in
    an HTML page. Used to extract links to Capabilities exposed
    as link collections.

    """
    def __init__(self, **kwargs):
        super(CrawlParser, self).__init__(**kwargs)
        self.urls = []

    def handle_starttag(self, tag, attrs):
        attrs = {k: v for (k,v) in attrs}
        if tag == "a" and "href" in attrs:
            self.urls.append(attrs["href"])

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
            ])
            
        if args.DISABLE_SEC == False:
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
        self._capabilities = []
        self._specifications = []
        self._receipts = []
        self._results = []

    def capabilities(self):
        """Iterate over capabilities"""
        yield from self._capabilities

    def capability_at(self, index):
        """Retrieve a capability at a given index"""
        return self._capabilities[index]
        
    def capability_by_token_and_ip(self, token, ip):
        for cap in self._capabilities:
            if (str(cap.simple_cap().get_token()) == token and
                cap.ip4() == ip):
                return cap

    def add_capability(self, cap):
        """Add a capability to the capability cache"""
        self._capabilities.append(cap)

    def clear_capabilities(self):
        """Clear the capability cache"""
        self._capabilities.clear()
       
    def receipts(self):
        """Iterate over receipts (pending measurements)"""
        yield from self._receipts

    def add_receipt(self, msg):
        """Add a receipt. Check for duplicates."""
        if msg.get_token() not in [receipt.get_token() for receipt in self.receipts()]:
            self._receipts.append(msg)

    def _delete_receipt_for(self, token):
        self._receipts = list(filter(lambda msg: msg.get_token() != token, self._receipts))
        
    def add_result(self, msg):
        """Add a receipt. Check for duplicates and if result is expected."""
        
        for receipt in self.receipts():
            if str(receipt.get_token()) == str(msg.get_token()):
                if msg.get_token() not in [result.get_token() for result in self._results]:
                    self._results.append(msg)
                    self._delete_receipt_for(msg.get_token())
                return True
        print("WARNING: Received an unexpected Result!")
        return False

    def measurements(self):
        """Iterate over all measurements (receipts and results)"""
        yield from self._results
        yield from self._receipts

    def measurement_at(self, index):
        """Retrieve a measurement at a given index"""
        if index >= len(self._results):
            index -= len(self._results)
            return self._receipts[index]
        else:
            return self._results[index]

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
        for i, cap in enumerate(self._supervisor.capabilities()):
            print ("%4u: %s" % (i, repr(cap.simple_cap())))

    def do_listmeas(self, arg):
        """List running/completed measurements by index"""
        for i, meas in enumerate(self._supervisor.measurements()):
            print ("%4u: %s" % (i, repr(meas)))

    def do_showcap(self, arg):
        """
        Show a capability given a capability index; 
        without an index, shows all capabilities

        """
        if len(arg) > 0:
            try:
                self._show_stmt(self._supervisor.capability_at(int(arg.split()[0])).simple_cap())
            except:
                print("No such capability "+arg)
        else:
            for i, cap in enumerate(self._supervisor.capabilities()):
                print ("cap %4u ---------------------------------------" % i)
                self._show_stmt(cap.simple_cap())

    def do_showmeas(self, arg):
        """Show receipt/results for a measurement, given a measurement index"""
        if len(arg) > 0:
            try:
                meas = self._supervisor.measurement_at(int(arg.split()[0]))
                print("ok fin qui fuori")
                self._show_stmt(meas)
            except:
                print("No such measurement "+arg)
        else:
            for i, meas in enumerate(self._supervisor.measurements()):
                print ("meas %4u --------------------------------------" % i)
                self._show_stmt(meas)

    def _show_stmt(self, stmt):
        print(mplane.model.unparse_yaml(stmt))

    def do_runcap(self, arg):
        """
        Run a capability given an index, filling in temporal 
        scope and defaults for parameters. Prompts for parameters 
        not yet entered.

        """
        # Retrieve a capability and create a specification
        try:
            cap = self._supervisor.capability_at(int(arg.split()[0]))
        except:
            print ("No such capability: "+arg)
            return

        simple_spec = mplane.model.Specification(capability=cap.simple_cap())
        spec = ComplexSpecification(simple_spec, cap.ip4())
        
        # Check for concurrent specifications
        for sp in self._supervisor._specifications:
            if sp.fulfills(cap):
                print("There is already a Specification for this Capability. Try again later")
                return
                
        # Set temporal scope or prompt for new one
        while self._when is None or \
              not self._when.follows(cap.simple_cap().when()) or \
              (self._when.period is None and cap.simple_cap().when().period() is not None):
            sys.stdout.write("|when| = ")
            self._when = mplane.model.When(input())

        spec.simple_spec().set_when(self._when)

        # Fill in single values
        spec.simple_spec().set_single_values()

        # Fill in parameter values
        for pname in spec.simple_spec().parameter_names():
            if spec.simple_spec().get_parameter_value(pname) is None:
                if pname in self._defaults:
                    # set parameter value from defaults
                    print("|param| "+pname+" = "+self._defaults[pname])
                    spec.simple_spec().set_parameter_value(pname, self._defaults[pname])
                else:
                    # set parameter value with input
                    sys.stdout.write("|param| "+pname+" = ")
                    spec.simple_spec().set_parameter_value(pname, input())
            else:
                # FIXME we really want to unparse this
                print("|param| "+pname+" = "+str(spec.simple_spec().get_parameter_value(pname)))

        # Validate specification
        spec.simple_spec().validate()

        # And send it to the server
        self._supervisor._specifications.append(spec)
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
