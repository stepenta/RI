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

import tornado.web
import mplane.model

REGISTRATION_PATH = "registration"
SPECIFICATION_PATH = "specification"
RESULT_PATH = "result"
S_CAPABILITY_PATH = "s_capability"
S_AGGREGATED_CAPABILITY_PATH = "s_aggregated_capability"
S_SPECIFICATION_PATH = "s_specification"
S_RESULT_PATH = "s_result"
    
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
    supervisor._dn_to_ip[dn] = request.remote_ip
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
                    self._supervisor.aggregate(new_cap, self.dn)
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
                        self._supervisor.aggregate(new_cap, self.dn)
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
            elif path[1].startswith("aggregated-"):
                self._respond_aggregated_capability(path[1])
            else:
                self._respond_capability(path[1], path[2])
        else:
            # FIXME how do we tell tornado we don't want to handle this?
            raise ValueError("I only know how to handle /" + S_CAPABILITY_PATH + " URLs via HTTP GET")

    def _respond_capability_links(self):
        self.set_status(200)
        self.set_header("Content-Type", "text/html")
        self.write("<html><head><title>Capabilities</title></head><body>")
        for key in self._supervisor._capabilities:
            for cap in self._supervisor._capabilities[key]:
                aggr_label = "aggregated-" + cap.get_label()
                if aggr_label not in self._supervisor._aggregated_caps:
                    print("cap singola")
                    cap_id = cap.get_label() + ", " + key
                    if self._supervisor.ac.check_azn(cap_id, self.dn):
                        self.write("<a href='/" + S_CAPABILITY_PATH + "/" + key.replace(" ", "_") + "/" + cap.get_token() + "'>" + cap.get_label() + "</a><br/>")
                    
        # aggregated caps
        for label in self._supervisor._aggregated_caps:
            azn_list = []
            for dn in self._supervisor._aggregated_caps[label].dn_list:
                lab = self._supervisor._aggregated_caps[label].schema.get_label()
                cap_id = lab + ", " + dn
                if self._supervisor.ac.check_azn(cap_id, self.dn):
                    azn_list.append(dn)
                    print("azn_list = " + str(azn_list))
                    if len(azn_list) >= 2:
                        print("cap aggregata")
                        # more than 2 source IPs, aggregation makes sense
                        self.write("<a href='/" + S_CAPABILITY_PATH + "/" + label + "'>" + label + "</a><br/>")
                        break
            if len(azn_list) == 1:
                print("cap singola dopo aggregata")
                # at least one source IP, exposing single capability
                cap_schema = self._supervisor._aggregated_caps[label].schema
                self.write("<a href='/" + S_CAPABILITY_PATH + "/" + azn_list[0].replace(" ", "_") + "/" + cap_schema.get_token() + "'>" + cap_schema.get_label() + "</a><br/>")
        self.write("</body></html>")
        self.finish()

    def _respond_capability(self, dn, token):
        dn = dn.replace("_", " ")
        for cap in self._supervisor._capabilities[dn]:
            cap_id = cap.get_label() + ", " + dn
            if (token == str(cap.get_token()) and self._supervisor.ac.check_azn(cap_id, self.dn)):
                self._respond_message(cap)

    def _respond_aggregated_capability(self, label):
        ip_list = ""
        for dn in self._supervisor._aggregated_caps[label].dn_list:
            cap_id = self._supervisor._aggregated_caps[label].schema.get_label() + ", " + dn
            if self._supervisor.ac.check_azn(cap_id, self.dn):
                if ip_list == "":
                    ip_list = self._supervisor._dn_to_ip[dn]
                else:
                    ip_list = ip_list + "," + self._supervisor._dn_to_ip[dn]
                
        if ip_list != "":
            cap = self._supervisor._aggregated_caps[label].schema
            cap._label = label
            cap.add_parameter("source.ip4", ip_list)
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
            if isinstance(msg, mplane.model.Specification):
                if msg.get_label().startswith("aggregated"):
                    print_then_prompt("Aggregated cap received!")
                else:
                    if selfdn not in self._supervisor._specifications:
                        self._supervisor._specifications[dn] = [spec]
                    else:
                        # Check for concurrent specifications
                        for spec in self._supervisor._specifications[dn]:
                            if spec.fulfills(cap):
                                print("There is already a Specification for this Capability. Try again later")
                                return 
                        self._supervisor._specifications[dn].append(spec)
        else:
            raise ValueError("I only know how to handle mPlane JSON messages via HTTP POST")
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            