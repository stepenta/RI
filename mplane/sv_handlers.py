# mPlane Protocol Reference Implementation
# Supervisor HTTP handlers
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

import tornado.web
import mplane.model
import mplane.utils
import copy
import re
from collections import OrderedDict

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
    
    def _respond_text(self, code, text = None):
        self.set_status(code)
        if text is not None:
            self.set_header("Content-Type", "text/plain")
            self.write(text)
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
        self._supervisor._dn_to_ip[self.dn] = self.request.remote_ip
        

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
                found = False
                if new_cap.get_label() in self._supervisor._label_to_dn:
                    for dn in self._supervisor._label_to_dn[new_cap.get_label()]:
                        if dn == self.dn:
                            print("WARNING: Capability " + new_cap.get_label() + " already registered!")
                            found = True
                if found is False:
                    self._supervisor.register(new_cap, self.dn)
                    print_then_prompt("Capability " + new_cap.get_label() + " received from " + self.dn)
                    success = True
                        
        # reply to the component
        if success == True:
            self._respond_text(200)
        else:
            self._respond_text(403, "Invalid registration format, or capabilities already registered")
    
    def split_caps(self, msg):
        caps = []
        cap_start = 0
        cap_end = self.find_closed_brace(msg, cap_start)
        while cap_end != -1:
            caps.append(mplane.model.parse_json(msg[cap_start:cap_end+1]))
            cap_start = cap_end + 1
            cap_end = self.find_closed_brace(msg, cap_start)
        return caps
        
    def find_closed_brace(elf, msg, cap_start):
        cap_end = msg.find('}', cap_start)
        closed_braces_counter = msg[cap_start:cap_end+1].count("}")
        open_braces_counter = msg[cap_start:cap_end].count("{")
        while closed_braces_counter < open_braces_counter:
            cap_end = msg.find('}', cap_end+1)
            closed_braces_counter = msg[:cap_end+1].count("}")
            open_braces_counter = msg[:cap_end].count("{")
        return cap_end
        
class SpecificationHandler(MPlaneHandler):
    """
    Exposes the specifications, that will be periodically pulled by the
    probes

    """
    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)
        self._supervisor._dn_to_ip[self.dn] = self.request.remote_ip

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
            self._respond_text(204)
        
class ResultHandler(MPlaneHandler):
    """
    Receives results of specifications, when available 

    """

    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)
        self._supervisor._dn_to_ip[self.dn] = self.request.remote_ip

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
                self._respond_text(403, "Result unexpected")
        elif isinstance(msg, mplane.model.Exception):
            # hand message to supervisor
            self._supervisor._handle_exception(msg)
            print_then_prompt("Exception Received! (instead of Result)")
        else:
            self._redirect(msg)

class S_CapabilityHandler(MPlaneHandler):
    """
    Exposes the capabilities registered to this supervisor. 
    URIs ending with "capability" will result in an HTML page 
    listing links to each capability. 

    """

    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)

    def get(self):
        # capabilities
        path = self.request.path.split("/")[1:]
        if path[0] == S_CAPABILITY_PATH:
            if (len(path) == 1 or path[1] is None):
                self._respond_capability_links()
            elif path[1] == "aggregated":
                self._respond_aggregated_capability(path[2])
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
                cap_id = cap.get_label() + ", " + key
                if self._supervisor.ac.check_azn(cap_id, self.dn):
                    self.write("<a href='/" + S_CAPABILITY_PATH + "/" + key.replace(" ", "_") + "/" + cap.get_token() + "'>" + cap.get_label() + "</a><br/>")
                    
        # aggregated caps
        for cap in self._supervisor._aggregated_caps:
            azn_list = []
            for dn in cap.dn_list:
                label = cap.schema.get_label()
                cap_id = label + ", " + dn
                if self._supervisor.ac.check_azn(cap_id, self.dn):
                    self.write("<a href='/" + S_CAPABILITY_PATH + "/aggregated/" + str(cap.schema.get_token()) + "'>" + label + "</a><br/>")
                    break
        self.write("</body></html>")
        self.finish()

    def _respond_capability(self, dn, token):
        dn = dn.replace("_", " ")
        for cap in self._supervisor._capabilities[dn]:
            cap_id = cap.get_label() + ", " + dn
            if (token == str(cap.get_token()) and self._supervisor.ac.check_azn(cap_id, self.dn)):
                self._respond_message(cap)
                return

    def _respond_aggregated_capability(self, token):
        for cap in self._supervisor._aggregated_caps:
            if cap.schema.get_token() == token:
                forbidden_dn = []
                label = cap.schema.get_label()
                allowed_net_list = ""
                for dn in cap.dn_list:
                    cap_id = label + ", " + dn
                    if not self._supervisor.ac.check_azn(cap_id, self.dn):
                        forbidden_dn.append(dn)
                    else:
                        if allowed_net_list == "":
                            allowed_net_list = str(cap.dn_to_nets[dn])
                        else:
                            allowed_net_list = allowed_net_list + "," + str(cap.dn_to_nets[dn])
                if len(forbidden_dn) > 0:
                    cap.schema.remove_parameter("aggregate.ip4")
                    cap.schema.add_parameter("aggregate.ip4", allowed_net_list)
                cap.schema.add_result_column("subnet.ip4")
                self._respond_message(cap.schema)

class S_SpecificationHandler(MPlaneHandler):
    """
    Receives specifications from a client. If the client is
    authorized to run the spec, this supervisor forwards it 
    to the probe.

    """

    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)
    
    def post(self):
        # unwrap json message from body
        if (self.request.headers["Content-Type"] == "application/x-mplane+json"):
            spec = mplane.model.parse_json(self.request.body.decode("utf-8"))
            receipt = mplane.model.Receipt(specification=spec)
            res = mplane.model.Result(specification=spec)
            if isinstance(spec, mplane.model.Specification):
                if spec.has_parameter("aggregate.ip4"):
                    # è una specification aggregata
                    requested_cap = None
                    for cap in self._supervisor._aggregated_caps:
                        if spec.get_label() == cap.schema.get_label():
                            requested_cap = cap
                    if requested_cap == None:
                        self._respond_text(403, "This aggregated measure is not available")
                        return
                    else:
                        subnets = spec.get_parameter_value("aggregate.ip4")
                        dn_to_be_run = []
                        if subnets.find(" ... ") >= 0:
                            # requested a measure for a RANGE of subnets
                            net_range = subnets.split(" ... ")
                            if len(net_range) != 2:
                                self._respond_text(403, "Invalid format for parameter \'aggregate.ip4\'")
                            if not self.check_ip_format(net_range):
                                self._respond_text(403, "Invalid format for one or more net addresses")
                                return
                            for dn in requested_cap.dn_list:
                                # creating the list of probes included in the range of subnets requested
                                mask = requested_cap.netmask
                                if (mplane.utils.get_distance(net_range[0], mask, requested_cap.dn_to_nets[dn], mask) >= 0 and
                                    mplane.utils.get_distance(net_range[1], mask, requested_cap.dn_to_nets[dn], mask) <= 0):
                                    if self._supervisor.ac.check_azn(spec.get_label() + ", " + dn, self.dn):
                                        dn_to_be_run.append(dn)
                        elif subnets.find(",") >= 0:
                            # requested a measure for a SET of subnets
                            net_list = subnets.replace(" ", "").split(".")
                            for net in net_list:
                                if not self.check_ip_format(net):
                                    self._respond_text(403, "Invalid format for one or more net addresses" + net)
                                    return
                                # creating the list of probes included in the set of subnets requested
                                for dn in requested_cap.dn_list:
                                    if net == requested_cap.dn_to_nets[dn]:
                                        if self._supervisor.ac.check_azn(spec.get_label() + ", " + dn, self.dn):
                                            dn_to_be_run.append(dn)
                        else:
                            #only one subnet requested
                            net = subnets
                            if not self.check_ip_format(net):
                                self._respond_text(403, "Invalid format for one or more net addresses" + net)
                                return
                            for dn in requested_cap.dn_list:
                                if net == requested_cap.dn_to_nets[dn]:
                                    if self._supervisor.ac.check_azn(spec.get_label() + ", " + dn, self.dn):
                                        dn_to_be_run.append(dn)
                            
                        if len(dn_to_be_run) == 0:
                            self._respond_text(403, "No valid IP addresses requested. Specification rejected")
                            return
                            
                        self._supervisor._aggregated_meas[receipt.get_token()] = [spec.get_label(), dn_to_be_run, res, receipt, requested_cap.dn_to_nets]   
                        spec.remove_parameter("aggregate.ip4")
                        spec.remove_result_column("subnet.ip4")
                        spec.add_parameter("subnet.ip4")
                        for dn in dn_to_be_run:
                            # add a specification for every subnet requested in the aggregate spec
                            for param in spec.parameter_names():
                                if param == "subnet.ip4":
                                    spec.set_parameter_value("subnet.ip4", requested_cap.dn_to_nets[dn])
                            spec.validate()
                            if not self._supervisor.add_spec(spec, dn):
                                self._respond_text(503, "Specification is temporarily unavailable. Try again later")
                                return     
                else:
                    dn = self.find_dn(spec.get_label())
                    if not self._supervisor.add_spec(spec, dn):
                        self._respond_text(503, "Specification is temporarily unavailable. Try again later")
                        return
            self._respond_message(receipt)
            return
        else:
            raise ValueError("I only know how to handle mPlane JSON messages via HTTP POST")        
     
    def check_ip_format(self, ip_list):
        for ip in ip_list:
            pattern = re.compile("^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$")
            if not pattern.match(ip):
                return False
        return True
    
    def find_dn(self, label):
        if label in self._supervisor._label_to_dn:
            for dn in self._supervisor._label_to_dn[label]:
                cap_id = label + ", " + dn
                if self._supervisor.ac.check_azn(cap_id, self.dn):
                    return dn
        raise Error("Specification " + label + " doesn't match any DN")

class S_ResultHandler(MPlaneHandler):
    """
    Receives receipts from a client. If the corresponding result
    is ready, this supervisor sends it to the probe.

    """

    def initialize(self, supervisor):
        self._supervisor = supervisor
        self.dn = get_dn(self._supervisor, self.request)
    
    def post(self):
        # unwrap json message from body
        if (self.request.headers["Content-Type"] == "application/x-mplane+json"):
            rec = mplane.model.parse_json(self.request.body.decode("utf-8"))
            if isinstance(rec, mplane.model.Redemption):
                if rec.has_parameter("aggregate.ip4"):
                    aggr_meas = self._supervisor._aggregated_meas[rec.get_token()]
                    label = aggr_meas[0]
                    dn_list = aggr_meas[1]
                    aggregated_res = aggr_meas[2]
                    for i, dn in enumerate(dn_list):
                        single_res = None
                        if dn in self._supervisor._results:
                            for r in self._supervisor._results[dn]:
                                if r.get_label() == label:
                                    single_res = r
                        if single_res == None:
                            self._respond_message(aggr_meas[3])
                            return
                        dn_to_nets = aggr_meas[4]
                        for result_column in aggregated_res.result_column_names():
                            if result_column == "subnet.ip4":
                                aggregated_res.set_result_value("subnet.ip4", dn_to_nets[dn], i)
                            else:
                                val = single_res.get_result_value(result_column)
                                if len(val) == 1:
                                    aggregated_res.set_result_value(result_column, val[0], i)
                                else:
                                    aggregated_res.set_result_value(result_column, val, i)
                        if not aggregated_res.when().is_definite():
                            aggregated_res.set_when(single_res.when())
                        else:
                            # the measurement interval is given by the time of the 
                            # first cap started, and by the time of the last completed
                            if aggregated_res.when()._a > single_res.when()._a:
                                aggregated_res.when()._a = single_res.when()._a
                            if aggregated_res.when()._b < single_res.when()._b:
                                aggregated_res.when()._b = single_res.when()._b
                    self.clean_results(dn_list, label)
                    print(mplane.model.unparse_yaml(aggregated_res))
                    self._supervisor._aggregated_meas.pop(rec.get_token())
                    self._respond_message(aggregated_res)
                    return
                else:
                    for dn in self._supervisor._results:
                        for r in self._supervisor._results[dn]:
                            if str(r.get_token()) == str(rec.get_token()):
                                self._respond_message(r)
                                self._supervisor._results[dn].remove(r)
                                return
                    meas = self._supervisor.measurements()
                    for dn in meas:
                        for r in meas[dn]:
                            if str(r.get_token()) == str(rec.get_token()):
                                self._respond_message(r)
                                return
                                
    def clean_results(self, dn_list, label):
        new_results = OrderedDict()
        for dn in dn_list:
            for res in self._supervisor._results[dn]:
                if res.get_label() != label:
                    if dn not in new_results:
                        new_results[dn] = [res]
                    else:
                        new_results[dn].append(res)
        self._supervisor._results = new_results