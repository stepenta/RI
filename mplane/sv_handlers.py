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
                if len(self._supervisor._capabilities) == 0:
                    self._supervisor._capabilities[self.dn] = [new_cap]
                    print_then_prompt("Capability " + new_cap.get_label() + " received from " + self.dn)
                    success = True
                else:
                    found = False
                    if new_cap.get_label() in self._supervisor._info_by_label:
                        for dn in self._supervisor._info_by_label:
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
                    if len(azn_list) >= 2:
                        # more than 2 source IPs, aggregation makes sense
                        self.write("<a href='/" + S_CAPABILITY_PATH + "/" + label + "'>" + label + "</a><br/>")
                        break
            if len(azn_list) == 1:
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
                return

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
            cap = copy.deepcopy(self._supervisor._aggregated_caps[label].schema)
            cap._label = label
            subnet = aggregate_subnets()
            cap.add_parameter("list.ip4", ip_list)
            cap.add_result_column("subnet.ip4")
            self._respond_message(cap)
            return

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
                if spec.get_label().startswith("aggregated"):
                    if spec.get_label() not in self._supervisor._aggregated_caps:
                        self._respond_text(403, "This aggregated measure is not available")
                        return
                    else:
                        ip_list = str(spec.get_parameter_value("list.ip4")).replace(" ", "").split(",")
                        if not self.check_ip_format(ip_list):
                            self._respond_text(403, "Invalid format for one or more IP addresses")
                            return
                        spec.remove_parameter("list.ip4") 
                        spec.remove_result_column("subnet.ip4")
                        spec._label = spec.get_label().replace("aggregated-", "")
                        dn_list = []
                        for ip in ip_list:
                            probe_dn = self._supervisor.dn_from_ip(ip)
                            if probe_dn is not None:
                                if self._supervisor.ac.check_azn(spec.get_label() + ", " + probe_dn, self.dn):
                                    dn_list.append(probe_dn)
                        if len(dn_list) == 0:
                            self._respond_text(403, "No valid IP address. Specification rejected")
                            return
                        self._supervisor._aggregated_meas[receipt.get_token()] = [spec.get_label(), dn_list, res, receipt]     
                        for probe_dn in dn_list:
                            if not self._supervisor.add_spec(spec, probe_dn):
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
        for dn in self._supervisor._label_to_dn[label]:
            cap_id = label + ", " + dn
            if self._supervisor.ac.check_azn(cap_id, self.dn):
                return dn
        if dn is None:
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
                if rec.has_result_column("subnet.ip4"):
                    aggr_meas = self._supervisor._aggregated_meas.pop(rec.get_token())
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
                        
                        for result_column in aggregated_res.result_column_names():
                            if result_column == "subnet.ip4":
                                aggregated_res.set_result_value("subnet.ip4", self._supervisor._dn_to_ip[dn], i)
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