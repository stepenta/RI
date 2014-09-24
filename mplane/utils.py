# mPlane Protocol Reference Implementation
# Various Utilities
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
# FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.
#

import os.path
import re
import mplane.model
import json

def read_setting(filepath, param):
    """
    Reads a setting from the file indicated
    
    """
    with open(filepath,'r') as f:
        for line in f.readlines():
            if line[0] != "#":
                line = line.rstrip('\n')
                if line.split('= ')[0] == param:
                    if line.split('= ')[1] == 'True':
                        return True
                    elif line.split('= ')[1] == 'False':
                        return False
                    else:
                        return line.split('= ')[1]
    return None
    
def check_file(filename): 
    """
    Checks if the file exists
    
    """      
    if not os.path.exists(filename):
        raise ValueError("Error: File " + filename + " does not appear to exist.")
        exit(1)
        
def normalize_path(path):
    """
    Converts every path into absolute paths
    
    """
    if path[0] != '/':
        return os.path.abspath(path)
    else:
        return path
    
def ip_to_bin(address, netmask):
    """
    Converts an IP address into a binary string
    
    """
    num_groups = address.split('.')
    bin_address = ""
    for group in num_groups:
        
        # convert each group of numbers of the IP into binary
        bin_group =bin(int(group)).replace("0b","") # the bin() function prefixes each converted value with '0b'
        
        # normalize the binary value to 8 ciphers
        while len(bin_group) < 8:
            bin_group = "0" + bin_group
            
        # append the binary group to the string containing the address in binary
        bin_address += bin_group
        
    # return the binary address, truncated to the bits of its netmask
    return bin_address[0:netmask]
        
def get_distance(net1, mask1, net2, mask2):
    """
    Returns the distance (in terms of IP addresses)
    between two subnets:
    net1 < net2: distance < 0
    net1 > net2: distance > 0
    
    """
    if mask1 == mask2:
        bin_net1 = ip_to_bin(net1, mask1)
        bin_net2 = ip_to_bin(net2, mask2)
        dec_net1 = int(bin_net1, 2)
        dec_net2 = int(bin_net2, 2)
        return dec_net2 - dec_net1
    else:
        
        # netmasks don't coincide, then the subnets are not 
        # adjacent: return an absurdly high distance
        return 10000

def check_ip_format(ip_list):
    """
    Checks the correctness of the IP addresses in the list
    
    """
    for ip in ip_list:
        pattern = re.compile("^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$")
        if not pattern.match(ip):
            return False
    return True
   
def print_then_prompt(line):
    """
    Prints a message on screen, then prints the mplane prompt
    
    """
    print(line)
    print('|mplane| ', end="", flush = True)
    pass

def add_value_to(container, key, value):
    """
    Adds a value to a dict() of lists
    
    """
    if key not in container:
        container[key] = [value]
    else:
        container[key].append(value)
        
def split_stmt_list(msg):
    """
    Splits a JSON array of statements (capabilities or specifications) in 
    JSON format into a list of single statements
    
    """
    json_stmts = json.loads(msg)
    stmts = []
    for json_stmt in json_stmts:
        stmts.append(mplane.model.parse_json(json.dumps(json_stmt)))
    return stmts