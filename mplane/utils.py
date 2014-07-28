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

def read_setting(filepath, param):
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
    if not os.path.exists(filename):
        raise ValueError("Error: File " + filename + " does not appear to exist.")
        exit(1)
        
def normalize_path(path):
    if path[0] != '/':
        return os.path.abspath(path)
    else:
        return path
    
def ip_to_bin(address, netmask):
    num_groups = address.split('.')
    bin_address = ""
    for group in num_groups:
        bin_group =bin(int(group)).replace("0b","")
        while len(bin_group) < 8:
            bin_group = "0" + bin_group
        bin_address += bin_group
    return bin_address[0:netmask]
        
def get_distance(net1, mask1, net2, mask2):
    # net1 < net2: > 0
    # net1 > net2: < 0
    if mask1 == mask2:
        bin_net1 = ip_to_bin(net1, mask1)
        bin_net2 = ip_to_bin(net2, mask2)
        dec_net1 = int(bin_net1, 2)
        dec_net2 = int(bin_net2, 2)
        return dec_net2 - dec_net1
    else:
        return 10000