#!/usr/bin/env python

import sys
import dwarf
import probe
from time import sleep

if len(sys.argv) < 4:
    print("usage:", sys.argv[0], "binary filename line_number")
    sys.exit(1)
binary = sys.argv[1]
filename = sys.argv[2].encode()
line = int(sys.argv[3])

print('loading dwarf')
d = dwarf.load_dwarf(binary)
print('reading dwarf for line address')
cu, address = dwarf.location_to_abs_address(d, filename, line)
print('reading dwarf for variable address')
addresses = dwarf.get_variable_location(d, address, cu, b'tick')
print(addresses)
print('compiling bpf')
b = probe.compile(addresses)
print('attaching probes')
probe.attach(b, binary, address)
print('running')
while True:
    probe.report(b)
    sleep(1)
