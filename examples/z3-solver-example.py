# download z3 from: https://github.com/Z3Prover/z3/wiki/Using%20Z3Py%20on%20Windows
#be sure to add the extarct'd zip files' Bin dir to your path   [ path=%path%c:\z3\bin; ] 
#
# problem with 3 params
#-------------------
# x - y + z == 0x5c664b56
# 3 * (x + z) + y == 0x2e700c7b2
# y * z == 0x32ac30689a6ad314
#
# u need to figure out what are x,y,z ...


from z3 import *

username = ""
x = Real('x')
y = Real('y')
z = Real('z')

s = Solver()
s.add(x - y + z == 0x5c664b56, 3 * (x + z) + y == 0x2e700c7b2, y * z == 0x32ac30689a6ad314)
s.check()

for d in s.model():
	print(hex(int("%s" % (s.model()[d]))))
	username += hex(int("%s" % (s.model()[d])))[2:].decode("hex")[::-1]

print("Username found: " + username)  
print(s.model())
