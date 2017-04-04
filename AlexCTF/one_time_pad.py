#Links:
#http://users.telenet.be/d.rijmenants/en/onetimepad.htm
#http://crypto.stackexchange.com/questions/59/taking-advantage-of-one-time-pad-key-reuse
#My initial guess of the key is 'ALEXCTF{'

c1 = "0529242a631234122d2b36697f13272c207f2021283a6b0c7908"
c2 = "2f28202a302029142c653f3c7f2a2636273e3f2d653e25217908"
c3 = "322921780c3a235b3c2c3f207f372e21733a3a2b37263b313012"
c4 = "2f6c363b2b312b1e64651b6537222e37377f2020242b6b2c2d5d"
c5 = "283f652c2b31661426292b653a292c372a2f20212a316b283c09"
c6 = "29232178373c270f682c216532263b2d3632353c2c3c2a293504"
c7 = "613c37373531285b3c2a72273a67212a277f373a243c20203d5d"
c8 = "243a202a633d205b3c2d3765342236653a2c7423202f3f652a18"
c9 = "2239373d6f740a1e3c651f207f2c212a247f3d2e65262430791c"
c10 = "263e203d63232f0f20653f207f332065262c3168313722367918"
c11 = "2f2f372133202f142665212637222220733e383f2426386b"

k_str = "ALEXCTF{HERE_GOES_THE_KEY}"
k1 = k_str.encode("hex")

c1_str = c1.decode("hex")
c2_str = c2.decode("hex")
c3_str = c3.decode("hex")
c4_str = c4.decode("hex")
c5_str = c5.decode("hex")
c6_str = c6.decode("hex")
c7_str = c7.decode("hex")
c8_str = c8.decode("hex")
c9_str = c9.decode("hex")
c10_str = c10.decode("hex")
c11_str = c11.decode("hex")

def hexxor(a, b):
    return "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(a, b)])

m1_str = "Dear Friend, This time I u"
m1 = m1_str.encode("hex")
m2_str = "nderstood my mistake and"
m2 = m2_str.encode("hex")
m3_str = "sed One time pad encryption"
m3 = m3_str.encode("hex")
m7_str =" proven to be"
m7 = m7_str.encode("hex")
m8_str = "ever if the key"
m8 = m8_str.encode("hex")
print hexxor(c1[:len(k1)], k1).decode("hex")
print hexxor(c2[:len(k1)], k1).decode("hex")
print hexxor(c3[:len(k1)], k1).decode("hex")
print hexxor(c4[:len(k1)], k1).decode("hex")
print hexxor(c5[:len(k1)], k1).decode("hex")
print hexxor(c6[:len(k1)], k1).decode("hex")
print hexxor(c7[:len(k1)], k1).decode("hex")
print hexxor(c8[:len(k1)], k1).decode("hex")
print hexxor(c9[:len(k1)], k1).decode("hex")
print hexxor(c10[:len(k1)], k1).decode("hex")
print hexxor(c11[:len(k1)], k1).decode("hex")
#print hexxor(c3[:len(m3)], m3).decode("hex")