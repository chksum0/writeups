import os
md5s = [174282896860968005525213562254350376167L, 137092044126081477479435678296496849608L, 126300127609096051658061491018211963916L, 314989972419727999226545215739316729360L, 256525866025901597224592941642385934114L, 115141138810151571209618282728408211053L, 8705973470942652577929336993839061582L, 256697681645515528548061291580728800189L, 39818552652170274340851144295913091599L, 65313561977812018046200997898904313350L, 230909080238053318105407334248228870753L, 196125799557195268866757688147870815374L, 74874145132345503095307276614727915885L]
#print len(md5s)
#print 'Can you turn me back to python ? ...'
#flag = raw_input('well as you wish.. what is the flag: ')
flag = md5s[0:10]
#print len(flag)
if len(flag) > 69:
    print 'nice try1'
    exit()
if len(flag) % 5 != 0:
    print 'nice try2'
    exit()
print "**********************************************"
for i in range(0, len(md5s)):
    curr_md5 = str(hex(md5s[i]))
    print curr_md5
    curr_md5 = curr_md5[2:-1]
    print curr_md5
    print len(curr_md5)
    cmd = "c:\\Python27\\Scripts\\pybozocrack.exe -s " + curr_md5
    print os.system(cmd)
    print "**********************************************"

print 'Congratz now you have the flag'