
# Public Key Infrastructure

This is a short writeup on solving the 'Public Key Infrastructure' challenge from the CONfidence teaser CTF by DragonSector.

## The Challenge

We are given an address of a service that runs the following code:

```python
from secrets import SECRET, PRIVATE, FLAG
import hashlib
import SocketServer

PORT = 1337

G = 0xe6a5905121b0fd7661e2eb06db9a4d96799165478a0b2baf09836c59ccf4f086bc2a55191ee4bf8b2324f6f53294da244342aba000f7b915861ba2167d09c5569910ae80990c3c79040879d8e16e48219127718d9ff05f71a905041564e9bcb55417b39cdb0b7afc6863ccd10b90ee42f856840e0dd5f8602e49592b58a22d39
P = 0xf2a4ca87978e05b112ef4a16b547c5036cd51fadac0cf967c152e56378c792a45e76e0ebfd62b2b23e94ca3727fbe1ebb308211cf8938c8a735db2de4cd26f0beb53b51fc2a5474bd0d466fc54fce13a4ec2b9840800ecdf337c55105c9b7d702b7f2d20bb3cba16a5948a208f8886ab2eddd1284a5b8ec457bf696be4bbb51b
Q = 0x9821a36da85bf3bcfb379d7cc39f5b6db7a553d5
PUBLIC = 0x5596b39949bab7979f8a679c11daad86ed59394ff4956769ec036d579ae6f80cd99bd12c442e10ee6aceed275739cb07417842d28d45f82b7a64d506c6f50f95622491a07c834260d64eb75bdaccdfdcf8ca4584f0c300403a4bed1ca515854b97732c8638118f71720c054f15d441f784a8c7b0c1a41dd07eb9acaaa7a7126e

def h(x):
  return int(hashlib.md5(x).hexdigest(), 16)

def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
  g, x, y = egcd(a, m)
  if g != 1:
    raise Exception('modular inverse does not exist')
  else:
    return x % m

def makeMsg(name, n):
  return 'MSG = {n: ' + n + ', name: ' + name + '}'

def makeK(name, n):
  return 'K = {n: ' + n + ', name: ' + name + ', secret: ' + SECRET + '}'

def sign(name, n):
  k = h(makeK(name, n))
  print k
  r = pow(G, k, P) % Q
  s = (modinv(k, Q) * (h(makeMsg(name, n)) + PRIVATE * r)) % Q
  return (r*Q + s)

def verify(name, n, sig):
  r = sig / Q
  s = sig % Q
  if r < 0 or s < 0 or r > Q:
    return False
  w = modinv(s, Q)
  u1 = (h(makeMsg(name, n)) * w) % Q
  u2 = (r * w) % Q
  v = ((pow(G, u1, P) * pow(PUBLIC, u2, P)) % P) % Q
  return r == v

def register(name, n):
  if name == 'admin':
    return 'admin name not allowed'
  if len(name) > 5:
    return 'name too long'
  return str(pow(sign(name, n), 65537, int(n.encode('hex'), 16)))

def login(name, n, sig):
  if not verify(name, n, int(sig.encode('hex'), 16)):
    return 'failed to verify'
  if name == 'admin':
    return FLAG
  else:
    return 'Hello ' + name

def process(data):
  [fun, params] = data.split(':')
  if fun == 'register':
    [name, n] = [x.decode('base64') for x in params.split(',')]
    return register(name, n)
  elif fun == 'login':
    [name, n, sig] = [x.decode('base64') for x in params.split(',')]
    return login(name, n, sig)
  else:
    return 'bad function'

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    data = self.request.recv(1024)
    try:
      ret = process(data)
    except:
      ret = 'Error'
    self.request.sendall(ret + '\n') 

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
  pass

if __name__ == '__main__':
  server = ThreadedTCPServer(('0.0.0.0', PORT), ThreadedTCPRequestHandler)
  server.allow_reuse_address = True
  server.serve_forever()
```

This code implements a service with two functionalities: `register` and `login` which maps to `sign` and `verify`.
The user may ask to sign any name except _admin_ and get some signature. Then, a user can ask to login, providing the username and a signature to get some response from the system.

From the code above, the objective of the challenge is to pass the `verify` function on the _admin_ name and thus get the flag from the `login` function.

## The Dawn Of DSA

Going over the code, this looks like some signing algorithm which signs/verifies user's messages. A quick search comes up with a very similar algorithm: [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm).

Comparing DSA outline in wikipedia and the challenges' code, we see the following differences/peculiarities:

* r,s in the signature mustn't be zero in DSA, yet in the challenge they might be
* n, which does not exist in DSA, is used in the **beginning** of strings in the `makeK` and `makeMsg` functions
* k must be **random** per message, however it's computed with a hash function (deterministic)
* the hash function used for computing k - md5 - is insecure
* the message can be signed locally (no nonce/salt in the username hash)
* the signature `(r,s)` is encoded as ${(s + r*Q)^e mod\ n}$ where $e = 2^{16} + 1$

## Things That Didn't Work

The first implementation mistake seems very promising. Since we provide the signature to verify, it is very easy to pass a signature such that `r == 0`. Working the equations in the `verify` process, we get that:
$$u2 \equiv r * w = 0$$
$$v \equiv (G^{u1} * PUBLIC^{u2}) mod\ P\ mod\ Q \equiv G^{u1} * 1 mod\ P\ mod\ Q$$
Which completely eliminates the public/private component in the system.

So, in order to solve the challenge, all we need is to find a $u1$ and an integer $\alpha$ such that $Q$ divides $g^{u1}-\alpha * P$ so the comparison of `v` and `r` holds true ($v = G^{u1}\ mod\ P\ mod\ Q \equiv 0 = r$).

Unfortunately, finding this value is computationaly **hard**. We suspect it is equivalent to the discrete logarithm problem. Just to make sure, we wrote a small brute-force and let it run, but it didn't return any results.

We also thought maybe out 'name: admin' as part of `n`, and trick the server to sign a request the will hold for `name = 'admin'`, but it was impossible.

## Back On Track

Looking at the other implementation problems, we started wondering what happens if we generate the same K for different messages. Some digging online resulted with a short blog describing a [very simple attack](https://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/).
To implement this attack, we need the following:
* two messages - m1,m2 such that h(m1) != h(m2) yet k(m1) == k(m2)
* getting the hash, s and r of each of the messages

If we have all that, we can compute k as following:
$$k = ({h(m1) - h(m2)) * (s(m1) - s(m2))^{-1}\ mod\ Q}$$
and than, get the private key from the following formula:
$$PRIVATE = ((s(m1) * k) - h(m1)) * r^{-1}\ mod\ Q$$

After getting the private key, we can sign any message (since we know how to generate the hash for a message).
Note that even though we don't get the SECRET using this message, it doesn't matter because the only requirement from K is to be random and it's generation method is not used anywhere in the original algorithm.

## Hashes In Colide

The first step in our plan is to create a hash collision on k for two different messages.
Looking at the code, we see:

```python
k = int(hashlib.md5('K = {n: ' + n + ', name: ' + name + ', secret: ' + SECRET + '}').hexdigest(), 16)
```
We have no limitiations on `n`, so we can genearate an MD5 collision on `'K = {n: ' + n ` using [fastcoll](https://github.com/upbit/clone-fastcoll). Due to the [Merkle-Damgard construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction) of MD5, if the prefixes collide, adding the same suffix to both messages will also result in collision. Thus, the `SECRET` and limitations on `name` don't really bother us.

## Getting The Signature

Here we find ourselves in an uncharted territory. The register function returns ${(s + r*Q)^e mod\ n}$ where $e = 2^{16} + 1$ and we need to get the original $s,r$.

The solution was quite ineteresting. We can extend `n` as much as we want. Padding `n` with `\x00` bytes is, in-fact, multiplying `n` by $256$.  We note that $x\ mod\ nm\ mod\ m \equiv x\ mod\ m$ for any n,m.
So we pad our collision with enough `\x00` that eventually $2^{320} = 16^{40}$ divides $n$ (why 320? because $Q$ is 160 bit, thus $s + r*Q$ is at most $160*2$ bit)

Then, we send a _register_ request with some name and our `n`. Now, denote $sig := s + r*Q$, so the result is $sig^{e} mod\ n$. According to the fact above follows: $sig^{e} mod\ n\ mod\ 2^{320} = sig^{e} mod\ 2^{320}$. We compute $d \equiv e^{-1} mod\ \varphi (2^{320})$ (therefore exists $t$ such that $e*d - 1 = t * \varphi(2^{320})$). According to [Euler's Theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem) if $sig$ is odd ($sig,2^{320}$ are co-prime) then 
$$(sig^{e})^{d} \equiv sig^{e*d} \equiv sig * sig^{e*d - 1} \equiv sig * sig^{t * \varphi(2^{320})} \equiv sig * (sig^{\varphi(2^{320})})^t \equiv sig * 1^t \equiv sig $$.

And this is how we can extract the original $sig$.

If $sig$ is not odd, this fails miserably and $(sig^{e})^{d}$ will result in 0, giving us a good indication wether we extracted a valid signature or not.

## Executing The Attack

We take the hash collisions we found for the prefix 'K ={n: ' and extend it with 40 '\x00', denote it with n1,n2.
Then choose a name - 'a' and send _register_ requests to the server with name and n1,n2 and exponentiate the response by $e^{-1}\ mod\ \varphi(2^{320})$ and save it as sig1 and sig2.
If the responses are even, we try again with a different name.
We can verify we extracted the correct signatures by sending a _login_ request to the server with the signatures.
Then, we extract r and s for each signature and compute the hashes of the messages locally:
```python
r1, r2 = sig1 / Q, sig2 / Q ## in fact - the same value
s1, s2 = sig1 % Q, sig2 % Q
h1,h2 =  h(makeMsg(name, n1)), h(makeMsg(name, n2))
```
and then compute `k` and then the PRIVATE key:
```python
k = ((h1 - h2) * modinv(s1 - s2, Q)) % Q
PRIVATE = ((s1 * k - h(makeMsg(name, n1))) * modinv(r1, Q)) % Q
```
(the calculation of PRIVATE according to n1 and n2 are the same and correspond to the PUBLIC key)
Now, we can sign any name - including _admin_ :)
```python
n = '' ## doesn't matter
k = 1 ## doesn't matter
r = pow(G, k, P) % Q
s = (modinv(k, Q) * (h(makeMsg(name, n)) + PRIVATE * r)) % Q
admin_sig = r*Q + s
```

And that's it. We have a valid signature for `name = 'admin'` (with `n = ''`) and we can now login and get the flag.

## The Full Code

```python
from task import *
import socket

addr = ('pki.hackable.software',1337)
n1 = '3473610a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7c3252c8d653f6e08707032329bde4b960bb1d78477243b293a40be719aa5a4c4fcc1c3ecf420ec6b4a7623b775ac6620a109cef4bf74db4fa69d7bd7a12562acdbcd3fc9880790bd2da6f8a7634c34ac29f90101bae01cd5fb13c94c297d1eef9856de6c729741b1b3adefb01958ec1007653d0e62f792b618c57eea6bcdd9'
n2 = '3473610a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7c3252c8d653f6e08707032329bde4b960bb1578477243b293a40be719aa5a4c4fcc1c3ecf420ec6b4a7623b7f5ac6620a109cef4bf74db4fa69dfbd7a12562acdbcd3fc9880790bd2da6f8a7634c34ac29f98101bae01cd5fb13c94c297d1eef9856de6c729741b1b3adefb09957ec1007653d0e62f792b618c5feea6bcdd9'
n1 = (n1 + '00' * 40).decode('hex')
n2 = (n2 + '00' * 40).decode('hex')

name = 'c'

base = pow(2, 320)
e = 2 ** 16 + 1
d = modinv(e, base / 2)

## make sure we have a K collision
assert h(makeK(name,n1)) == h(makeK(name,n2))
assert h(makeMsg(name,n1)) != h(makeMsg(name,n2))

def b64(s):
	return s.encode('base64').replace('\n', '')

def make_register_req(name, n):
	params = ','.join([b64(p) for p in [name, n]])
	req = ':'.join(['register', params])
	return req

def make_login_req(name, n, sig):
	sig = hex(sig)[2:].strip('L')
	sig = ('\0' + sig) if (len(sig) % 2 == 1) else sig
	print 'sig:', sig
	sig = sig.decode('hex')
	params = ','.join([b64(p) for p in [name, n, sig]])
	req = ':'.join(['login', params])
	return req

def snd_rcv(req):
	s = socket.socket()
	s.connect(addr)
	print '>', req
	s.send(req)
	resp = s.recv(4096).strip()
	print '<', resp
	return resp

resp1 = snd_rcv(make_register_req(name, n1))
sig1 = pow(int(resp1), d, base)
assert snd_rcv(make_login_req(name, n1, sig1)) == 'Hello ' + name

resp2 = snd_rcv(make_register_req(name, n2))
sig2 = pow(int(resp2), d, base)
assert snd_rcv(make_login_req(name, n2, sig2)) == 'Hello ' + name


r1 = sig1 / Q
r2 = sig2 / Q
assert r1 == r2

s1 = sig1 % Q
s2 = sig2 % Q
assert s1 != s2

ds = (s1 - s2) % Q
inv_ds = modinv(ds, Q)

h1 = h(makeMsg(name, n1))
h2 = h(makeMsg(name, n2))

dh = (h1 - h2) % Q
k = (dh * inv_ds) % Q
inv_r1 = modinv(r1, Q)
inv_r2 = modinv(r2, Q)

PRIVATE1 = ((s1 * k - h(makeMsg(name, n1))) * inv_r1) % Q
PRIVATE2 = ((s2 * k - h(makeMsg(name, n2))) * inv_r2) % Q
inv_k = modinv(k,Q)
assert PRIVATE1 == PRIVATE2
PRIVATE = PRIVATE1
assert PUBLIC == pow(G, PRIVATE, P)

def my_sign(name, n):
  k = 1
  r = pow(G, k, P) % Q
  s = (modinv(k, Q) * (h(makeMsg(name, n)) + PRIVATE * r)) % Q
  return (r*Q + s)

n = ''
name = 'admin'
print snd_rcv(make_login_req(name, n, my_sign(name, n))) 
```
