''' Author: Michael Abramzon.
I used a full batch of information instead of empty fields.
rng-tools are really important if you want it done fast.
'''

import gnupg
import requests

gpg = gnupg.GPG()

email = "<CYBER>!"
passphrase = 'sekrit'
batch = { 'name_real': '',
    'name_email': email,
    'expire_date': '2017-05-05',
    'key_type': 'RSA',
    'key_length': 1024,
    'key_usage': '',
    'subkey_type': 'RSA',
    'subkey_length': 1024,
    'subkey_usage': 'encrypt,sign,auth',
    }
input_data = gpg.gen_key_input(**batch)
key = gpg.gen_key(input_data)

ascii_armored_public_keys = gpg.export_keys(key)
ascii_armored_private_keys = gpg.export_keys(key, True)
with open('mykeyfile.asc', 'w') as f:
    f.write(ascii_armored_public_keys)

multipart_form_data = {
    'gpg_file': open('mykeyfile.asc', 'rb')
}

response = requests.post('http://104.198.80.195/public/', files=multipart_form_data)

str1 = response.content
start = str1.find("<div") + 20
finish = str1.find("</div>") - 1
reply = str1[start:finish]

if "PGP" in reply:
    print "#### Decrypted Reply from Server ####"
    print str(gpg.decrypt(reply))
else:
    print "@@@@ Plain Text Reply from Server @@@@"
    print reply
