# Delegate wallet

#### Description:
```
I have been using this software for generating crypto wallets. I think if I was able to predict the next private key, I could probably steal the funds of other users.

EU instance: 161.97.176.150 4008

US instance: 185.172.165.118 4008
```
#### Files:
wallet.py

```python
import os
import socketserver
import string
import threading
from time import *
import time
import binascii
import random

flag = open("flag.txt", "rb").read().strip()

class prng_lcg:

    def __init__(self):
        self.n = pow(2, 607) -1 
        self.c = random.randint(2, self.n)
        self.m = random.randint(2, self.n)
        self.state = random.randint(2, self.n)

    def next(self):
        self.state = (self.state * self.m + self.c) % self.n
        return self.state

class Service(socketserver.BaseRequestHandler):

    def handle(self):
        RNG = prng_lcg()
        while True:
            self.send("1) Generate a new wallet seed")
            self.send("2) Guess the next wallet seed")
            choice = self.receive("> ")
            print(choice)
            if choice == b'1':
                self.send(str(RNG.next()))
            elif choice == b'2':
                guess = int(self.receive("> ").decode())
                if guess == RNG.next():
                    self.send(flag)
                else:
                    self.send("Nope!")

    def send(self, string, newline=True):
        if type(string) is str:
            string = string.encode("utf-8")

        if newline:
            string = string + b"\n"
        self.request.sendall(string)

    def receive(self, prompt="> "):
        self.send(prompt, newline=False)
        return self.request.recv(4096).strip()


class ThreadedService(
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
    socketserver.DatagramRequestHandler,
):
    pass


def main():

    port = 4008
    host = "0.0.0.0"

    service = Service
    server = ThreadedService((host, port), service)
    server.allow_reuse_address = True

    server_thread = threading.Thread(target=server.serve_forever)

    server_thread.daemon = True
    server_thread.start()

    print("Server started on " + str(server.server_address) + "!")

    # Now let the main thread just wait...
    while True:
        sleep(10)


if __name__ == "__main__":
    main()
```

#### Auther:
Soul
#### Points and solvers:
At the end of the CTF, 71 teams solved this challenge and it was worth 465 points.

## Solution:

First of all, let's clean that code - it contains server stuff that is irrelevant to us:

```python
import os
import socketserver
import string
import threading
from time import *
import time
import binascii
import random

flag = open("flag.txt", "rb").read().strip()

class prng_lcg:

    def __init__(self):
        self.n = pow(2, 607) -1 
        self.c = random.randint(2, self.n)
        self.m = random.randint(2, self.n)
        self.state = random.randint(2, self.n)

    def next(self):
        self.state = (self.state * self.m + self.c) % self.n
        return self.state

RNG = prng_lcg()
while True:
    self.send("1) Generate a new wallet seed")
    self.send("2) Guess the next wallet seed")
    choice = self.receive("> ")
    print(choice)
    if choice == b'1':
        self.send(str(RNG.next()))
    elif choice == b'2':
        guess = int(self.receive("> ").decode())
        if guess == RNG.next():
            self.send(flag)
        else:
            self.send("Nope!")
```

This is nicer. Now we see that we can generate a new seed - option 1 or we can guess the new seed - option 2, if we succeed we get the flag.   
The name of the function that generates the seeds called `prng_lcg` - a `lcg` is a [`Linear congruential generator`](https://en.wikipedia.org/wiki/Linear_congruential_generator)
and it is unsafe, it appears that using a pen and paper we can predict the next number.

Let's take 3 seeds from the server and call them `s1`, `s2` and `s3`. Now write `s2` and `s3` as a function of `s1`, `s2`, `c`, `m`, `n`:
= ((s1 * m + c) * m + c) % n = (s1 * m * m + c * m + c) % n
```
s2 = (s1 * m + c) % n
s3 = (s2 * m + c) % n 
```
`m` and `c` are the only two parameters we do not know in these equations - we have two equations with two parameters, let's simplify that:
```
s2 - s1 * m = c % n
s3 - s2 * m = c % n

s2 - s1 * m = s3 - s2 * m % n
s2 - s3 = s1 * m - s2 * m % n
s2 - s3 = (s1 - s2) * m % n
(s2 - s3) / (s1 - s2) = m % n
```
Awesome - we can calculate `m`! Once we know `m` just put it in one of the first equations and we will know `c` as well, and once we also know `c` we can easly calculate `s4`.    
Note that this is not a real division, since we are uner a finite field (module `n`) this is acutall multipling by the inverse of `(s1 - s2)`.

### Solution Code:
```python
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



s1 = 218938461323895569921115633648418966539571486170478785862264203996978269091395347765886630029952567881444657422342493768766050168087793902109378055588445059510453936507447004586534925
s2 = 433361185786481276360491616006724395919669309745646122570934960031956841654449931009448691601128913477289285712098780268872043119937154923052768918289171555608608361093538139103503876
s3 = 12831025342291268037915091642369375488556080108863259142478771087950396499592076555863031197803965224100400575779286156704477686476699016159544785204495338931642799818807215798813739

n = pow(2, 607) - 1
m = ((s3 - s2) * modinv(s2 - s1, n)) % n
c = (s2 - s1 * m) % n
assert s2 == (s1 * m + c) % n
assert s3 == (s2 * m + c) % n

s4 = (s3 * m + c) % n
print(s4)
```
### Flag:
```
The server went down after the event closed.
```
