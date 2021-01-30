# eazy RSA

#### Description:
```
c = 3708354049649318175189820619077599798890688075815858391284996256924308912935262733471980964003143534200740113874286537588889431819703343015872364443921848
e = 16
p = 75000325607193724293694446403116223058337764961074929316352803137087536131383
q = 69376057129404174647351914434400429820318738947745593069596264646867332546443
```
#### Auther:
Soul
#### Points and solvers:
At the end of the CTF, 85 teams solved this challenge and it was worth 445 points.

## Solution:
In RSA encryption scheama in order to encrypt the data we take the `message` and raise it to the `power of e` modules `n`, where `n = p * q`. 
In order to decrypt it we take the cipher and raise it to the `power of d` modules `n`.   
So the stright forward solution is to calculate `d` which is the [modular inverse](https://cp-algorithms.com/algebra/module-inverse.html#:~:text=Practice%20Problems-,Definition,inverse%20does%20not%20always%20exist.) 
to `e` under `phi(n) = (p - 1) * (q - 1)` and can be found using the following code:

```python
def egcd(a, b):
    # extended Euclidean algorithm
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
```

But the result of `modinv(e, (p - 1) * (q - 1))` is `modular inverse does not exist`!

Why is this happening? When a number `a` is not [coprime](https://en.wikipedia.org/wiki/Coprime_integers#:~:text=In%20number%20theory%2C%20two%20integers,both%20of%20them%20is%201.&text=This%20is%20equivalent%20to%20their,a%20reduced%20fraction%20are%20coprime.) 
to `n` than more than one number `b` can setisfy the equation: `a * b mod n == 1`, [this cryptography stackexchange post](https://crypto.stackexchange.com/questions/12255/in-rsa-why-is-it-important-to-choose-e-so-that-it-is-coprime-to-%CF%86n)
explains why is it bad.

So now what do we do? Notice that `e = 16` that means that if we were able to take a square root of `c` 4 times we would be able to recive the flag!   
Finding sqaure root can be done using the [Tonelli Shanks algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm), the boot2root ctf had a similar challenge called brokenRSA, here is a [nice writeup](https://github.com/MehdiBHA/b00t2root-2020-Crypto-Challenges#challenge-4--brokenrsa) for it, lets take the `find_square_roots` function from there and modify it a bit:

```python
def legendre(a, p):
    return pow(a, (p - 1) // 2, p)


def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r


def find_square_roots(c, n, e):
    if e == 1:
        return [c]

    elif pow(c, (n - 1) // 2, n) != 1:
        return []

    else:
        rt1 = tonelli(c, n)
        res1 = find_square_roots(rt1, n, e // 2)
        rt2 = n - rt1
        res2 = find_square_roots(rt2, n, e // 2)
        return res1 + res2
```

Problem with that is that we are only able to apply this algorithm if `n` is prime, so this would not work right away. 
What we can do is use the [Chinese remainder theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem), 
the theorem says that only one solution `x` mudules `n` exist for the set of equations `x = a1 mod p` and `x = a2 mod q`, lets rewrite these formulas - `m ^ 16 = a1 mod p` and `m ^ 16 = a2 mod q` where we know `a1` and `a2`.   
So now we can take a square root for `c` under `q` and then under `p`, and get `m = a1 ^ (1/16) mod p` and `m = a2 ^ (1/16) mod q`, now we can reconstruct `m` using the chinese remainder theorem reconstruction:

Find `m1` and `m2` such that `m1 * p + m2 * q = 1`, this can be done using the [extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) (the `egcd` function in our code).   
`x = a1 ^ (1/16) * m2 * q + a2 ^ (1/16) * m1 * p`

Side Note: there is more then one square root for each number and that is why the function outputs an array, it is possible we would need to iterate all combinations of `sq_a1` and `sq_a2`
```python
from Crypto.Util.number import long_to_bytes

n = p * q
_, m1, m2 = egcd(p, q)

sq_a1 = find_square_roots(a1, n1, 16)
sq_a2 = find_square_roots(a2, n2, 16)
print(sq_a1)
for s in sq_a1:
    assert pow(s, 16, p) == a1
print(sq_a2)
for s in sq_a2:
    assert pow(s, 16, q) == a2

new_sq = sq_a1[0] * m2 * q + sq_a2[0] * m1 * p
new_sq = new_sq % n
print(new_sq)
assert pow(new_sq, 16, n) == c
print(long_to_bytes(new_sq))
```

### Flag:
```
flag{d0nt_h4v3_4n_3v3n_3_175_34sy!!!}
```

