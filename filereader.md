# file reader

#### Description:
```
hello guys, I started this new service check note.txt file for a sanity check 207.180.200.166 2324
```
#### Files:
reader.py
```python
import glob

blocked = ["/etc/passwd", "/flag.txt", "/proc/"]

def read_file(file_path):
    for i in blocked:
        if i in file_path:
                return "you aren't allowed to read that file"
    
    try:
        path = glob.glob(file_path)[0]
    except:
        return "file doesn't exist"
    
    return open(path, "r").read()

user_input = input("> ")
print(read_file(user_input))
```

#### Auther:
No Auther was mentioned foor this challenge.
#### Points and solvers:
At the end of the CTF, 77 teams solved this challenge and it was worth 459 points.

## Solution:
We need of course to print the content of the "/flag.txt" file, we cannot though because of the `blocked` list.   
The [`glob.glob`](https://docs.python.org/3/library/glob.html#glob.glob) function "can contain shell-style wildcards", 
what this means is that if we would write `/flag.tx*` the function will try to complete this pattern and match `/flag.tx*` with the file names in the system where `*` can be everything.   
Insert that and the flag will appear.

## Flag:
```
flag{oof_1t_g0t_expanded_93929}
```
