# ______________________________________________
#[                                              ]
#[   A SOLUTION FOR THE BAGEYELET'S "ROP-OBF"   ]
#[            CRACKME	   	                ]
#[                                              ]
#[  By S01den			  		]
#[  S01den@protonmail.com	               	]
#[_________________________________13/09/2019___]


#Hey my fellow crackers !
#This is my -very dirty- solution for the bageyelet's crackme from crackmes.one (https://crackmes.one/crackme/5cfb961a33c5d41c6d56e069).

#-------------------------------------------------------------------------------------------------
#Author:
#bageyelet

#Language:
#Assembler

#Upload:
#11:03 AM 06/08/2019

#Level:
#3

#Platform
#Unix/linux etc.

#Description
#The goal is to print "1" at screen by providing the correct password. No patching is allowed.
#-------------------------------------------------------------------------------------------------


# When we open it with radare2 and disassemble at the entrypoint, we found a serie of push instructions.
# The name of the crackme refers to this technique, ROP means Return Oriented Programming (it's an exploitation technique), in fact some addresses
# and arguments are pushed in the stack with the serie of push until a ret instruction. RET is an equivalent of POP EIP, so when the program execute 
# this instruction, he sets EIP at the address on the top of the stack.
# On this crackme, the ROP technique permits to obfuscate by shuffling the instructions, however I didn't desobfuscate...

# In fact, by debugging, I found an interesting comparaison on 0x5655607f (cmp    edi,esi) where edi is our number transformed by an algorithm 
# (different for the 6 inputs) and esi is the correct number.
# As I said, I didn't desobfuscate, so I made some tests with value from 0 to 16 on each inputs and I deduced the differents algorithms and I code a solver.

# With my solver, I found the correct password:
# 4
# 8
# 15
# 16
# 23
# 42

# Thanks a lot for this very interesting and original crackme bageyelet !

# ------------------------------------------------------------------ AND NOW, THE SOLVER ! ------------------------------------------------------------------

#print("------------ STEP 1 ------------")

graine = 0x83
nbr = 0
c = 1

while nbr < 50:
	if(graine == 0x87):
		print(nbr)
		break

	graine-=1
	nbr+=1
	c+=1
	if(c == 5):
		c = 1
		graine += 8

#print("------------ STEP 2 ------------") 

graine = 0x36
nbr = 0
c = 1

while nbr < 50:
	if(graine == 0x3e):
		print(nbr)
		break

	graine-=1
	nbr+=1
	c+=1
	if(c == 5):
		c = 1
		graine += 8

#print("------------ STEP 3 ------------") 

graine = 0x9d
nbr = 0
c = 1
counter = 0

while nbr < 50:
	if(graine == 0x92):
		print(nbr)
		break

	graine-=1
	nbr+=1
	c+=1
	if(c == 3):
		counter += 1
		c = 1
		if(counter%2 != 0):
			graine += 4
		else:
			graine -= 4


#print("------------ STEP 4 ------------") 

graine = 0xcd
nbr = 0
c = 1
d = 1
counter = 0

while nbr < 50:
	if(graine == 0xdd):
		print(nbr)
		break

	graine-=1
	nbr+=1
	c+=1
	d+=1
	if(c == 3):
		counter += 1
		c = 1
		if(counter%2 != 0):
			graine += 4
		else:
			graine -= 4

	if(d == 17):
		graine += 0x20
		d = 1


#print("------------ STEP 5 ------------")

graine = 0xec
nbr = 0
c = 1
d = 1

while nbr < 50:
	if(graine == 0xfb):
		print(nbr)
		break

	graine+=1
	nbr+=1
	c+=1
	d+=1
	if(c == 5):
		c = 1
		graine -= 8
	if(d == 17):
		graine += 0x20
		d = 1

#print("------------ STEP 6 ------------") 

graine = 0xf6
nbr = 0
c = 1
d = 1

while nbr < 50:
	if(graine == 0xdc):
		print(nbr)
		break

	graine+=1
	nbr+=1
	c+=1
	d+=1
	if(c == 3):
		c = 1
		graine -= 4

	if(d == 25):
		d = 1
		graine+=0x10
