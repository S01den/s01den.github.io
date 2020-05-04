```C
  ____  ____  _____              _   
 / ___|/ ___|| ____|___ _ __ ___| |_ 
 \___ \\___ \|  _| / __| '__/ _ \ __|
  ___)  ___) | |__| (__| | |  __/ |_ 
 |____/|____/|_____\___|_|  \___|\__|
```
# SSEcret Writeup - FCSC French Pre-qualifier 2020
02/05/2020
par S01den (S01den@protonmail.com)

SSEcret est à ce jour le challenge qui m'aura donné le plus de fil à retordre, et c'est en tout cas celui qui m'a occupé le plus longtemps durant le CTF, c'est seulement après 3 jours de travail que j'ai pu faire cracher le flag à ce maudit programme.
Malgré tout c'est un challenge très intéressant qui m'aura permis de beaucoup progresser, notamment sur l'utilisation de radare2.
Alors allons y !
Qu'est-ce qu'on a au menu ?

## Description du challenge:
```
SSEcret:
500
reverse maths
Trouvez le secret qui affichera le flag.
```
C'est donc une épreuve de reverse engineering, qui contient une part non négligeable de mathématiques (ce qui signifie qu'elle sera soit très amusante, soit très embêtante)
```Python
solden@solden:~$ ./ssecret.bin
Usage: ./ssecret.bin <secret>
```
Classique, ce binaire nous demande de lui fournir un password en argument.
Ok, essayons d'y voir plus clair, ouvrons cela avec **Ghidra**.

## Analyse

Dans Ghidra, nous ne voyons à priori aucune trace du flag, mais une grosse partie du binaire contient des instructions qui ne signifient rien, à partir de **0x603c50**; probablement du code chiffré...

Le programme est constitué principalement de 3 fonctions, nous obtenons le pseudo-code de la fonction "**main**":
```C

undefined8 main(int param_1,undefined8 *param_2)

{
  char cVar1;
  undefined8 uVar2;
  ulong uVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 2) {
    uVar3 = 0xffffffffffffffff;
    pcVar4 = (char *)param_2[1];
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    uVar2 = FUNC_0x00400860((char *)param_2[1],~uVar3 - 1,&local_18);
    FUNC_0x00601050(uVar2,local_18);
  }
  else {
    __printf_chk(1,"Usage: %s <secret>\n",*param_2);
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
  __stack_chk_fail();
}

```
Dans cette fonction, nous voyons que la fonction "**0x00400860**" est appelée avec comme paramètre notre fameux secret.
Creusons de ce côté là...
Voici la partie "intéressante" du pseudo-code de la fonction:
```C
  do {
    local_128[(byte)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[lVar4]] =
         (char)lVar4;
    lVar4 = lVar4 + 1;
  } while (lVar4 != 0x40);
  if (len_secret != 0) {
    uVar5 = 0;
    pbVar6 = secret;
    do {
      if (local_128[*pbVar6] != -0x80) {
        uVar5 = uVar5 + 1;
      }
      pbVar6 = pbVar6 + 1;
    } while (secret + len_secret != pbVar6);
    if ((uVar5 != 0) && ((uVar5 & 3) == 0)) {
      __ptr = (byte *)malloc((uVar5 >> 2) * 3);
      if (__ptr != (byte *)0x0) {
        lVar4 = 0;
        iVar7 = 0;
        pbVar8 = __ptr;
LAB_00400999:
        do {
          bVar2 = *secret;
          if (local_128[bVar2] != -0x80) {
            local_12c[lVar4] = local_128[bVar2];
            lVar4 = lVar4 + 1;
            iVar7 = iVar7 + (uint)(bVar2 == 0x3d);
            if (lVar4 == 4) {
              *pbVar8 = local_12c[1] >> 4 | local_12c[0] * '\x04';
              pbVar8[1] = local_12c[1] << 4 | local_12c[2] >> 2;
              pbVar1 = pbVar8 + 3;
              pbVar8[2] = local_12c[2] << 6 | local_12c[3];
              if (iVar7 != 0) {
                if (iVar7 == 1) {
                  pbVar8 = pbVar8 + 2;
                }
                else {
                  if (iVar7 != 2) {
                    free(__ptr);
                    goto LAB_00400a44;
                  }
                  pbVar8 = pbVar8 + 1;
                }
                break;
              }
```
Cela peut paraître à première vue un peu... indigeste, mais il s'agit en réalité d'une fonction très simple que nous connaissons déjà: le décodage de **base64**.
Ce qui m'a mit la puce à l'oreille c'est le "cmp r8b, 0x3d" (iVar7 = iVar7 + (uint)(bVar2 == 0x3d); dans le pseudo-code), une comparaison avec le signe "=", j'ai donc essayé et en debuggant j'ai vu que mon secret était bien décodé.

Maintenant, si la fonction de décodage de base64 parait rebarbative, je n'étais pas au bout de mes peines en observant le contenu de la fonction la plus importante du binaire, dont vous avez un echantillon ci dessous.

```C
  encrypted = (undefined *)0x603c50;
  if (0xf < param_2) {
                    /* WARNING: Load size is inaccurate */
    in_XMM0 = *(undefined *)param_1;
    auVar7 = pinsrq(ZEXT816(0),0x8000000000000000,1);
    xmm3 = pinsrq(ZEXT816(0xdcd26c8c431d185),0x9cbf4b9eb8ff5fd5,1);
    uVar2 = vmovq_avx(xmm3 & in_XMM0);
    uVar4 = vpextrq_avx(xmm3 & in_XMM0,1);
    uVar3 = popcnt(uVar2);
    uVar5 = popcnt(uVar4);
    xmm3 = (undefined  [16])0x0;
    if ((uVar3 & 1) != (uVar5 & 1)) {
      xmm3 = auVar7;
    }
```
La première chose qui saute aux yeux, c'est que la taille de notre input, une fois décodé, doit être de plus de 16 caractères.
Mais il reste quelque chose d'étrange.
"**popCNT**", "**pinsrq**" ou encore "**vmovq_avx**". 
Qu'est ce que c'est que ça ?
Les instructions présentes ne sont pas habituelles, et c'est de là que l'épreuve tire son nom, en effet ce que nous avons là ce sont des **SSE Instructions** (pour Streaming SIMD Extensions)
Cela permet l'utilisation de nombres codés sur **128 bits** dans les registres "xmm".

En regardant d'un oeil plus attentif, on peut voir qu'il y a au total **128 blocs** comme celui montré ci dessus.
Ces instructions:
```C
    xmm3 = pinsrq(ZEXT816(0xdcd26c8c431d185),0x9cbf4b9eb8ff5fd5,1);
    uVar2 = vmovq_avx(xmm3 & in_XMM0);
    uVar4 = vpextrq_avx(xmm3 & in_XMM0,1);
```
permettent de mettre le registre xmm3 à **0x9cbf4b9eb8ff5fd50dcd26c8c431d185** (un nombe de **128 bits**)
puis d'effectuer un "**AND**" logique entre **xmm3** et **xmm0**, qui contient notre input décodé.

Après cette opération, selon le nombre de bits sets à 1 du résultat est comparé, afin de générer un bit:
```C
    uVar3 = popcnt(uVar2);
    uVar5 = popcnt(uVar4);
    if ((uVar3 & 1) != (uVar5 & 1)) {
      xmm3 = xmm3 ^ xmm2;
    }
```
Ainsi, chaque bloc génére un bit d'un nombre de 128 bit (stocké dans le registre **xmm3**) qui sera à la fin comparé à **0x62e9eed78a671820f72389798f7ca4f4**
Comme nous pouvons le voir ici:
```C
MOV        RAX,-0x8dc768670835b0c
MOV        RBX,0x62e9eed78a671820
MOVQ       XMM4,RAX
PINSRQ     XMM4,RBX,0x1
PCMPEQD    xmm3[0],XMM4
```
Viennent alors des instructions AES pour déchiffrer une partie du binaire:
```C
    auVar7 = aeskeygenassist(in_XMM0,1);
    uVar6 = SUB164(auVar7 >> 0x60,0);
    auVar7 = pslldq(in_XMM0,4);
    xmm2 = pslldq(auVar7,4);
    auVar8 = pslldq(xmm2,4);
    auVar7 = in_XMM0 ^ auVar7 ^ xmm2 ^ auVar8 ^
             CONCAT412(uVar6,CONCAT48(uVar6,CONCAT44(uVar6,uVar6)));
```
Cependant, pas besoin de nous y attarder, si le secret est bon, le déchiffrement s'opérera naturellement.

Bon, c'est maintenant le moment de réfléchir, ce qui veut dire que c'est l'heure des maths !

## Quick maths
*Two plus two is four. Minus one, that's three, quick maths*
*-Big Shaq 2017-*

Si on résume, on a 128 nombres de 128 bits générant après un AND logique un autre nombre, qui est comparé à la fin à une clé
Mais ! Serait-ce ?! Non... Si ! Une  équation matricielle contenant une  **matrice carrée** d'ordre **128** (les 128 nombres venant des blocs), et **deux vecteurs colonnes**  d'ordre 128 également (la clé finale et notre input)
En effet, en modélisant le problème de cette façon, on aborde les valeurs qui nous apparaissent en hexadécimal dans le code comme des bits, des 1 ou des 0; or ces deux nombres constituent les éléments de **l'anneau Z/2Z**.

Je ne vais pas rentrer dans les détails de ce qu'est un anneau en mathématiques, voyez ça comme un ensemble munis de deux opérations, en l'occurence l'addition et la multiplication.

Dans **Z/2Z**, l'addition et la mutiplication sont simples, il s'agit respectivement du **XOR** et du **AND**.
En voyant le problème comme ça, tout deviens plus clair: les "AND" qu'on observait ici: 
```C
    uVar2 = vmovq_avx(xmm3 & in_XMM0);
    uVar4 = vpextrq_avx(xmm3 & in_XMM0,1);
```
Sont au final une multiplication entre la ligne de la matrice et celle du vecteur colonne (c'est à dire du n_ième bit de notre input décodé).

Cela nous amène à cette équation:
$$M*INPUT = KEY$$
Où **M** est la matrice carrée d'ordre 128, **INPUT** le vecteur colonne inconnu (le bon input à fournir au programme pour que la comparaison soit bonne) et **KEY** le vecteur colonne de la clée comparée à la fin.
Pour résoudre cela, il suffit simplement de calculer:
$$INPUT = M^-1 * KEY$$
**SageMath** résous ça facilement, il suffit de faire un 
``input = M.solve_right(key)``

## Let's get the flag !
Malheureusement le chall ne se finit pas là, bien au contraire...
En fait il vient juste de commencer, il faut maintenant automatiser tout ce processus car il y a plus d'un bloc à déchiffrer, bien plus d'un...
Et chaque bloc déchiffré forme la même équation, mais avec des nouvelles valeurs.
Un verre d'eau (avec en option un doliprane), une petite pause et c'est reparti !
Pour automatiser cela j'ai utilisé radare2 avec les options de debug, grâce à la lib r2pipe.

Mon script parcourt les blocs un à un pour relever les valeurs de la matrice, jusqu'à la comparaison, où la clée se situe.
Une fois les valeurs enregistrée, il utilise la console de sage, à travers pwntools, pour calculer (et enregistrer) la valeur du bon secret pour déchiffrer la portion suivante; et ce en boucle jusqu'à ce que la dernière portion soit déchiffrée.

Voici donc sans plus attendre le fameux script (attention les yeux, c'est très sale):
```Python
import r2pipe
from pwn import *

def sage(matrix, check_key):
    r = process("./sage")

    r.recvuntil("sage:")

    r.sendline("a = ["+",".join([hex(_) for _ in matrix])+"]")
    r.recvuntil("sage:")

    r.sendline("MS = MatrixSpace(GF(2),128,128)")
    r.recvuntil("sage:")

    r.sendline("M = MS([list(bin(_)[2:].zfill(128)) for _ in a])")
    r.recvuntil("sage:")

    r.sendline("key = vector(GF(2), list(bin("+hex(check_key)+")[2:].zfill(128)))")
    r.recvuntil("sage:")

    r.sendline("input = M.solve_right(key)")
    r.recvuntil("sage:")

    r.sendline("input")

    solution_binary_raw = r.recvuntil("sage:")

    r.sendline("exit")

    solution = hex(int("".join(solution_binary_raw.split("(")[1].split(")")[0].split(", ")),2))[2:].replace("L", "")

    return solution

def align_128(x):
	if(len(x) < 18):
		return (x[:2]+"0"*(18-len(x))+x[2:])
	else:
		return x

def cont():
    print(r.cmd('dc'))


def step_out():
    print(r.cmd('dcr; ds'))


def breakpoint(addr):
    print(r.cmd('db ' + addr))


def get_esp():
    return r.cmdj('drj')['esp']


def get_eip():
    return r.cmdj('drj')['eip']

def next_i():
	cmdDisas = "ds;sr rip"
	return r.cmd(cmdDisas)

def get_curr_addr():
	return r.cmd("s")

def seek_next():
	return r.cmd("so 1")

def calculateKey():
	nbr_data = 0
	hex_data = []
	count = 0
	instNbr = 0
	opcode = ""
	s = ""
	while(opcode != "pcmpeqd xmm3, xmm4"):
		seek_next()

		instruction = r.cmdj('pdj 1')
		instruction = instruction[0]
		opcode = instruction['opcode']
		#print(opcode)

		if('movabs' in opcode and ("rax" in opcode or "rbx" in opcode) and "0x" in opcode and "0x8000000000000000" not in opcode):
			if("rbx" in opcode):
				count += 1
				s += align_128(opcode[12:])
			if("rax" in opcode):
				count += 1
				s += align_128(opcode[12:])[2:]
			if(count == 2):
				s = s[16:]+s[:16]
				#print(s)
				count = 0
				hex_data.append(int(s,16))
				nbr_data+=1
				s = ""

	if(nbr_data != 129):
		print("SOmething bad happened...")	

	key = hex_data[len(hex_data)-1]
	#key = binbits(key,128)[2:]
	print("Key = ",key)

	return(sage(hex_data[:len(hex_data)-1],key))


keyList = open("keys.txt","w")
begin = 0x00601055
addrAfterSyscall = 0x006039f3
addrJE = 0x00603c45
addrEncrypted = 0x00603c50
addrBrk = 0x00603c69

#eqFUxbL2zNoSFXuPo3P64A==

r = r2pipe.open("./ssecret.bin", ["-d", 'rarun2', 'program=ssecret.bin', 'arg1=eqFUxbL2zNoSFXuPo3P64A=='])
cont()
breakpoint("0x0040058f")
cont()
next_i()


keyComputed = calculateKey()
print()
keyList.write(keyComputed+"\n")

breakpoint(str(hex(addrAfterSyscall))) # addr after the "syscall" += 
addrAfterSyscall += 0x2c00        
cont()

breakpoint(str(hex(addrJE))) # addr of JE 
cont()

breakpoint(str(hex(addrEncrypted))) # addr of encryted block
addrEncrypted += 0x2c00
cont()

bpRem = "db -"+str(hex(addrJE))
r.cmd(bpRem)
addrJE += 0x2c00
cont()
next_i()

r.cmd("dr rsi = 0x10")

for i in range(140):
	print("block number",i)

	breakpoint(str(hex(addrBrk)))
	addrBrk += 0x2c00
	cont()


	keyComputed = calculateKey()
	if(len(keyComputed) != 32):
		keyComputed = "0"*(32-len(keyComputed))+keyComputed
	print(keyComputed)
	keyList.write(keyComputed+"\n")

#b605ce87afae7e2a013ea98d6dfa5d6c

	packet = ""
	packet += keyComputed[len(keyComputed)-2]
	packet += keyComputed[len(keyComputed)-1]
	packet += keyComputed[len(keyComputed)-4]
	packet += keyComputed[len(keyComputed)-3]
	packet += keyComputed[len(keyComputed)-6]
	packet += keyComputed[len(keyComputed)-5]
	packet += keyComputed[len(keyComputed)-8]
	packet += keyComputed[len(keyComputed)-7]
	changeRegister = "wx 0x" + packet + " @ rdi"
	r.cmd(changeRegister)
	packet = ""
	packet += keyComputed[len(keyComputed)-10]
	packet += keyComputed[len(keyComputed)-9]
	packet += keyComputed[len(keyComputed)-12]
	packet += keyComputed[len(keyComputed)-11]
	packet += keyComputed[len(keyComputed)-14]
	packet += keyComputed[len(keyComputed)-13]
	packet += keyComputed[len(keyComputed)-16]
	packet += keyComputed[len(keyComputed)-15]
	changeRegister = "wx 0x" + packet + " @ rdi+4"
	r.cmd(changeRegister)
	packet = ""
	packet += keyComputed[len(keyComputed)-18]
	packet += keyComputed[len(keyComputed)-17]
	packet += keyComputed[len(keyComputed)-20]
	packet += keyComputed[len(keyComputed)-19]
	packet += keyComputed[len(keyComputed)-22]
	packet += keyComputed[len(keyComputed)-21]
	packet += keyComputed[len(keyComputed)-24]
	packet += keyComputed[len(keyComputed)-23]
	changeRegister = "wx 0x" + packet + " @ rdi+8"
	r.cmd(changeRegister)
	packet = ""
	packet += keyComputed[len(keyComputed)-26]
	packet += keyComputed[len(keyComputed)-25]
	packet += keyComputed[len(keyComputed)-28]
	packet += keyComputed[len(keyComputed)-27]
	packet += keyComputed[len(keyComputed)-30]
	packet += keyComputed[len(keyComputed)-29]
	packet += keyComputed[len(keyComputed)-32]
	packet += keyComputed[len(keyComputed)-31]
	changeRegister = "wx 0x" + packet + " @ rdi+12"
	r.cmd(changeRegister)

	breakpoint(str(hex(addrAfterSyscall))) # addr after the "syscall" += 
	addrAfterSyscall += 0x2c00        
	cont()

	breakpoint(str(hex(addrJE))) # addr of JE 
	cont()

	breakpoint(str(hex(addrEncrypted))) # addr of encryted block
	addrEncrypted += 0x2c00
	cont()

	bpRem = "db -"+str(hex(addrJE))
	r.cmd(bpRem)
	addrJE += 0x2c00
	cont()
	next_i()

	r.cmd("dr rsi = 0x10")
```
Une fois l'execution du script terminée (au bout de quelques dizaines de minutes...), notre fichier contenant toutes les valeurs hexadecimales des bons secrets de chaque bloc est disponible, il suffit alors de les regrouper bout à bout et d'encoder tout ça en base64.
On relance le crackme avec ça et on obtient enfin le flag !
```Python
./ssecret.bin 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
Well done! Here is the flag: FCSC{b0f6cfda0049a03d65d6b9e3e3ecf5b990c24ffe27784b7d553fcdc2f45a8ad4}
```

## Conclusion
C'est ainsi qu'on empoche les 500 points du challenge; et que ce termine ce WriteUp.
Merci à \J pour cette épreuve très amusante !
