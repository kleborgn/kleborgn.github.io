# Pre-prechall

J'ai vu sur Discord qu'il y avait un prechall bonus avant le début du CTF. J'ai cherché sur le site et dans le code source mais je n'ai rien trouvé. Je me suis demandé si il n'y avait pas déjà eu un challenge similaire les années précédentes et j'ai trouvé un writeup écrit par "Xenos" sur son [blog](https://blog.reinom.com/story/ctf/fcsc2022/welcome/prechall/).

En 2022, le début du challenge était donc caché dans le logo sur la page d'accueil. Après un passage sur [Aperi'Solve](aperisolve.com), le logo n'a pas l'air de cacher quelque chose.

A la fin du writeup, on peut voir que le flag était à soumettre à l'adresse https://france-cybersecurity-challenge.fr/teasing. Et cette année c'est à cette adresse que se trouve le début du prechall!

# Puzzle

![[Pasted image 20230416151416.png]]

On peut voir que l'image a été divisée par 4x11 blocs puis mélangée. En essayant d'assembler le texte, on peut deviner "FCSC 2023", "Challenge" et "LSB stegano". Effectivement, en passant l'image sur  [Aperi'Solve](aperisolve.com) ou `zsteg` on peut voir qu'il y a des données cachées: 

![[Pasted image 20230416152130.png]]

```
**imagedata .. text:** "...222 "**  
b4,r,lsb,xy .. text:** "'vdUTETB\"DEUFUEGf"**  
b4,r,msb,xy .. text:** "&D\"ff&\"bf\"D\"\"\"VG"**  
b4,g,lsb,xy .. text:** "6guETDDB3UTDWUDGg"**  
b4,g,msb,xy .. text:** "\"U533SUU3w7SU3www3w"**  
b4,b,lsb,xy .. text:** "7wuETUUR3UDUVDTFvL"**  
b4,b,msb,xy .. text:** "s FR@0af"**  
b4,rgb,lsb,xy .. text:** "##7gvvwgtUTEUUTDDUETTEDR\"#23ETUEEDTUEEVvUETDUDDGvfvvwO"**  
b4,bgr,lsb,xy .. text:** "%3'gvwvweTDUUUTDTEETUDTB\"3#2UETEDETUEUFvETUTDEDFwvfvG|"
```

On voit que les données cachées ne sont pas continues et ont donc aussi été mélangées. J'ai donc commencé par ouvrir l'image sur Paint, numéroté tous les blocs puis j'ai résolu le puzzle:

![[teaser_solved 1.png]]

J'ai ensuite écrit un script Python pour remettre l'image dans l'ordre proprement:

```python
from PIL import Image
import numpy as np

im = Image.open("teaser.png")

width, height = im.size

col = 5
row = 11

init_order = []

order = np.array([[40, 38, 33, 37, 25],

        [22, 41, 1, 54, 50],

        [32, 52, 55, 42, 43],

        [8, 13, 11, 3, 44],

        [30, 23, 49, 48, 39],

        [28, 29, 9, 45, 21],

        [27, 46, 14, 17, 53],

        [12, 18, 24, 35, 34],

        [15, 4, 19, 36, 51],

        [2, 5, 6, 10, 31],

        [26, 47, 7, 20, 16]])

order -= 1 # I started indexing the pieces with 1 instead of 0

for i in range(row):
    for j in range(col):
        piece = im.crop((j*(width/col), i*(height/row), j*(width/col) + (width/col), i*(height/row) + (height/row)))
        init_order.append(piece)

# Get the size of each block

image_width, image_height = init_order[0].size

# Create an empty image to store the final result

final_image = Image.new(mode='RGB', size=(col * image_width, row * image_height))

# Iterate through the array and paste each block into the final image

for r in range(row):
    for c in range(col):
        x = c * image_width
        y = r * image_height
        final_image.paste(init_order[order[r, c]], (x, y))

# Save and show the final image

final_image.save('output.png')
final_image.show()
```

Ce qui donne:

![[output.png]]
(sympa les costumes, ça doit pas être très pratique pour taper au clavier)

En passant l'image dans `zsteg` on obtient:

```
$ zsteg output.png
imagedata           .. text: "\"!%*+*%$$"
b1,g,msb,xy         .. text: "QUQUUUUUUQUUU1*J{"
b1,b,lsb,xy         .. text: "DDTDUUUUDUUUUEb\"-i"
b1,rgb,lsb,xy       .. file: PNG image data, 500 x 666, 8-bit/color RGB, non-interlaced
b1,bgr,lsb,xy       .. text: ["U" repeated 13 times]
b1,bgr,msb,xy       .. file: OpenPGP Secret Key
b2,g,msb,xy         .. text: "2www\"6rb\"&\"wwW\"rw'\"\"w"
b2,b,msb,xy         .. file: OpenPGP Secret Key
b2,bgr,msb,xy       .. text: " sUUUU]UEQ"
b4,r,lsb,xy         .. file: OpenPGP Secret Key
b4,r,msb,xy         .. text: "$\"\"b\"\"\"\"\"\"\"\"\""
b4,g,lsb,xy         .. text: "gtDETTTEED\"\"\"\"\"\"UTh"
b4,g,msb,xy         .. text: "DDDDDDDD**LL"
b4,b,lsb,xy         .. text: "\"\"\"\"\"\"#\"DE#2%VgwwvggUUh"
b4,b,msb,xy         .. text: "]U;3;U]3]"
b4,rgb,lsb,xy       .. file: OpenPGP Secret Key
b4,rgb,msb,xy       .. text: "B DB$DB$DB"
b4,bgr,lsb,xy       .. text: "B$\"B$\"B$2C%EDTEDEfy"
b4,bgr,msb,xy       .. text: "$@B$DB$DB$L"
```

On a donc ce qui ressemble à une image PNG dans les bits 1 des channels R,G et B (LSB first). Essayons de l'extraire:

```bash
zsteg -e b1,rgb,lsb,xy output.png > teaser2.png
```

Le fichier est bien un PNG valide:

![[teaser2.png]]

# Encore un puzzle

Maintenant on est habitué, on applique la même méthodologie.

## Résolution

Comme pour le premier, on numérote les blocs et on le résout:

![[teaser2_solved.png]]

## Script

C'est globalement le même script que pour la première image, légèrement modifié pour prendre en compte la bande noir sous ce nouveau puzzle.

```python
from PIL import Image
import numpy as np

im = Image.open("teaser2.png")

p_width, p_height = (100, 60)

col = 5
row = 11

init_order = []

order = np.array([[27, 12, 3, 40, 55],

                   [10, 39, 23, 38, 51],

                   [20, 24, 11, 4, 6],

                   [19, 16, 34, 53, 50],

                   [26, 43, 33, 22, 13],

                   [36, 35, 41, 30, 46],

                   [54, 21, 45, 15, 18],

                   [47, 1, 28, 44, 2],

                   [48, 7, 14, 25, 42],

                   [31, 29, 32, 8, 17],

                   [5, 49, 52, 37, 9]])

order -= 1 # I started indexing the pieces with 1 instead of 0

for i in range(row):
    for j in range(col):
        piece = im.crop((j*p_width, i*p_height, j*p_width + p_width, i*p_height + p_height))
        init_order.append(piece)

black_bar = im.crop((0, 660, 500, 666))

# Get the size of each block

image_width, image_height = init_order[0].size

# Create an empty image to store the final result

final_image = Image.new(mode='RGB', size=(col * image_width, row * image_height))

# Iterate through the array and paste each block into the final image

for r in range(row):
    for c in range(col):
        x = c * image_width
        y = r * image_height
        final_image.paste(init_order[order[r, c]], (x, y))

final_image.paste(black_bar, (0, row*p_height - 6))

# Save and show the final image

final_image.save('fulloutput2.png')
final_image.show()
```

Résultat:

![[fulloutput2.png]]

## Stegano

On passe notre nouvelle image dans `zsteg`:

```
$ zsteg fulloutput2.png
imagedata           .. text: " $$4..\n\n\n"
b1,b,lsb,xy         .. file: OpenPGP Public Key
b1,rgb,lsb,xy       .. file: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), statically linked, interpreter *empty*, can't read name of elf section at -72340177048960768
b1,bgr,lsb,xy       .. file: DOS 2.0 backup id file, sequence 149
b2,r,msb,xy         .. text: ["U" repeated 8 times]
b2,g,msb,xy         .. text: ["U" repeated 8 times]
b2,rgb,msb,xy       .. text: "EQTUUUMQ"
b2,bgr,msb,xy       .. text: "EQUUUUUU"
b4,r,lsb,xy         .. text: "d$B$BB\"$BDB\"\""
b4,r,msb,xy         .. text: "]UUUUUU;3333333333333SU33333"
b4,g,lsb,xy         .. text: "gfffffffffdTDDDDdD "
b4,g,msb,xy         .. text: "UUUUUUUUUUUUUUUU33333"
b4,b,msb,xy         .. text: "pwp7UUuRt"
b4,rgb,msb,xy       .. text: "S5US5US5US5US5US5US5US35S3"
b4,bgr,msb,xy       .. text: "5US5US5US5US5US5US5US5S35S"
```

L'outil détecte un ELF, intéressant. Essayons de voir si cet ELF en est vraiment un:

```bash
zsteg -e b1,rgb,lsb,xy fulloutput2.png > elf
```

Inspectons le header:

```
$ readelf -h elf
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1080
  Start of program headers:          64 (bytes into file)
  Start of section headers:          13176 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         11
  Size of section headers:           64 (bytes)
  Number of section headers:         28
  Section header string table index: 27
readelf: Error: Reading 1792 bytes extends past end of file for section headers
```

Ce fichier a bien l'air d'être un ELF mais le header est corrompu...

## Reverse

Il y a un problème avec les section headers mais cette corruption peut être intentionnelle car la plupart des outils comme GDB ou Ghidra refuseront d'ouvrir le fichier mais il reste exécutable et fonctionnel.

Avec GDB par exemple: `not in executable format: file format not recognized`
Avec IDA Pro: `SHT table size or offset is invalid.` mais le fichier s'ouvre.

Mais l'exécutable a bien l'air de fonctionner. Il demande une entrée clavier puis se ferme.

Plutôt que de me compliquer la tâche en essayant de restaurer le header original, j'ai simplement mis les champs `e_shoff`, `e_shnum` et `e_shstrndx` à 0, ce qui résout nos problèmes avec les outils. J'ai utilisé [lepton](https://github.com/BinaryResearch/lepton) pour cela:

```python
#!/usr/bin/python3

from lepton import *
from struct import pack

def main():
    with open("elf", "rb") as f:
        elf_file = ELFFile(f)

    elf_file.ELF_header.fields["e_shoff"] = pack("Q", 0x0)
    elf_file.ELF_header.fields["e_shnum"] = pack("H", 0)
    elf_file.ELF_header.fields["e_shstrndx"] = pack("<H", 0)  

    # output to file

    binary = elf_file.ELF_header.to_bytes() + elf_file.file_buffer[64:]

    with open("fixed_elf", "wb") as f:
        f.write(binary)

if __name__ == "__main__":

    main()
```


### Static

En l'ouvrant dans IDA, on peut voir qu'il n'y a pas beaucoup de fonctions:
![[Pasted image 20230418131600.png]]

(ajouter graph)

Voici le pseudo-code généré pour la fonction `main`:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[4356]; // [rsp+0h] [rbp-1120h] BYREF
  int v5; // [rsp+1104h] [rbp-1Ch]
  int k; // [rsp+1108h] [rbp-18h]
  int v7; // [rsp+110Ch] [rbp-14h]
  int v8; // [rsp+1110h] [rbp-10h]
  int v9; // [rsp+1114h] [rbp-Ch]
  int j; // [rsp+1118h] [rbp-8h]
  int i; // [rsp+111Ch] [rbp-4h]
  __int64 savedregs; // [rsp+1120h] [rbp+0h] BYREF

  memset(&s[256], 0, 0x1000uLL);
  *(_QWORD *)&s[256] = 32LL;
  memset(&s[264], 0, 56);
  for ( i = 0; i <= 62; ++i )
  {
    for ( j = 0; j <= 63; ++j )
    {
      if ( ((qword_4060[i] >> j) & 1LL) != 0 )
        *((_BYTE *)&savedregs + 64 * (__int64)i + j - 4128) = 35; // 0x23, #
      else
        *((_BYTE *)&savedregs + 64 * (__int64)i + j - 4128) = 32; // 0x20, space
    }
  }
  v9 = 0;
  v8 = 0;
  v7 = 1;
  __isoc99_scanf("%188s", s);
  v5 = strlen(s);
  for ( k = 0; k < v5; ++k )
  {
    switch ( s[k] )
    {
      case 'L':
        --v8;
        break;
      case 'R':
        ++v8;
        break;
      case 'U':
        --v9;
        break;
      case 'D':
        ++v9;
        break;
    }
    if ( *((_BYTE *)&savedregs + 64 * (__int64)v9 + v8 - 4128) == 35 )
      v7 = 0;
    if ( v9 < 0 )
      v7 = 0;
    if ( v8 < 0 )
      v7 = 0;
    if ( v9 > 62 )
      v7 = 0;
    if ( v8 > 62 )
      v7 = 0;
  }
  if ( v7 == 1 && v9 == 62 && v8 == 62 )
  {
    puts("Congrats!! You can use the flag given by this command to validate the challenge:");
    printf("echo -n %s | sha256sum | awk '{ print \"FCSC{\" $1 \"}\" }'\n", s);
  }
  return 0LL;
}
```

Tout le code a l'air d'être dans cette fonction et c'est probablement la dernière étape du challenge puisqu'on peut voir que notre chaîne de caractère `s` saisie au clavier nous permettera de calculer le flag. Maintenant il faut trouver la bonne chaîne.

Visiblement elle doit être composée de 'L', 'R', 'U' et 'D' et maximum 188 charactères sont lus d'après `__isoc99_scanf("%188s", s);`. 

Après une bonne nuit de sommeil, j'ai eu la révélation dont j'avais besoin:
L = Left ; R = Right ; U = Up et D = Down !

`v8` et `v9` sont donc des coordonnées, appelons les `x` et `y` maintenant. On part donc de $(0;0)$ et il faut arriver à $(62;62)$. Mais il y a une autre condition, `v7` que nous appelerons `check`, doit être égal à 1. Il l'est dès le début mais $0 \le x \le 62$  et $0 \le y \le 62$ doivent rester vraies sinon `check` passe à 0.

Mais certaines valeurs dans le stack (dont l'addresse est calculée à partir de $(x;y)$) doivent être égales à 35 (soit 23h ou '#') sinon `check` passe à 0.

Avant d'appeler `scanf`, le programme calcule quelque chose et place soit un '#' soit un ' ' dans le stack. Ce calcul est réalisé à partir de ces valeurs:

![[Pasted image 20230418141607.png]]

J'ai essayé de reproduire ce calcul en Python, sans succès. Il y a quelque chose que je ne dois pas bien comprendre.

Essayons d'obtenir le résultat en faisant une analyse dynamique.

### Dynamic

Je place un breakpoint à la fin des deux boucles `for`:

![[Pasted image 20230418170132.png]]

On exécute le programme, on atteint le BP et dans le stack on obtient:

![[Pasted image 20230418142826.png]]

On a un ensemble de '#' et d'espaces qui semblent former un labyrinthe! Maintenant il faut le mettre en forme, le résoudre et écrire la suite de "mouvements" à réaliser pour aller du coin supérieur gauche au coin inférieur droit.

### Labyrinthe

J'ai donc écrit un script pour mettre en forme ce labyrinthe:

```python
data = "  ############################################################# #   # # #   #   #   # #           #   #     # #   #           # # ### # # ##### ### # ### # ### # # # # # ### ### # # ### ##### #   # #   #         # # # # #   #   # # # #   #   # # # # #   # # ### ### # ####### # # # # ### # ### ### ### # # ### # ##### # # #   #     # # # #   #   #   # #   #       #   # #     #     # # # ####### # # # ### ##### ### ##### ######### ### ##### ### # #               # #   #   #   # #     #     #   # #   #   # # # # ####### ####### # # ### ### ########### ##### # # ##### # ### #   #       #     # #   #   #   # #           #     # #   #   # ### ######### ##### ##### ### ### # ####### ### ### # # ### ### #   #         #     #   #             #   # #   # # #     #   # ### # # ######### ##### ### # # # ### ### ### # # # ##### # # # #   # # #   #     #     # # # # # # #     #   # #   # #   # # # ### # ### ### ### # # # # # ####### # # ########### # ### # ### #         #     # # # # # #   #     # #   #       # # #   # # # # # # ####### ##### ##### ### ##### # ########### # # ### # # # # # #     # # # #           # #   #               #           # # ####### # ### ### ### # ### # ########### # ##### ####### # # # # #   #           #   #         #       # #   # #   # # # # # # # # ### # ##### ### # # ### ######### # ####### ##### # ### # # # #     # #     #   # # #   # #       # #                   # # # # # ### ### ### ### ##### # # ####### ########### ##### # # #   # #   # #     # # # #     #   # #     #   # #     # # # # # # ####### ####### ### # ####### # # # ####### # # # ### # # # # #       #     #   #   # #   #   # #   #   #       # #     # # # # # # ####### # # ### ### # ##### # ### ### ### ####### ####### # # #     # # # # # #     # #     # #     #   # #   #   #     # ### # ##### # ### # ####### # # ######### # ##### ### # ### ### # # #       # #     #   # #   #             #   #     #   #   # # ##### ####### ##### ### ### ######### ### # ### ### ### # ### # #         #   # #           #         # # #   # #   #       # # # ### ### ### # ### # # # ### ######### # # # # # # ####### # #     # #     #       # # # #   #           # #   # #   #     # # ### ########### ####### ### # ##### ##### # ### ########### # #   # # #   # # #   # # # #   # # #     #     # # # #     #   # ### ### # ### # ##### # ######### ######### # # ### ##### # # # #   # #   #       #     #     #         # # #   #   # # #   # # ##### # # ### # # ### ### # # # # # ##### # # # ### # # ### ### # # #   # #   # #   #   # # #   # # #       # # # # #     #   # # # # ### ### # # ### ##### ##### ######### ##### # ##### # # # #       # #   # # #         #   #     #         #           # # ### # ### # ####### # ##### # ############# ##### ######### # # #   #   #   #   #   # # #     #       # #   #   #       #   # # ### ### # ### ### ### # ##### ####### # ####### # ######### ### #     # #           #   # #   #     #     # #         #       # # # ##### # ### ### ### # # ### ##### # ### ### ### ######### # # # #   # # #   #   # #   # #     #   # #     # #     #       # # ##### ### ####### # # ### ##### ##### ##### ##### ##### ##### #     #   # #   #     #   #     #   #       #     # #       # # # ####### ##### ### ####### # ##### # # ##### ### ####### ### # #       #   #   #     #     # #   #   # #       # # #     # # # # ######### ### # ####### ##### ### ##### ### ### # # ##### # # # #     #   #   # #       # #   #     # # #     #           # # ### ### # # # # # # ####### # # # # # # # ##### ##### ### ### # #   #   # #   #   #   #   #   #   # #   #     #   #     #     # # ####### ### # ### # # # ### ##### ### # # # # ############# # #   #     # # # # # #   #     # # # #     # # #         # #   # # # ### ### ### # ### ##### # # # # ### # ### ### ### # # # ### # #       # #   #   #   #   # # # # #   #   #   # #   #   # # # ### # ##### # ##### # ### ##### # # # ########### ##### ### # # #   #       # #       #         #   # #             #     #     #########################################################      "

  

def draw():
    s = ""

    for y in range(63):
        for x in range(63):
            s += data[y*64 + x]
        s += "\n"
    return s

if __name__ == '__main__':
	print(draw())
```

Ce qui nous donne:

```
  #############################################################
#   # # #   #   #   # #           #   #     # #   #           #
# ### # # ##### ### # ### # ### # # # # # ### ### # # ### #####
#   # #   #         # # # # #   #   # # # #   #   # # # # #   #
# ### ### # ####### # # # # ### # ### ### ### # # ### # ##### #
# #   #     # # # #   #   #   # #   #       #   # #     #     #
# # ####### # # # ### ##### ### ##### ######### ### ##### ### #
#               # #   #   #   # #     #     #   # #   #   # # #
# ####### ####### # # ### ### ########### ##### # # ##### # ###
#   #       #     # #   #   #   # #           #     # #   #   #
### ######### ##### ##### ### ### # ####### ### ### # # ### ###
#   #         #     #   #             #   # #   # # #     #   #
### # # ######### ##### ### # # # ### ### ### # # # ##### # # #
#   # # #   #     #     # # # # # # #     #   # #   # #   # # #
### # ### ### ### # # # # # ####### # # ########### # ### # ###
#         #     # # # # # #   #     # #   #       # # #   # # #
# # # ####### ##### ##### ### ##### # ########### # # ### # # #
# # #     # # # #           # #   #               #           #
# ####### # ### ### ### # ### # ########### # ##### ####### # #
# # #   #           #   #         #       # #   # #   # # # # #
# # # ### # ##### ### # # ### ######### # ####### ##### # ### #
# # #     # #     #   # # #   # #       # #                   #
# # # # ### ### ### ### ##### # # ####### ########### ##### # #
#   # #   # #     # # # #     #   # #     #   # #     # # # # #
# ####### ####### ### # ####### # # # ####### # # # ### # # # #
#       #     #   #   # #   #   # #   #   #       # #     # # #
# # # ####### # # ### ### # ##### # ### ### ### ####### #######
# # #     # # # # # #     # #     # #     #   # #   #   #     #
### # ##### # ### # ####### # # ######### # ##### ### # ### ###
# # #       # #     #   # #   #             #   #     #   #   #
# ##### ####### ##### ### ### ######### ### # ### ### ### # ###
# #         #   # #           #         # # #   # #   #       #
# # ### ### ### # ### # # # ### ######### # # # # # # ####### #
#     # #     #       # # # #   #           # #   # #   #     #
# ### ########### ####### ### # ##### ##### # ### ########### #
#   # # #   # # #   # # # #   # # #     #     # # # #     #   #
### ### # ### # ##### # ######### ######### # # ### ##### # # #
#   # #   #       #     #     #         # # #   #   # # #   # #
##### # # ### # # ### ### # # # # # ##### # # # ### # # ### ###
# # #   # #   # #   #   # # #   # # #       # # # # #     #   #
# # # ### ### # # ### ##### ##### ######### ##### # ##### # # #
#       # #   # # #         #   #     #         #           # #
### # ### # ####### # ##### # ############# ##### ######### # #
#   #   #   #   #   # # #     #       # #   #   #       #   # #
### ### # ### ### ### # ##### ####### # ####### # ######### ###
#     # #           #   # #   #     #     # #         #       #
# # ##### # ### ### ### # # ### ##### # ### ### ### ######### #
# # #   # # #   #   # #   # #     #   # #     # #     #       #
# ##### ### ####### # # ### ##### ##### ##### ##### ##### #####
#     #   # #   #     #   #     #   #       #     # #       # #
# ####### ##### ### ####### # ##### # # ##### ### ####### ### #
#       #   #   #     #     # #   #   # #       # # #     # # #
# ######### ### # ####### ##### ### ##### ### ### # # ##### # #
# #     #   #   # #       # #   #     # # #     #           # #
### ### # # # # # # ####### # # # # # # # ##### ##### ### ### #
#   #   # #   #   #   #   #   #   # #   #     #   #     #     #
# ####### ### # ### # # # ### ##### ### # # # # ############# #
#   #     # # # # # #   #     # # # #     # # #         # #   #
# # ### ### ### # ### ##### # # # # ### # ### ### ### # # # ###
# #       # #   #   #   #   # # # # #   #   #   # #   #   # # #
### # ##### # ##### # ### ##### # # # ########### ##### ### # #
#   #       # #       #         #   # #             #     #
#########################################################
```

Pour plus de visibilité, j'ai remplacé les '#' et les espaces par des emojis carrés noir et blanc puis j'ai résolu le labyrinthe:

![[Screenshot 2023-04-16 133236.png]]

Les chemins rouges sont des essais, le chemin vert est le plus court pour résoudre le labyrinthe. En faisant le chemin avec une lettre pour un mouvement d'une case, on obtient:

```
RDDDDDDDDDRRDDDDDDRRDDRRRRDDRRRRRRRRDDLLDDRRDDDDDDLLDDDDRRRRRRUURRRRRRRRUUUURRDDRRRRRRRRRRRRDDDDDDRRUUUURRDDRRUUUURRRRUURRDDRRDDRRRRDDDDLLDDDDDDDDDDRRDDLLLLDDDDLLLLDDRRRRDDRRRRDDLLDDDDRRRD
```

Et cela fonctionne:

![[Pasted image 20230418145025.png]]

Le flag est donc: `FCSC{5cf9940286533f76743984b95c8edede9dbfde6226de012b8fe84e15f2d35e83}`.



