# -*- coding: utf-8 -*-
"""biso_hash.ipynb

Original file is located at
    https://colab.research.google.com/drive/1V1gMf8xa4K9R4Ud2fnp_HJDwtRz_6UUM

la fonction d'Hachage BISO est inspiré de l'algorithme SHA-256, effectuant la préparation des données, 
l'initialisation des variables, le traitement par blocs, la compression du bloc, la finalisation du condensé, 
et finalement le retour du résultat sous forme de base64.

1. **Préparation des données (prepare_data):**
   - La fonction commence par encoder la chaîne de message en UTF-8.
   - Elle calcule la longueur du message en bits et détermine le nombre de bits de padding nécessaires pour 
        que la longueur totale soit un multiple de 512 bits.
   - Ajoute un padding au message avec un '1' suivi de zéros et la longueur du message en bits codée sur 8 octets.
"""

def prepare_data(message):
    # Ajout du padding pour que la longueur totale soit un multiple de 512 bits
    message = message.encode('utf-8')
    ml = len(message) * 8  # Longueur du message en bits
    k = 448 - (ml + 1) % 512  # Nombre de bits de padding à ajouter
    padding = b'\x80' + b'\x00' * (k // 8) + (ml).to_bytes(8, byteorder='big')
    prepared_data = message + padding
    return prepared_data

"""2. **Initialisation des variables (initialize_variables):**
   - Initialise les variables internes (h0 à h7) avec des valeurs spécifiques, qui sont les premières parties des racines carrées des huit premiers nombres premiers.


"""

def initialize_variables():
    # Initialisation des variables internes avec des valeurs spécifiques
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19
    return (h0, h1, h2, h3, h4, h5, h6, h7)

"""3. **Traitement par blocs (process_blocks):**
   - Divise le message préparé en blocs de 512 bits.


"""

def process_blocks(data):
    # Traitement par blocs de 512 bits à la fois
    block_size = 64  # Taille d'un bloc en octets (512 bits)
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    return blocks

"""4. **Compression du bloc (compress_block):**
   - La fonction de compression applique l'algorithme de compression SHA-256 sur chaque bloc.
   - Utilise les constantes de la table de hachage et des opérations logiques et arithmétiques pour calculer de nouveaux mots à partir du bloc actuel.
   - Effectue la compression principale en mettant à jour les variables de travail (a à h) à chaque itération.
   - À la fin de chaque bloc, les variables de travail sont mises à jour en ajoutant les valeurs calculées aux variables existantes.


"""

def compress_block(block,h , h0, h1, h2 ,h3 ,h4 ,h5 , h6, h7):
    # Valeurs initiales des constantes de la table de hachage
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Initialisation des variables de travail
    a, b, c, d, e, f, g, h = h

    # Préparation des mots du bloc
    w = [int.from_bytes(block[i:i + 4], byteorder='big') for i in range(0, len(block), 4)]
    w += [0] * (64 - len(w))  # Extension à 64 mots

    # Calcul des nouveaux mots
    for i in range(16, 64):
        s0 = (w[i-15] >> 7 | w[i-15] << (32-7)) ^ (w[i-15] >> 18 | w[i-15] << (32-18)) ^ (w[i-15] >> 3)
        s1 = (w[i-2] >> 17 | w[i-2] << (32-17)) ^ (w[i-2] >> 19 | w[i-2] << (32-19)) ^ (w[i-2] >> 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & ((1 << 32) -1)

    # Compression principale
    for i in range(64):
        S1 = (e >> (32 - 6) | e << (32 - (32 -6))) ^ (e >> (32 -11) | e << (32 - (32 -11))) ^ (e >> (32 -25) | e << (32 - (32 -25)))
        ch = (e & f) ^ (~e & g)
        temp1 = h + S1 + ch + k[i] + w[i]
        S0 = (a >> (32 -2) | a << (32 - (32 -2))) ^ (a >> (32 -13) | a << (32 - (32 -13))) ^ (a >> (32 -22) | a << (32 - (32 -22)))
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = S0 + maj

        h = g
        g = f
        f = e
        e = (d + temp1) & ((1 << 32) - 1)
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & ((1 << 32) - 1)

    h0, h1, h2 ,h3 ,h4 ,h5 , h6, h7 = h0, h1, h2 ,h3 ,h4 ,h5 , h6, h7
    # Mise à jour des variables de travail
    h0 = (h0 + a) & ((1 << 32) - 1)
    h1 = (h1 + b) & ((1 << 32) - 1)
    h2 = (h2 + c) & ((1 << 32) - 1)
    h3 = (h3 + d) & ((1 << 32) - 1)
    h4 = (h4 + e) & ((1 << 32) - 1)
    h5 = (h5 + f) & ((1 << 32) - 1)
    h6 = (h6 + g) & ((1 << 32) - 1)
    h7 = (h7 + h) & ((1 << 32) - 1)

    return [h0, h1, h2, h3, h4, h5, h6, h7]

"""5. **Finalisation du condensé (finalize_hash):**
   - Combiner les valeurs partielles de h0 à h7 pour former le condensé final.
   - Les valeurs sont concaténées et retournées sous forme de chaîne d'octets.


"""

def finalize_hash(h):
    # Finalisation : combinaison des valeurs partielles pour former le condensé final
    final_hash = b''
    for hi in h:
        final_hash += hi.to_bytes(4, byteorder='big')
    return final_hash

"""6. **Fonction principale (biso_hash):**
   - Appelle les fonctions précédentes dans l'ordre pour effectuer le hachage complet du message.
   - Retourne le résultat final sous forme de chaîne hexadécimale.


"""

import base64

def biso_hash(message):
    prepared_data = prepare_data(message)
    h = initialize_variables()
    h0, h1, h2, h3, h4, h5, h6, h7 = h

    blocks = process_blocks(prepared_data)
    for block in blocks:
        h = compress_block(block, h, h0, h1, h2, h3, h4, h5, h6, h7)
    hashed_message = finalize_hash(h)

    # Convertit le résultat final en base 64
    base64_message = base64.b64encode(hashed_message)

    return base64_message.decode('utf-8')  # Retourne la représentation en tant que chaîne de caractères



# Exemple d'utilisation de la fonction pour hacher un message
message = "mon texte"
message2 = "mon texte"
hashed_message_1 = biso_hash(message)
hashed_message_2 = biso_hash(message2)

print("Message original:", message)
print("Message haché   (biso_hash):", hashed_message_1)
print("Message haché 2 (biso_hash):", hashed_message_2)

hashed_message_1==hashed_message_2

len(hashed_message_2)