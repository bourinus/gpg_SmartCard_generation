# gpg_SmartCard_generation


* Goal
 a generated main keyring is stored in a vault while
 a gpgcard is used to carry its subkeys


* Keyring structure 
 keys  Public  Private   gpgcard  desktop          
   SC    pub     sec       sec#     sec#               
   S     sub     ssb       ssb>     ssb#            
   E     sub     ssb       ssb>     ssb#            
   A     sub     ssb       ssb>     ssb#  
 Symbol # after key means the secret key is not usable
 Symbol > after key means the secret key is     usable


* This script give a functional gpg dongle in the less interactive way possible.
move your old .gnupg to .old_gnupg
generate a gpg master key
generate sub keys for auth sign enc
export the subkeys to dongle
remove master key from keyring
leave save of keyrings in a folder


* Tested on:
Debian GNU/Linux 9.7 (stretch)
gpg (GnuPG) 2.1.18
libgcrypt 1.7.6-beta


* Authors: 
Bourinus [choucroutage.com][1]


* Licence: 
Creative Commons: Attribution-ShareAlike 4.0 International ([CC BY-SA 4.0][3]) 

        
[1]: https://choucroutage.com
