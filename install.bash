#!/bin/bash
  #
  ##  realise with gpg2.1.15 the following keyring:
  ##  https://wiki.fsfe.org/TechDocs/CardHowtos/CardWithSubkeysUsingBackups
  #
  ## Goal
  #   the main keyring is stored in a vault while
  #   a gpgcard is used to carry its subkeys
  #
  ## Keyring         
  #   key roles               Key types
  #     A: authentication       pub: public  primary-key
  #     C: certification        sec: private primary-key
  #     E: encryption           sub: public  sub-key
  #     S: signing              ssb: private sub-key
  #
  #   keys  Public  Private   gpgcard  desktop          
  #     SC    pub     sec       sec#     sec#               
  #     E     sub     ssb       ssb#     ssb              
  #     S     sub     ssb       ssb>     ssb#            
  #     E     sub     ssb       ssb>     ssb#            
  #     A     sub     ssb       ssb>     ssb#  
  #
  #   Symbol # after key means the secret key is not usable
  #   Symbol > after key means the secret key is     usable
  #
  ## sources
  #  projet avorté de faire la meme chose, interface + init smart card
  #   https://gist.github.com/woods/8970150
  #  soluce pour gpg-agent hijack par gnome-keyring-daemon ??
  #   https://gist.github.com/ageis/5b095b50b9ae6b0aa9bf
  #
  ## Hardware
  #   http://shop.kernelconcepts.de/
  #
  ## Required
  # sudo apt install signing-party
  #

## Variables
 # path_to_trace path where all export of keys will be performed, store this repo in a safe place
  path_to_folder="/home/david/owncloud/cloud.ch/DavidDesktop/work/gpg/folder";

  ## gpg-id param
  var_mail="davidgueguen@yandex.ru"
  var_name="David Gueguen"
  var_usrname_machine="david"
  var_comment="''"
  ## keyring param
  var_pass_poem="@"
  var_key_type="1"
  var_key_lenght="2048"
  var_pref="SHA512 SHA384 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed"
  var_expiracy="2y"
  var_gpg_pth="/home/$USER/.gnupg";
  ## public key web path
  asci_public_key_name="david.gueguen.txt"
  var_web_path="https://choucroutage.com//$asci_public_key_name";
  ## optional
  var_photo_path="/home/david/Desktop/green_reduced.jpg";


printer(){
 ##  write output on both terminal and repport file
  ## 
  #
  echo $@ >> report/gen_key_report
  echo $@
}
function echo_fail {
 ##  display a message in red with a cross by it
  ## 
  # echo first argument in red
  printf "\e[31m✘ ${1}"
  # reset colours back to normal
  printf "\033[0m\n"
}
function program_is_installed {
 ##  return 1 if global command line program installed, else 0
  ## echo "node: $(program_is_installed node)"
  #
  for var in "$@"; do
    if ! which $var &> /dev/null; then
      echo "Install $var!" 
    fi
  done
}
check_softs(){
 ## ensure mandatory softs presence
  ## exit the whole sript if not
  #
  echo
  echo "-->> Processing if softs are available ... "
  if [ "$(program_is_installed libccid)" == 0 ]; then
    sudo apt-get install libccid
  fi
  if [ "$(program_is_installed gpg2)" == 0 ]; then
    sudo apt-get install gnupg2 
  fi
  if [ "$(program_is_installed signing-party)" == 0 ]; then
    sudo apt install signing-party
  fi
  if [ "$(program_is_installed scdaemon)" == 0 ]; then
    sudo apt-get install scdaemon
  fi
  if [ "$(program_is_installed opensc-explorer)" == 0 ]; then
    sudo apt-get install opensc
  fi
  program_is_installed pcscd paperkey haveged gnupg-agent hopenpgp-tools pinentry-curses scdaemon libksba8 libpth20
  printer "Required softs are present."
}
check_card_is_here(){
 ## ensure openpgp card is readable
  ## exit the whole sript if not
  #
  echo
  echo "-->> Processing if 'gpg2 --card-status' returns no error ... "
  local cmd=$(gpg2 --card-status)
  if [[ "$cmd" == *"Reader ...........:"* ]]; then
    echo  "OK, GPG card readable."
  else
    echo
    echo_fail "FAIL ! No GPG card readable" 
    exit 1
  fi
}
check_mail_id_is_not_used(){
 ## ensure mail_id is not linked to a secret key
  ## exit the whole sript if not
  #
  echo
  echo "-->> Processing if $var_mail id is not in gpg public keys list ... "
  local cmd=$(gpg2 --list-secret-keys | grep $var_mail)
  if [[ -z "$cmd" ]]; then
    echo  "OK, can pursue to main keys generations."
  else
    
    echo_fail "FAIL ! This mail id is already linked to referenced private key" 
    echo
    echo "$(gpg2 --list-secret-keys --with-fingerprint | grep -A10 $var_mail)"
    exit 1       
  fi
    printer "OK,  keyring generated."
}
gen_main_key(){
 #  Generate main keyring
 ## primary keyring: 2 pairs of asymetrical keys ! do not change 
  # Key-Usage:    sign cert
  # Subkey-Usage:   encrypt
  # 
  #  gpg2 gen key with no interaction 'technique EOF pour --full-gen-key'
  #   https://gist.github.com/woods/8970150
  printer 
  printer    "-->> Generating main keyring: SC keypair and E keypair ... " 
  touch report/gen_KEYIDript         # creating file to gen key in gpg batch mode
  echo " 
  Key-Type:         $var_key_type 
  Key-Usage:        sign cert
  Key-Length:       $var_key_lenght
  Name-Real:        $var_name
  Name-Comment:     $var_comment
  Name-Email:       $var_mail
  Keyserver:        $var_web_path
  Expire-Date:      $var_expiracy
  Passphrase:       $var_pass_poem
  Preferences:      $var_pref
  " > report/gen_KEYIDript  # creating SC and E keys
  gpg2 --batch --full-gen-key report/gen_KEYIDript  &> /dev/null 
  rm report/gen_KEYIDript
  #  gpg2 --list-only --list-packets < *.gpg
  gpg2 -K
  printer "OK, main keyring generated."
}

get_KEYID(){
 #  get keyring id hash and individual key hash for newly created passkey
 ## gpg2 -k --with-colons option emits the output in a stable, machine-parseable format
  #
  printer 
  printer "-->> Getting keyring id ... " 
  # fingerprint and keygrip"
  local locate=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail)
  echo $locate
  KEYID=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep fpr | awk -F: '{ print $10 }')
  KEYID_grp=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep grp | awk -F: '{ print $10 }') 
  KEYID_uid=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep uid | awk -F: '{ print $8 }')
  # test if all present
  if [[ -z "$KEYID" || -z "$KEYID_grp" || -z "$KEYID_uid" ]]; then
    echo_fail "FAIL ! while getting keyring components, values:" 
    echo   "FAIL ! while getting keyring components, values:" >> report/gen_key_report
    echo $KEYID, $KEYID_grp, $KEYID_uid
    printer
    exit 1  
  else
    printer "Keyring after main keys generation, for $var_mail:" 
    printer "uid:   $KEYID_uid"
    printer "$(gpg2 -k --no-verbose $var_mail | grep pub) fpr:   $KEYID, grp:   $KEYID_grp"
  fi
  printer "OK, hash values for main key get."
}
publish_KEYID(){
 ## 
  #
  printer 
  printer    "-->> Publishing master keyring ... " 
  # report
  # export to file
  #gpg2 --no-verbose --export-secret-key  --armor --yes $KEYID > priv_main.key    
  #gpg2 --no-verbose --export             --armor --yes $KEYID > pub_main.asc            



  # gpg2 --export-secret-key $KEYID | paperkey --output my-secret-key.gpg 
  #  gpg2 --export-secret-key $KEYID | paperkey | dmtxwrite -e 8 -f PDF > pub.ring.pdf


  # export to pdf QR code
  # 
  printer "OK, keyring written to pub.main.txt and priv.keys.txt."
}
add_photo(){
 ## Add photo to key from user input Recquired ! --command-fd 0 --status-fd 2 recquires gpg 2.1.15
  #   next gen command for --edit-key gpg2.1.15
  #     https://eferdman.github.io/debian/outreachy/2016/12/20/Debian-2w/
  #   no password prompt
  #     https://superuser.com/questions/1191963/gpg2-edit-key-addphoto-keytocard-without-password-prompt
  #
  printer
  printer  "-->> Adding photo ... " 
  local cmd="addphoto\n$var_photo_path\ny\y\n"
  echo -e $cmd | gpg2  --command-fd 0 --status-fd 2 --edit-key $KEYID
  printer  "$(gpg2  --no-verbose -k $var_mail | grep -A1 $var_mail)"
  printer "OK, Done."
}
gen_sub_keys(){
## Generates 3 sub keys to keyring
  # https://superuser.com/questions/1191933/gpg2-quick-addkey-without-password-prompt/1191943#1191943
  #
  printer
  printer "-->> Generating sub keyring ... " 
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $KEYID rsa$var_key_lenght sign 1y    &> /dev/null; # gpg2 --quick-addkey $KEYID rsa$var_key_lenght sign 1y
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $KEYID rsa$var_key_lenght encrypt 1y &> /dev/null; # gpg2 --quick-addkey $KEYID rsa$var_key_lenght encrypt 1y
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $KEYID rsa$var_key_lenght auth 1y    &> /dev/null; # gpg2 --quick-addkey $KEYID rsa$var_key_lenght auth 1y
 # printer "Export keyring to pdf: " 
 # gpg2 --export $KEYID | paperkey --output-type raw | dmtxwrite -e 8 -f PDF > pub.ring.pdf
 printer  "Done."
}
get_subkeys_id(){
 ## Get keys ids 
  # detection by 'sub' only after Remove main encryption subkey
  # keyring identity; the --with-colons option emits the output in a stable, machine-parseable format
  #
  printer
  printer  "-->> get subkeys id ... " 
  local subkeys_edit=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -A12 $var_mail | grep fpr | awk -F: '{ print $10 }')
  echo $subkeys_edit
  subkey_S_fpr=$(echo $subkeys_edit | awk '{print $1}')
  subkey_E_fpr=$(echo $subkeys_edit | awk '{print $2}')
  subkey_A_fpr=$(echo $subkeys_edit | awk '{print $3}')
  # 
  local subkeys_edit=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -A12 $var_mail | grep grp | awk -F: '{ print $10 }')
  subkey_S_grp=$(echo $subkeys_edit | awk '{print $1}')
  subkey_E_grp=$(echo $subkeys_edit | awk '{print $2}')
  subkey_A_grp=$(echo $subkeys_edit | awk '{print $3}')
  # test if all present
  if [[ -z "$subkey_S_fpr" || -z "$subkey_E_fpr" || -z "$subkey_A_fpr" || -z "$subkey_S_grp" || -z "$subkey_E_grp" || -z "$subkey_A_grp"  ]]; then
    printer  "FAIL ! while getting keyring components, values:" 
    printer $subkey_S_fpr, $subkey_E_fpr, $subkey_A_fpr, $subkey_S_grp, $subkey_E_grp, $subkey_A_grp
    printer
    exit 1 
  else
    printer "Subkeys after generation"
    printer
    printer "OK, keyring for $var_mail  uid: $KEYID_uid S,E,A"
    printer "$(gpg2 -K --no-verbose $var_mail | grep "ssb>" | head -1 | tail -1) fpr:   $subkey_S_fpr, grp:    $subkey_S_grp"
    printer "$(gpg2 -K --no-verbose $var_mail | grep "ssb>" | head -2 | tail -1) fpr:   $subkey_E_fpr, grp:    $subkey_E_grp"
    printer "$(gpg2 -K --no-verbose $var_mail | grep "ssb>" | head -3 | tail -1) fpr:   $subkey_A_fpr, grp:    $subkey_A_grp"
  fi
  printer "Done."
}
mv_subkeys_to_card(){
 ## Move subkeys to cards
  #   sign subkey:  key n2        encrypt subkey: key n3        auth key:   key n4
  #
  printer
  printer  "-->> Subkeys exportation to card and removal from keyring:"
  local cmd="key 1\nkeytocard\n1\ny\nkey 1\nkey 2\nkeytocard\n2\ny\nkey 2\nkey 3\nkeytocard\n3\ny\nsave\nY\n"
  #local cmd="key 1\nkeytocard\n1\ny\nsave\nY\n"
  #echo -e $cmd | gpg2 --no-verbose --command-fd 0 --status-fd 2 --edit-key $KEYID &> /dev/null
  #cmd="key 2\nkeytocard\n2\ny\nsave\nY\n"
  #echo -e $cmd | gpg2 --no-verbose --command-fd 0 --status-fd 2 --edit-key $KEYID &> /dev/null
  #cmd="key 3\nkeytocard\n3\ny\nsave\nY\n"
  #echo -e $cmd | gpg2 --no-verbose --command-fd 0 --status-fd 2 --edit-key $KEYID &> /dev/null
  gpg2 -K
  echo -e $cmd | gpg2 --no-verbose --command-fd 0 --status-fd 2 --edit-key $KEYID &> /dev/null
  gpg2 -K
  printer  "OK, Key in dongle."
}
build_gpg.conf(){
 # Minimum modification to gpg.conf 
  if [ ! -e "/home/$USER/.gnupg/gpg.conf" ] ; then
      touch "/home/$USER/.gnupg/gpg.conf"
  fi
  printer
  printer "-->> Modifying gpg.conf:"
  printf "# This is an implementation of the Riseup OpenPGP Best Practices
# https://help.riseup.net/en/security/message-security/openpgp/best-practices
#
no-greeting
#-----------------------------
# behavior
#-----------------------------
no-emit-version                 # Disable inclusion of the version string in ASCII armored output
no-comments                     # Disable comment string in clear text signatures and ASCII armored messages
keyid-format 0xlong             # Display long key IDs
with-fingerprint                # List all keys (or the specified ones) along with their fingerprints
list-options show-uid-validity  # Display the calculated validity of user IDs during key listings
use-agent                       # GnuPG first tries to connect to the agent before it asks for a passphrase.
verify-options show-uid-validity
keyserver-options no-honor-keyserver-url
fixed-list-mode
charset utf-8
utf8-strings
auto-key-locate local
#-----------------------------
# algorithm and ciphers
#-----------------------------
# list of personal crypto preferences  
# !! small key lenght can bring conditions of use not satisfied
personal-digest-preferences SHA512 SHA384 SHA256 SHA224
cert-digest-algo SHA512
default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
personal-cipher-preferences AES256 AES192 AES CAST5
#-----------------------------
# default key
#-----------------------------
# The default key to sign with. If this option is not used, the default key is
# the first key found in the secret keyring
" >> /home/$USER/.gnupg/gpg.conf
  printf "hidden-encrypt-to %s\n"         $subkey_E_fpr >> /home/$USER/.gnupg/gpg.conf
  printf "default-recipient %s\n"         $var_mail >> /home/$USER/.gnupg/gpg.conf
  #printf "default-key %s\n"               $subkey_S_fpr >> /home/$USER/.gnupg/gpg.conf
  printer "Done."
}
test_1(){
  echo 'hello world' > test/hello.txt
  gpg --yes -o test/test1.txt.gpg -r $var_mail -e test/hello.txt
  gpg --yes -o test/test1.txt -d test/test1.txt.gpg
  echo_fail "Expected behaviour pin asked for decryption & 'hello World'"
  printer $(cat test/test1.txt)
}
test_2(){
  gpg --yes -o test/test2.txt.gpg -r $var_mail -s test/hello.txt
  gpg --yes -o test/test2.txt -d test/test2.txt.gpg
  echo_fail "Expected behaviour pin asked for signature & 'hello World'"
  printer $(cat test/test2.txt)
}
test_3(){
  gpg --yes -o test/test3.txt.gpg -r $var_mail -s -e test/hello.txt
  gpg --yes -o test/test3.txt -d test/test3.txt.gpg
  echo_fail "Expected behaviour pin asked for signature & 'hello World'"
  printer $(cat test/test3.txt)
}
export_subkey_stubs(){
 ## Sub key exportation to txt files
  # Removing master keyring encryption key I
  # 
  printer
  printer "-->> Sub key exportation to file:"
 #gpg2 --no-verbose --export --armor --yes $subkey_S_fpr! > public.subkey_S.pub
 #gpg2 --no-verbose --export --armor --yes $subkey_E_fpr! > public.subkey_E.pub
 #gpg2 --no-verbose --export --armor --yes $subkey_A_fpr! > public.subkey_A.pub
  gpg2 --no-verbose --export --armor --yes $KEYID > public_gpg_keyring.pub
  gpg2 --no-verbose --export-secret-keys --armor --yes $KEYID > private_gpg_keyring.key
  gpg2 --no-verbose --export-secret-subkeys --armor --yes $KEYID > priv.subkey.key

  #gpg2 --no-verbose --export-secret-key  --armor --yes $KEYID > priv_main.key    
  #gpg2 --no-verbose --export             --armor --yes $KEYID > pub_main.asc            


  #gpg2 --export-secret-subkeys $KEYID | paperkey --output-type raw | dmtxwrite -e 8 -f PDF > priv.subkey.pdf
  echo "OK, subkeys exported."
}
rm_primary_signing_key(){
 ## Primary signing key removal from keyring
  # Removing master keyring encryption key II
  #   
  echo
  echo "-->> Private key removal from keyring:"
  gpg2 --yes --no-verbose --delete-secret-keys  $KEYID
  gpg2 --card-status
  echo "Private key has been removed:"
  echo "Done."
}
import_subkeys_stubs(){
 ## Sub key importation
  # Reimport the subkey stubs
  # Removing master keyring encryption key III
  #
  echo
  echo "-->> Sub key importation:" 
  #gpg2 --import pub.main.txt
  gpg2 -K
  gpg2 --import priv.subkey.key 
  gpg2 --card-status
  gpg2 -K
  echo  "Done."
  echo
  echo "  ---  KEYRING BUILDING COMPLETED  ---  " 
  echo
  echo " On this computer: " 
  echo "    Private part: gpg2 -K" $(gpg2 -K)
  echo "    Public part:  gpg2 -k" $(gpg2 -k)
  gpg2 --card-status
  echo "Done."
}
rm_master_keyring_encryption_key(){
 ## removing master key from keyring  
  #
  printer
  printer  "-- >> main encryption public key removal:"
  local cmd="key 1\ndelkey\ny\nsave\n"
  echo -e $cmd | gpg2 --command-fd 0 --status-fd 2 --edit-key $KEYID 
  echo "$(gpg2 -K)" >> report/gen_key_report
  printer "Done."
}
do_send_key_server(){
 ## send public key to keyserver
 echo
 echo "-->> keyring online:"
  # gpg2 --send-keys --keyserver keyserver.ubuntu.com $KEYID
   #
  #gpg2 --export-ssh-key $KEYID --yes --armor > output-sshkey.sec 
  echo "Done." 
}
update_keyring(){
 # Clean up the GPG Keyring.  Keep it tidy.
  # blog.lavall.ee
  # 
  echo -n "Expired Keys: "
  for expiredKey in $(gpg2 -k | awk '/^pub.* \[expired\: / {id=$2; sub(/^.*\//, "", id); print id}' | fmt -w 999 ); do
    echo -n "$expiredKey"
    gpg2 --batch --quiet --delete-keys $expiredKey >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo -n "(OK), "
    else
      echo -n "(FAIL), "
    fi
  done
  echo done.
  echo -n "Update Keys: "
  for keyid in $(gpg2 -k | grep ^pub | grep -v expired: | grep -v revoked: | cut -d/ -f2 | cut -d' ' -f1); do
    echo -n "$keyid"
    gpg2 --batch --quiet --edit-key "$keyid" check clean cross-certify save quit > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo -n "(OK), "
    else
      echo -n "(FAIL), "
    fi
  done
  echo done.
  gpg2 --batch --quiet --refresh-keys > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "Refresh OK"
  else
   echo "Refresh FAIL."
 fi
 echo "Done."
}
main(){
 ## main
  #
  rm -r /home/david/.gnupg
  mkdir -p $path_to_folder
  rm -r $path_to_folder/*
  cd $path_to_folder
  mkdir -p test
  mkdir -p report
  
  cat /dev/null > report/gen_key_report  # initiate report/gen_key_report to void
  pkill -f gnome-keyring-daemon
  gpgconf --kill gpg-agent      
  check_softs                       || { echo "check_softs failed"; exit 1; } 
  check_card_is_here                || { echo "check_card_is_here failed"; exit 1; }   # attempts to read card, stop if can't
  check_mail_id_is_not_used         || { echo "check_mail_id_is_not_used failed"; exit 1; }   # attempts to create key, stop if exists
  gen_main_key                      || { echo "gen_main_key failed"; exit 1; }   # Create a GnuPG secret key
  get_KEYID                         || { echo "get_KEYID failed"; exit 1; }    # getting main key hash
  publish_KEYID                     || { echo "publish_KEYID failed"; exit 1; }
  add_photo                         || { echo "add_photo failed"; exit 1; }    # incorporating photo to keyring
  gen_sub_keys                      || { echo "gen_sub_keys failed"; exit 1; }    # Generating subkeys for the card
  get_subkeys_id                    || { echo "get_subkeys_id failed"; exit 1; }
  build_gpg.conf                    || { echo "build_gpg.conf failed"; exit 1; }
  export_subkey_stubs               || { echo "export_subkey_stubs failed"; exit 1; }   # Export secret subkeys
  mv_subkeys_to_card                || { echo "mv_subkeys_to_card failed"; exit 1; }   # Move the subkeys to the card
  #test_1                            || { echo "test_1 failed"; exit 1; }   # Move the subkeys to the card
  #rm_master_keyring_encryption_key  || { echo "rm_master_keyring_encryption_key failed"; exit 1; }   # Remove main encryption subkey  
  rm_primary_signing_key             || { echo "rm_primary_signing_key failed"; exit 1; }   # Remove secret master key
  #import_subkeys_stubs              || { echo "import_subkeys_stubs failed"; exit 1; }   # Reimport the subkey stubs
  gpg --export $KEYID | hokey lint
  test_1                             || { echo "test_1 failed"; exit 1; }   # Move the subkeys to the card
  test_2                             || { echo "test_2 failed"; exit 1; }
  test_3                             || { echo "test_3 failed"; exit 1; }
  #update_keyring                    || { echo "update_keyring failed"; exit 1; } # Clean up the GPG Keyring.  Keep it tidy.
  #do_send_key_server                || { echo "do_send_key_server failed"; exit 1; }  # publishing 
  #echo "$(uname -a)" | gpg2 --clearsign --armor --default-key $KEYID | gpg2 --decrypt --armor


}
main

