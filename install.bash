#!/bin/bash
  #
  ##	realise with gpg2.1.15 the following keyring:
  ## 	https://wiki.fsfe.org/TechDocs/CardHowtos/CardWithSubkeysUsingBackups
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
  # 	https://gist.github.com/woods/8970150
  #  soluce pour gpg-agent hijack par gnome-keyring-daemon ??
  # 	https://gist.github.com/ageis/5b095b50b9ae6b0aa9bf
  #
  ## Hardware
  #		http://shop.kernelconcepts.de/
  #
  ## Required
  # sudo apt install signing-party
  #

## Variables
 # path_to_trace
 path_to_trace="test"
  ## gpg-id param
  var_mail="davidgueguen@yandex.ru"
  var_name="David Gueguen"
  var_comment="''"
  ## keyring param
  var_pass_poem="@29"
  var_key_type="1"
  var_key_lenght="1024"
  var_pref="SHA512 SHA384 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed"
  var_expiracy="2y"
  ## public key web path
  asci_public_key_name="david.gueguen.txt"
  var_web_path="https://choucroutage.com//$asci_public_key_name"
  ## optional
  var_photo_path="/home/david/choucroutage/MySave/desktop/pic/green_reduced.jpg"

  check_card_is_here(){
 ## ensure openpgp card is readable
  ## exit the whole sript if not
  #
  echo
  echo "-->> Processing if 'gpg2 --card-status' returns no error ... "
  local cmd=$(gpg2 --card-status)
  if [[ "$cmd" == *"Reader ...........:"* ]]; then
    echo  "OK, GPG card readable "
  else
    echo
    echo  "FAIL ! No GPG card readable" 
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
    echo  "OK, processing main keys generations "
  else
    echo  "FAIL ! This mail id is already linked to referenced private key" 
    echo
    echo "$(gpg2 --list-secret-keys --with-fingerprint | grep -A10 $var_mail)"
    exit 1			 
  fi
}
gen_main_key(){
 #  Generate main keyring
 ## primary keyring: 2 pairs of asymetrical keys ! do not change 
  # Key-Usage:    sign cert
  # Subkey-Usage:   encrypt
  # 
  #  gpg2 gen key with no interaction 'technique EOF pour --full-gen-key'
  # 	https://gist.github.com/woods/8970150
  printer 
  printer    "-->> Generating main keyring: a SC keypair and E keypair ... " 
  touch gen_key_script         # creating file to gen key in gpg batch mode
  echo " 
  Key-Type:         $var_key_type 
  Key-Usage:        sign cert
  Key-Length:       $var_key_lenght
  Subkey-Type:      $var_key_type
  Subkey-Usage:     encrypt
  Subkey-Length:    $var_key_lenght
  Name-Real:        $var_name
  Name-Comment:     $var_comment
  Name-Email:       $var_mail
  Keyserver:        $var_web_path
  Expire-Date:      $var_expiracy
  Passphrase:       $var_pass_poem
  Preferences:      $var_pref
  " > gen_key_script  # creating SC and E keys
  gpg2 --batch --full-gen-key gen_key_script  &> /dev/null 
  #  gpg2 --list-only --list-packets < *.gpg
  printer "Done."
}
printer(){
 ## write output on both terminal and repport file
  #
  echo $@ >> gen_key_report
  echo $@
}

get_key_SC_fpr(){
 #  get keyring id hash and individual key hash for newly created passkey
 ## gpg2 -k --with-colons option emits the output in a stable, machine-parseable format
  #
  printer 
  printer "-->> Getting keyring id ... " 
  # fingerprint and keygrip"
  key_SC_fpr=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep fpr | awk -F: '{ print $10 }')
  key_SC_grp=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep grp | awk -F: '{ print $10 }') 
  key_SC_uid=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep uid | awk -F: '{ print $8 }')
  # encryption key id 
  key_E_fpr=$(gpg2  --no-verbose --with-colons --with-keygrip -k $var_mail | grep -A3 $var_mail | grep fpr | awk -F: '{ print $10 }')
  key_E_grp=$(gpg2  --no-verbose --with-colons --with-keygrip -k $var_mail | grep -A3 $var_mail | grep grp | awk -F: '{ print $10 }') 
  # test if all present
  if [[ -z "$key_SC_fpr" || -z "$key_SC_grp" || -z "$key_SC_uid" || -z "$key_E_fpr" || -z "$key_E_grp" ]]; then
    printer  "FAIL ! while getting keyring components, values:" 
    printer $key_SC_fpr, $key_SC_grp, $key_SC_uid, $key_E_fpr, $key_E_grp
    printer
    exit 1  
  else
    printer ""
    printer "Keyring after main keys generation:  " 
    printf "$(gpg2 --with-keygrip -k  --no-verbose $var_mail) \n"                    >> gen_key_report
    printer " keyring for $var_mail  uid: $key_SC_uid"
    printer "fingerprint and grip key SC: $key_SC_fpr, $key_SC_grp"
    printer "fingerprint and grip key E : $key_E_fpr, $key_E_grp"
    printer "OK"     
  fi
  printer "Done."
}
publish_key_SC_fpr(){
 ## 
  #
  printer 
  printer    "-->> Publishing master keyring: a SC keypair and a E keypair ... " 
  # report
  # export to file
  gpg2 --no-verbose --export             --armor --yes $key_SC_fpr > pub.main.txt            
  gpg2 --no-verbose --export-secret-key  --armor --yes $key_SC_fpr > priv.keys.txt            
  # export to pdf QR code
  # 
  printer "Done."
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
  local cmd="addphoto\n$var_photo_path\nsave"
  echo -e $cmd | gpg2  --command-fd 0 --status-fd 2 --edit-key $key_SC_fpr

  printer  "$(gpg2  --no-verbose -k $var_mail | grep -A1 $var_mail)"

  printer "Done."
}
gen_sub_keys(){
## Generates 3 sub keys to keyring
  # https://superuser.com/questions/1191933/gpg2-quick-addkey-without-password-prompt/1191943#1191943
  #
  printer
  printer "-->> Generating sub keyring ... " 
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $key_SC_fpr rsa$var_key_lenght sign 1y    &> /dev/null # gpg2 --quick-addkey $key_SC_fpr rsa$var_key_lenght sign 1y
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $key_SC_fpr rsa$var_key_lenght encrypt 1y &> /dev/null   # gpg2 --quick-addkey $key_SC_fpr rsa$var_key_lenght encrypt 1y
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $key_SC_fpr rsa$var_key_lenght auth 1y    &> /dev/null # gpg2 --quick-addkey $key_SC_fpr rsa$var_key_lenght auth 1y
  printer "Export keyring to pdf: " 
  gpg2 --export $key_SC_fpr | paperkey --output-type raw | dmtxwrite -e 8 -f PDF > pub.ring.pdf
  printer  "Done."
}
mv_subkeys_to_card(){
 ## Move subkeys to cards
  #   sign subkey:  key n2        encrypt subkey: key n3        auth key:   key n4
  #
  printer
  printer  "-->> Subkeys exportation to card and removal from keyring:"
  local cmd="key 2\nkeytocard\n1\ny\nkey 2\nkey 3\nkeytocard\n2\ny\nkey 3\nkey 4\nkeytocard\n3\ny\nsave\nY\n"
  echo -e $cmd | gpg2 --no-verbose --command-fd 0 --status-fd 2 --edit-key $key_SC_fpr &> /dev/null
  printer  "Done."
}
rm_master_keyring_encryption_key(){
 ## removing master key from keyring	
  #
  printer
  printer  "-- >> main encryption public key removal:"
  local cmd="key 1\ndelkey\ny\nsave\n"
  echo -e $cmd | gpg2 --command-fd 0 --status-fd 2 --edit-key $key_SC_fpr 
  echo "$(gpg2 -K)" >> gen_key_report
  printer "Done."
}
get_subkeys_id(){
 ## Get keys ids 
  # detection by 'sub' only after Remove main encryption subkey
  # keyring identity; the --with-colons option emits the output in a stable, machine-parseable format
  #
  printer
  printer  "-->> get subkeys id ... " 
  local subkeys_edit=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -A12 $var_mail | grep fpr | awk -F: '{ print $10 }')
  subkey_S_fpr=$(echo $subkeys_edit | awk '{print $2}')
  subkey_E_fpr=$(echo $subkeys_edit | awk '{print $3}')
  subkey_A_fpr=$(echo $subkeys_edit | awk '{print $4}')
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
    printer "OK"      
  fi
  printer "Done."
}
publish_keys_cards_to_file(){
 ## Sub key exportation
  # 
  printer
  printer "-->> Publishing sub keys to main keyring: a S keypair, a E keypair, a A keypair"
  printer "Keyring after subkeys generation"
  printf "$ $(gpg2 --with-keygrip -k  --no-verbose $var_mail) \n"                    >> gen_key_report
  printer
  printer "OK, keyring for $var_mail  uid: $key_SC_uid"
  printer "fingerprint and grip subkey S: $subkey_S_fpr, $subkey_S_grp"
  printer "fingerprint and grip subkey E: $subkey_E_fpr, $subkey_E_grp"
  printer "fingerprint and grip subkey A: $subkey_A_fpr, $subkey_A_grp"
  printer
  printer "-->> Sub key exportation to file:"
  gpg2 --export-secret-subkeys $key_SC_fpr > priv.subkeys.txt 	
  gpg2 --export-secret-subkeys $key_SC_fpr | paperkey --output-type raw | dmtxwrite -e 8 -f PDF > priv.subkeys.pdf
  echo "Done."
}
rm_secret_master_key(){
 ## Private key removal from keyring
  # 	
  echo
  echo "-->> Private key removal from keyring:"
  gpg2 --no-verbose --delete-secret-keys $key_SC_fpr
  echo "Private key has been removed:"
  gpg2 -K
  echo "Done."
}
import_subkeys_stubs(){
 ## Sub key importation
  # Reimport the subkey stubs
  #
  echo
  echo "-->> Sub key importation:" 
  gpg2 --import pub.main.txt
  gpg2 --import priv.subkeys.txt
  rm /home/$HOME/.gnupg/private-keys-v1.d/$key_E_grp
  echo -e $cmd | gpg2 --command-fd 0 --status-fd 2 --edit-key $key_SC_fpr
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
build_gpg.conf(){
 # Minimum modification to gpg.conf 
 printer
 printer "-->> Modifying gpg.conf:"
  # hidden-to-encrypt
  awk '!/hidden-encrypt-to/'            /home/$USER/.gnupg/gpg.conf > /home/$USER/.gnupg/gpg.conf_temp
  mv  /home/$USER/.gnupg/gpg.conf_temp  /home/$USER/.gnupg/gpg.conf
  printf "hidden-encrypt-to 0x%s!\n"    $key_E_fpr                   >> /home/$USER/.gnupg/gpg.conf
  printf "hidden-encrypt-to 0x%s!\n"    $subkey_E_fpr                >> /home/$USER/.gnupg/gpg.conf
  # default recipient
  awk '!/default-recipient/'            /home/$USER/.gnupg/gpg.conf > /home/$USER/.gnupg/gpg.conf_temp
  mv  /home/$USER/.gnupg/gpg.conf_temp  /home/$USER/.gnupg/gpg.conf
  printf "default-recipient %s\n"        $var_mail                  >> /home/$USER/.gnupg/gpg.conf
  # WORKAROUND
  # https://lists.gnupg.org/pipermail/gnupg-users/2016-August/056571.html 
  awk '!/default-key/'                  /home/$USER/.gnupg/gpg.conf > /home/$USER/.gnupg/gpg.conf_temp
  mv /home/$USER/.gnupg/gpg.conf_temp   /home/$USER/.gnupg/gpg.conf
  printf "default-key %s\n"             $key_E_fpr                   >> /home/$USER/.gnupg/gpg.conf
  printf "default-key %s\n"             $subkey_E_fpr                >> /home/$USER/.gnupg/gpg.conf
  printer "Done."
}
do_send_key_server(){
 ## send public key to keyserver
 echo
 echo "-->> keyring online:"
  # gpg2 --send-keys --keyserver keyserver.ubuntu.com $key_SC_fpr
   #
  #gpg2 --export-ssh-key $key_SC_fpr --yes --armor > output-sshkey.sec 
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
  mkdir -p $path_to_trace
  rm $path_to_trace/*
  cd $path_to_trace
  cat /dev/null > gen_key_report 	# initiate gen_key_report to void
  pkill -f gnome-keyring-daemon
  gpgconf --kill gpg-agent      
 check_card_is_here                || { echo "command1 failed"; exit 1; }   # attempts to read card, stop if can't
 check_mail_id_is_not_used         || { echo "command2 failed"; exit 1; }   # attempts to create key, stop if exists
 gen_main_key                      || { echo "command3 failed"; exit 1; }   # Create a GnuPG secret key
  get_key_SC_fpr                    || { echo "command5 failed"; exit 1; }    # getting main key hash
  publish_key_SC_fpr                || { echo "command4 failed"; exit 1; }
  add_photo					                || { echo "command6 failed"; exit 1; }    # incorporating photo to keyring
  gen_sub_keys  				            || { echo "command7 failed"; exit 1; }    # Generating subkeys for the card
  get_subkeys_id                    || { echo "command8 failed"; exit 1; }
  build_gpg.conf                    || { echo "command9 failed"; exit 1; }
  mv_subkeys_to_card                || { echo "command10 failed"; exit 1; }   # Move the subkeys to the card
  rm_master_keyring_encryption_key     || { echo "command11 failed"; exit 1; }   # Remove main encryption subkey	
  publish_keys_cards_to_file		    || { echo "command12 failed"; exit 1; }   # Export secret subkeys
  rm_secret_master_key				      || { echo "command13 failed"; exit 1; }   # Remove secret master key
  import_subkeys_stubs		          || { echo "command14 failed"; exit 1; }   # Reimport the subkey stubs
  do_send_key_server                || { echo "command15 failed"; exit 1; }  # publishing	
  #update_keyring || { echo "command15 failed"; exit 1; } 

  # Clean up the GPG Keyring.  Keep it tidy.


}
main

