#!/bin/bash
##
 ##############################################################
 # 
 #   @category    bash script
 #   @package     gnupg
 #   @author      bourinus
 #   @copyright   2019 - choucroutage.com
 #   @license     Attribution 4.0 International
 #   @version     1.0
 #   @link        https://github.com/bourinus/gpg_SmartCard_generation
 #   @see         
 #                https://wiki.fsfe.org/TechDocs/CardHowtos/CardWithSubkeysUsingBackups             [DEPRECATED]
 #                https://alexcabal.com/creating-the-perfect-gpg-keypair                            [DEPRECATED]
 #                https://riseup.net/en/security/message-security/openpgp/best-practices            [DEPRECATED]
 #                https://framasphere.org/posts/1733780
 #                https://www.alessandromenti.it/blog/2017/01/transitioning-new-gpg-keypair.html    [GUIDE]
 #   @tech
 #                https://gist.github.com/woods/8970150             
 #                https://suva.sh/posts/gpg-ssh-smartcard-yubikey-keybase/#gnupg-version
 #                https://eferdman.github.io/debian/outreachy/2016/12/20/Debian-2w/
 #                https://superuser.com/questions/1191963/gpg2-edit-key-addphoto-keytocard-without-password-prompt
 #                https://superuser.com/questions/1191933/gpg2-quick-addkey-without-password-prompt/1191943#1191943
 #
 #   @Hardware    https://shop.nitrokey.com/
 #                https://www.yubico.com/
 #
 ##############################################################
 ## Goal
 #   generate main keyring is stored in a vault while
 #   a gpgcard is used to carry its subkeys
 #
 #   keys  Public  Private   gpgcard  desktop          
 #     SC    pub     sec       sec#     sec#               
 #     S     sub     ssb       ssb>     ssb#            
 #     E     sub     ssb       ssb>     ssb#            
 #     A     sub     ssb       ssb>     ssb#  
 #
 #   Symbol # after key means the secret key is not usable
 #   Symbol > after key means the secret key is     usable
 #
 ############################################################## 
## path of the script
  path="/home/david/owncloud/cloud.ch/DavidDesktop/work/gpg";
  ## gpg-id param
  var_mail="davidgueguen@yandex.ru"
  var_name="David Gueguen"
  var_usrname_machine="david"
  var_comment="''"
  ## keyring param
  var_pass_poem="@"
  var_key_type="1"
  var_key_lenght="2048"
  var_pref="SHA512 SHA384 SHA256 AES256 BZIP2 ZLIB ZIP Uncompressed"
  var_expiracy="2y"
  ## public key web path
  asci_public_key_name="david.gueguen.txt"
  var_web_path="https://choucroutage.com//$asci_public_key_name";
  ## optional
  var_photo_path="/home/david/Desktop/green_reduced.jpg";
  path_test="$path/folder/test";
  path_keyrings="$path/folder/keyrings";
  path_report="$path/folder/report/report";
  test_string="Hello World  ..!"
##
 # 
print_cmd(){
 ##  write output on both terminal and repport file
  ##
  printf  "$ %b\\n" "$*" >> $path_report
  printf  %b\\n "$($*)" >> $path_report
  printf  %b\\n "$*"
}
print_txt(){
 ##  write output on both terminal and repport file
  ##
  printf  %b\\n "$*" >> $path_report
  printf  %b\\n "$*"
}
setup_stuffs() {
 ## renew working folder
  ## trying to be cautious
  print_txt ""
  print_txt "-->> Seting up working folder ... " 
  # clean working folder
  mkdir -p $path/folder
  rm -r $path/folder/*
  cd $path/folder
  mkdir -p test
  mkdir -p report
  mkdir -p keyrings
  # initiate $path_report to void
  cat /dev/null > $path_report
  print_txt "A keyring for $var_mail was started being built at $date" "" ""
  # Kill gpg-agent if it is running
  pkill -f gnome-keyring-daemon
  gpgconf --kill gpg-agent  
  print_txt ""
  print_txt "-->> Moving old .gnupg ... " 
  # export all publikeys in your keyring in order not to have to fetch them again later
  gpg --export -a > allpublickeys.asc
  mkdir -p ~/.gnupg
  mkdir -p ~/.gnupg_old
  sudo rm -r ~/.gnupg_old
  sudo mv ~/.gnupg ~/.gnupg_old
  # set correct right for .gnupg directory
  mkdir ~/.gnupg
  chmod 700 ~/.gnupg
  # default for gpa.conf
  echo "advanced-ui
  show-advanced-options
  detailed-view
  " > ~/.gnupg/gpa.conf  
  # default for gpg.conf
  cp $path/reference.conf ~/.gnupg/gpg.conf
  print_txt "OK. Done, clean working folder, .gnupg/ saved."
}

check_softs(){
 ## ensure mandatory softs presence
  ## exit the whole sript if not
  #
  print_txt
  print_txt "-->> Checking softs installed ... "
  dpkg -l gnupg2          |grep -q gnupg2           ||sudo apt-get install -y gnupg
  dpkg -l libccid         |grep -q libccid          ||sudo apt-get install -y libccid
  dpkg -l scdaemon        |grep -q scdaemon         ||sudo apt-get install -y scdaemon
  dpkg -l opensc          |grep -q opensc           ||sudo apt-get install -y opensc
  dpkg -l hopenpgp-tools  |grep -q hopenpgp-tools   ||sudo apt-get install -y hopenpgp-tools
  dpkg -l pinentry-curses |grep -q pinentry-curses  ||sudo apt-get install -y pinentry-curses
  dpkg -l signing-party   |grep -q signing-party    ||sudo apt-get install -y signing-party
  dpkg -l hopenpgp-tools  |grep -q hopenpgp-tools   ||sudo apt-get install -y hopenpgp-tools
  dpkg -l paperkey        |grep -q paperkey         ||sudo apt-get install -y paperkey
  print_txt "OK. Done, required softs are present."
}
check_card_is_here(){
 ## ensure openpgp card is readable
  ## exit the whole sript if not
  #
  print_txt
  print_txt "-->> Processing if 'gpg2 --card-status' returns no error ... "
  local cmd=$(gpg2 --card-status)
  if [[ "$cmd" == *"Reader ...........:"* ]]; then
    print_txt  "OK. Done, GPG card present & readable."
  else
    print_txt
    print_txt "FAIL ! No GPG card readable" 
    exit 1
  fi
}
check_mail_id_is_not_used(){
 ## ensure mail_id is not linked to a secret key
  ## exit the whole sript if not
  #
  print_txt
  print_txt "-->> Processing if $var_mail id is not in gpg public keys list ... "
  local cmd=$(gpg2 --list-secret-keys | grep $var_mail)
  if [[ -z "$cmd" ]]; then
    print_txt "OK. Done, Mail address unlnown in .gnupg."
  else
    print_txt "FAIL ! This mail id is already linked to referenced private key" 
    exit 1       
  fi
}
generate_main_keys(){
 ##  Generate main keyring
  ## primary keyring: 2 pairs of asymetrical keys ! do not change 
  # 
  print_txt ""
  print_txt    "-->> Generating main keyring: SC keypair and E keypair ..." 
  touch report/gen_key_SCript         # creating file to gen key in gpg batch mode
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
  " > report/gen_key_SCript  # creating SC and E keys
  gpg2 --batch --full-gen-key report/gen_key_SCript  &> /dev/null 
  rm report/gen_key_SCript
  #
  print_cmd "gpg2 -K"
  print_txt "OK. Done, main keyring generated."
}
get_keys_fingerprints(){
 ##  get keyring id hash and individual key hash for newly created passkey
  ## gpg2 -k --with-colons option emits the output in a stable, machine-parseable format
  #
  print_txt 
  print_txt "-->> Getting keyring id ... " 
  # fingerprint, keygrip and uid
  key_SC_fpr=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep fpr | awk -F: '{ print $10 }')
  key_SC_grp=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep grp | awk -F: '{ print $10 }') 
  key_SC_uid=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -B3 $var_mail | grep uid | awk -F: '{ print $8 }')
  # test if all present
  if [[ -z "$key_SC_fpr" || -z "$key_SC_grp" || -z "$key_SC_uid"  ]]; then
    print_txt "FAIL !! while getting keyring components, values:" 
    print_txt $key_SC_fpr, $key_SC_grp, $key_SC_uid
    print_txt
    exit 1  
  else
    print_txt "Keyring after main keys generation, for $var_mail:  " 
    print_cmd "gpg2 -k --no-verbose $var_mail"
    print_txt "key_SC_uid: $key_SC_uid"
    print_txt "key_SC_fpr: $key_SC_fpr"
    print_txt "key_SC_grp: $key_SC_grp"
  fi
  print_txt "OK. Done, hash values for main key get."
}
export_master_keys(){
 ## 
  ##
  print_txt ""
  print_txt "-->> Publishing master keyring ..." 
  gpg2 --yes --no-verbose --export  --armor               $key_SC_fpr! > $path_keyrings/master_key_SC.pub
  gpg2 --yes --no-verbose --export-secret-keys  --armor   $key_SC_fpr! > $path_keyrings/master_key_SC.key
  # gpg2 --export-secret-key $key_SC | paperkey --output my-secret-key.gpg 
  #  gpg2 --export-secret-key $key_SC | paperkey | dmtxwrite -e 8 -f PDF > pub.ring.pdf
  # export to pdf QR code
  # 
  print_cmd "ls"
  print_txt "OK. Done, keyring written."
}
rm_primary_encryption_key(){
 ## [NOT USED]
  ## removing master key from keyring  
  ## Beware: make sense only if 5 keys are generated
  print_txt
  print_txt  "-- >> Primary encryption key removal:"
  local cmd="key 1\ndelkey\ny\nsave\n"
  echo -e $cmd | gpg2 --command-fd 0 --status-fd 2 --edit-key $key_SC_fpr 
  #
  print_cmd "gpg2 -K" 
  print_txt "OK. Done, primary encryption key removed."
}
add_photo(){
 ## Add photo to key  
  ##
  print_txt
  print_txt  "-->> Adding photo ..." 
  local cmd="addphoto\n$var_photo_path\ny\nsave\n"
  echo -e $cmd | gpg2  --command-fd 0 --status-fd 2 --edit-key $key_SC_fpr
  print_cmd  "gpg2  --no-verbose -k $var_mail"
  print_txt "OK. Done, photo added."
}
gen_sub_keys(){
 ## Generates 3 sub keys to keyring
  ##
  print_txt
  print_txt "-->> Generating sub keyring ... " 
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $key_SC_fpr rsa$var_key_lenght sign 1y    &> /dev/null; # gpg2 --quick-addkey $key_SC rsa$var_key_lenght sign 1y
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $key_SC_fpr rsa$var_key_lenght encrypt 1y &> /dev/null; # gpg2 --quick-addkey $key_SC rsa$var_key_lenght encrypt 1y
  echo $var_pass_poem | gpg2 --no-verbose --pinentry-mode loopback --batch --no-tty --yes --passphrase-fd 0 --quick-addkey --passphrase '' $key_SC_fpr rsa$var_key_lenght auth 1y    &> /dev/null; # gpg2 --quick-addkey $key_SC rsa$var_key_lenght auth 1y
 # print_cmd "Export keyring to pdf: " 
 # gpg2 --export $key_SC | paperkey --output-type raw | dmtxwrite -e 8 -f PDF > pub.ring.pdf
   print_cmd "gpg2 -K" 
   print_txt "OK. Done, sub-keyring generated"
}
get_subkeys_id(){
 ## Get keys ids 
  ## detection by 'sub' only after Remove main encryption subkey
  # keyring identity; the --with-colons option emits the output in a stable, machine-parseable format
  #
  print_txt
  print_txt  "-->> get subkeys id ... " 
  local subkeys_edit=$(gpg2 --no-verbose --with-colons --with-keygrip -k $var_mail | grep -A12 $var_mail | grep fpr | awk -F: '{ print $10 }')
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
    print_txt  "FAIL ! while getting keyring components, values:" 
    print_txt $subkey_S_fpr, $subkey_E_fpr, $subkey_A_fpr, $subkey_S_grp, $subkey_E_grp, $subkey_A_grp
    print_txt
    exit 1 
  else
    print_txt "Subkeys after generation"
    print_txt
    print_txt "OK. Done, keyring for $var_mail  uid: $key_SC_uid S,E,A"
    print_txt "subkey_S_fpr: $subkey_S_fpr"
    print_txt "subkey_S_grp: $subkey_S_grp"
    print_txt "subkey_E_fpr: $subkey_E_fpr"
    print_txt "subkey_E_grp: $subkey_E_grp"
    print_txt "subkey_A_fpr: $subkey_A_fpr"
    print_txt "subkey_A_grp: $subkey_A_grp"
  fi
  print_cmd "OK. Done, main key Ids obtained."
}
mv_subkeys_to_card(){
 ## Move subkeys to cards
  ##   sign subkey:  key 1        encrypt subkey: key 2        auth key:   key 3
  #
  print_txt
  print_txt  "-->> Move subkeys to card (which removal them keyring)"
  local cmd="key 1\nkeytocard\n1\ny\nkey 1\nkey 2\nkeytocard\n2\ny\nkey 2\nkey 3\nkeytocard\n3\ny\nsave\n"
  echo -e $cmd | gpg2 --yes --no-verbose --command-fd 0 --status-fd 2 --edit-key $key_SC_fpr &> /dev/null
  print_cmd "gpg2 -K" 
  print_txt  "OK. Done, Key in dongle."
}
build_gpg.conf(){
 ## Minimum modification to gpg.conf 
  print_txt
  print_txt "-->> Modifying gpg.conf:"
  if [ ! -e "/home/$USER/.gnupg/gpg.conf" ] ; then
      touch "/home/$USER/.gnupg/gpg.conf"
  fi
  printf "hidden-encrypt-to %s\n"         $subkey_E_fpr >> ~/.gnupg/gpg.conf;
  printf "default-recipient %s\n"         $var_mail >> ~/.gnupg/gpg.conf;
  #printf "default-key %s\n"               $subkey_S_fpr >> /home/$USER/.gnupg/gpg.conf
  printf "# PIN entry program: 
  #choose one of /usr/bin/pinentry-{curses,emacs,gnome3, gtk-2,qt,tty}.
  pinentry-program /usr/bin/pinentry-gnome3
  " > ~/.gnupg/gpg-agent.conf

  print_txt "OK. Done, new key added to gpg.conf"
}
export_subkey_stubs(){
 ## Sub keyring exportation to files
  ##
  print_txt
  print_txt "-->> Sub key exportation to file:"
  gpg2 --yes --no-verbose --export-secret-subkeys --armor   $key_SC_fpr > $path_keyrings/subkeys_dongle.key
  gpg2 --yes --no-verbose --export-ssh-key --armor          $key_SC_fpr > $path_keyrings/public_ssh.key
  print_cmd "gpg2 --card-status"
  print_txt "OK. Done, subkeys exported."
}
rm_primary_signing_key(){
 ## Primary signing key removal from keyring
  ## !! no key manipulation after this point without import
  #   
  print_txt
  print_txt "-->> Private key removal from keyring:"
  gpg2 --yes --no-verbose --delete-secret-keys  $key_SC_fpr
  gpg2 --card-status
  # End of keyring construct
  print_cmd "gpg2 -K" 
  print_txt "OK. Done, primary key removed from keyring."
  # Checking that best practices are followed
  gpg2 --export $key_SC_fpr | hokey lint
  # Copy a report for further use
  cp $path_report $path/
}
import_subkeys_stubs(){
 ## [NOT USED]
  ## Reimport the subkey stubs
  #
  echo
  echo "-->> Sub key importation:" 
  #gpg2 --import pub.main.txt
  gpg2 -K
  gpg2 --import $keyrings/subkeys_dongle.key 
  gpg2 --card-status
  gpg2 -K
  print_txt "Done."
  print_txt
  print_txt "  ---  KEYRING BUILDING COMPLETED  ---  " 
  print_txt
  print_txt " On this computer: " 
  print_txt "    Private part: gpg2 -K" $(gpg2 -K)
  print_txt "    Public part:  gpg2 -k" $(gpg2 -k)
  print_cmd "gpg2 --card-status"
  print_txt "Done."
}
test_1(){
  print_txt 
  print_txt "-->> Test1: encryption to defaut recipient ... ";
  print_txt "Expected behaviour with dongle inserted: pin asked for decryption & 'hello World'";
  echo "$test_string" > $path_test/hello.txt;
  gpg2 --yes -o $path_test/test1.gpg -e $path_test/hello.txt >> $path_report
  gpg2 --yes -o $path_test/test1.txt -d $path_test/test1.gpg >> $path_report
  print_cmd "cat $path_test/test1.txt"
  if [ "$test_string" == "$(cat $path_test/test1.txt)" ] ;then
    printf "\e[32m✓ reverse result correct. \033[0m\n";
  else
    printf "\e[31m✘ reverse result incorrect. \033[0m\n";
  fi
}
test_2(){
  print_txt 
  print_txt "-->> Test2: signature to defaut recipient ... ";
  print_txt "Expected behaviour pin asked for sign, sign_cpt to 1 & 'hello World'";
  echo "$test_string" > $path_test/hello.txt;
  gpg --yes -o $path_test/test2.gpg -s $path_test/hello.txt
  gpg --yes -o $path_test/test2.txt -d $path_test/test2.gpg
  print_cmd "cat $path_test/test2.txt"
  if [ "$test_string" == "$(cat $path_test/test2.txt)" ] ;then
    printf "\e[32m✓ reverse result correct. \033[0m\n";
  else
    printf "\e[31m✘ reverse result incorrect. \033[0m\n";
  fi
}
test_3(){
  print_txt 
  print_txt "-->> Test3: encryption & encryption to defaut recipient ... ";
  echo_red "Expected behaviour pin asked for signature & 'hello World'";
  echo "$test_string" > $path_test/hello.txt;
  gpg --yes -o $path_test/test3.gpg -s -e $path_test/hello.txt
  gpg --yes -o $path_test/test3.txt -d $path_test/test3.gpg
  print_cmd "cat $path_test/test3.txt"
  if [ "$test_string" == "$(cat $path_test/test3.txt)" ] ;then
    printf "\e[32m✓ reverse result correct. \033[0m\n";
  else
    printf "\e[31m✘ reverse result incorrect. \033[0m\n";
  fi
}
do_send_key_server(){
 ## send public key to keyserver
  ##
  print_txt
  print_txt "-->> keyring online:"
  # gpg2 --send-keys --keyserver keyserver.ubuntu.com key_SC_fpr
  #gpg2 --export-ssh-key key_SC_fpr --yes --armor > output-sshkey.sec 
  print_txt "Done." 
}
update_keyring(){
 ## Clean up the GPG Keyring 'Keep it tidy'.
  ## source: blog.lavall.ee
  # 
  print_txt
  print_txt  "-->> Updating keyring ... " 
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
  for key_SC_fpr in $(gpg2 -k | grep ^pub | grep -v expired: | grep -v revoked: | cut -d/ -f2 | cut -d' ' -f1); do
    echo -n "$key_SC_fpr"
    gpg2 --batch --quiet --edit-key "$key_SC_fpr" check clean cross-certify save quit > /dev/null 2>&1
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
 print_txt "Done."
}




main(){
 ## hard testing: first fail condamn all
  # no intermediate verication performed
  setup_stuffs                       || { echo "setup_stuffs failed";                 exit 1; } 
  check_softs                        || { echo "check_softs failed";                  exit 1; } 
  check_card_is_here                 || { echo "check_card_is_here failed";           exit 1; }   # attempts to read card, stop if can't
  check_mail_id_is_not_used          || { echo "check_mail_id_is_not_used failed";    exit 1; }   # attempts to create key, stop if exists
  generate_main_keys                 || { echo "generate_main_keys failed";           exit 1; }   # Create a GnuPG secret key
  get_keys_fingerprints              || { echo "get_keys_fingerprints failed";        exit 1; }   # getting main key hash
  export_master_keys                 || { echo "export_master_keys_fpr failed";       exit 1; }
  rm_master_encryption_key           || { echo "rm_master_encryption_key failed";     exit 1; }   # Remove main encryption subkey  
  gen_sub_keys                       || { echo "gen_sub_keys failed";                 exit 1; }   # Generating subkeys for the card
  get_subkeys_id                     || { echo "get_subkeys_id failed";               exit 1; }
  build_gpg.conf                     || { echo "build_gpg.conf failed";               exit 1; }
  add_photo                          || { echo "add_photo failed";                    exit 1; }   # incorporating photo to keyring
  export_subkey_stubs                || { echo "export_subkey_stubs failed";          exit 1; }   # Export secret subkeys
  mv_subkeys_to_card                 || { echo "mv_subkeys_to_card failed";           exit 1; }   # Move the subkeys to the card
  rm_primary_signing_key             || { echo "rm_primary_signing_key failed";       exit 1; }   # Remove secret master key
  test_1                             || { echo "test_1 failed";                       exit 1; }   # Move the subkeys to the card
  test_2                             || { echo "test_2 failed";                       exit 1; }
  test_3                             || { echo "test_3 failed";                       exit 1; }
  update_keyring                     || { echo "update_keyring failed";               exit 1; }   # Clean up the GPG Keyring.  Keep it tidy.
}
main

