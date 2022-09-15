# User Manual

EC-crypt message encryption/signing tool. Specification can be found here: https://github.com/rand-func/ec-crypt/blob/master/docs/Documentation.md

It allows users to create encrypted text messages (and optionally, add attachments) and use any medium to transfer messages. 

Benefits over GPG: much more simpler message specification and short keys - only 52 characters.

For complete manual can be found here: https://github.com/rand-func/ec-crypt/blob/master/src/manual/manual.txt

## Installation 

### Linux (running source code)

Install dependencies: 

    sudo apt-get install python git openssl python-qt4

Clone repository:

    git clone https://github.com/rand-func/ec-crypt.git

Navigate to /src/ with cd command like this:

    cd /path/to/ec-crypt-master/src/

Allow ec-crypt main script to create folders and file, in which messages and keys will be stored:

    chmod 700 ECcrypt.py

And run program with:

    python2 ECcrypt.py
    
ec-crypt GUI will appear.

### Windows

1. Download ECcrypt: https://github.com/rand-func/ec-crypt/archive/master.zip and unzip it.
2. Navigate to /build-win/
3. [Optional] Verify signature of ECcrypt.zip. Key can be found here: https://raw.githubusercontent.com/rand-func/ec-crypt/master/pubkey.asc
4. Unzip archive ECcrypt.zip to a folder.
5. Double-click ECcrypt.exe inside a folder to run it.
6. ECcrypt is a portable application and can be stored on external USB devices. 

## Usage (GUI version)

1. To create key, go to "MasterKeys" tab and click "Generate Key" button. Note that key ID will appear in status bar. It is advised to edit alias of newly-generated key immediately. 
2. To edit Master Key alias, go to "Master Keys" tab, double-click cell in "Alias" column, enter alias and press Enter. User can enter his/her nickname in label, or what key is used for.
3. To exchange public key, go to "Master Keys" tab, choose key in drop-down  "Choose Master Key to display" list. Public key will appear in form. Double-click, copy, distribute. 
![screen1](https://raw.githubusercontent.com/rand-func/ec-crypt/master/screenshots/scr3_v2_0_0.png)
4. For communication, Contacts should be added. Upon recieving public key, go to tab "Contacts" and paste it in "Add contact"form , then click "Add" button. It is advised to edit alias immediately. 
5. To edit Contact label, on tab "Contacts" click on drop-down list "Choose contact key to edit", enter label in "Edit label" form and click button "Save label". User can enter contact nickname in label, or what key is used for.
6. To encrypt message, go to "New message" tab. Choose Master key in drop-down list and contacts in table with checkboxes. Enter text in message field. Optonally, select attachment file by pressing "..." button. When message is ready, click "Encrypt" button. 
![screen2](https://raw.githubusercontent.com/rand-func/ec-crypt/master/screenshots/scr1_v2_0_0.png)
7. To reset attachment, click "Reset Attachment" button. 
8. Message can be written in raw binary without MIME-encoding. Before encrypting, check "Binary output" radiobutton. File will be written in /encrypted/ folder
9. To decrypt MIME-encoded message, go to "Decrypt message" tab and paste message in message field, then click "Decrypt". To decrypt binary message, check "Decrypt Binary File" radiobutton, click "..." button and choose message in file dialog, then click "Decrypt". 
![screen3](https://raw.githubusercontent.com/rand-func/ec-crypt/master/screenshots/scr2_v2_0_0.png)
10. Program will notify user in status bar if message is composed for someone else, if message is corrupted, or if contact key is unknown.
11. Contacts and Master keys can be deleted. Check key in "Choose Key(s) to delete" table and then click "Delete" button.
12. It is advised to keep backup of keys and contacts by archiving /keyring/ folder and keeping it somewhere safe. Attachment size limit is around 100Mb. 


## Disclaimer

Although ec-crypt uses well-known encryption algorithms, it may still be vulnerable or may contain bugs and/or critical cryptographical flaws. For the sake of security, use additional tools. 