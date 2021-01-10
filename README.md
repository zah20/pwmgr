## Password Manager
Commandline password manager coded from scratch in python


![alt tag](resources/images/pw_gen.png)


## Current Features:
- Generates secure password & stores user information in encrypted containers
- Encrypts & decrypts database completely in memory
- Doesn't require managing gpg keys & doesn't doesn't leak meta data information
- Helpful commandline interface, similar to pass (unix password manager)
- Can migrate existing password database from pass
- Can add, search, edit, remove information & copy password to clipboard


## Work in progress
- Cloud based automatic password synchronization (Google Drive, ssh ) 
- Pop up search with autocomplete feature for passwords
- Securely overwrite memory segments after usage
- Export / import passwords via csv format


## Requirements:
- Python 3.x
- Python modules: colorama, keyring, pyperclip, platform, getpass, fernet
- Linux / Unix operating system (recommended)


## Installation:

```
pip3 install --user colorama, keyring, pyperclip, platform, getpass, fernet
```


## Usage

```
    pwmgr [add, -a]

          Allows the user to add a new record to the database.


    pwmgr [edit, -e] [record number]

          Allows the user to edit the specified entry in the database.


    pwmgr [search, -s] [group | site | email | username | all] keyword

          Search by group, site, ..., etc.

          All records that match the specified keyword will be shown.

          * By default the search keyword without any other additional
            parameters uses the 'search all' function.
            e.g: 'pwmgr search some_keyword'

          group     - Search for the keyword by group
          site      - Search for the keyword by website
          email     - Search for the keyword by email address
          username  - Search for the keyword by username
          all       - Search for the keyword in group, site,
                      email & username


    pwmgr [show, -o] [record number]

          Show details about the specific record from the database.

          * By defaut show command without a record number,
            displays a brief summary of the entire database

          * Multiple comma separated values can also be passed
            to the show command & it will display detailed
            information about those records.
            e.g: 'pwmgr show '1,2,3'


    pwmgr [copy, -c] [record number]

          Copies the password for the specific entry to the clipboard.


    pwmgr [rm, -d] [record number]

          Remove the specified entry from the database.

          * This command also accepts comma separated values &
            can remove multiple entries. e.g: 'pwmgr rm 2,3,4'


    pwmgr key [show | reset]

          show  - Displays the current key that is being used
                  for encryption.

          reset - Allows the user to change the master key.
                  The user will be prompted for the old password.


    pwmgr keyring reset

          Allows the user to remove password from keyring.

          * This command can be useful for example if you have
            a different password database & you want to remove
            the previous password that was set on the keyring


    pwmgr import pass

          Scans for Pass (Unix Password Manager) password store
          & imports all relevant information if they exist.

          * This feature is experimental & has not been thoroughly
            tested yet. Although there are no observable bugs
            but if you do encounter one, please report to my email.


    pwmgr [sync, -y] [enable | disable]

          Allow syncing of encrypted database to Google Drive.

          * This feature is being worked on & is not currently available


    pwmgr [sync, -y] set [daily | weekly | monthly]

          Allow the database to be synced daily / weekly / monthly.

          * This feature is being worked on & is not currently available


    pwmgr [sync, -y] now

          Sync the entire database immediately.

          * This feature is being worked on & is not currently available


    pwmgr [help, -h]

          Show this text.

```





