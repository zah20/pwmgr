#!/usr/bin/python3

import csv, wx, base64
import subprocess, sys, os
import termios, tty, random
from database_pwmgr import Record, ManageRecord, \
        IncorrectKeyException, IncorrectPasswordException, IntegrityCheckFailedException, \
        AllocateSecureMemory, UnsupportedFileFormatException, SecureClipboardCopyFailedException, \
        MemoryAllocationFailedException, KeyFileInvalidException
from random import seed, randint
from getpass import getpass
from getch import getch
from time import sleep


"""
Password Manager

Copyright © 2023 Zubair Hossain

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""


global __title__, __author__, __email__, __version__, __last_updated__, __license__

__title__        =  'Password Manager'
__author__       =  'Zubair Hossain'
__email__        =  'zhossain@protonmail.com'
__version__      =  '2.6.1'
__last_updated__ =  '06/16/2023'
__license__      =  'GPLv3'


global enc_db_handler, app_name, file_name, password_in_keyring, \
       pw_master, config, config_file, db_file_path, \
       theme, field_color_fg, term_bar_color, term_len_h, term_len_v
####### All configs / database is stored under '~/.config/pwmgr/'
password_in_keyring=False
enc_db_handler = None
file_name = 'db.enc'
app_name = 'pwmgr'
term_len_h = 75
term_len_v = 30
pw_master = ''
config = {}
theme = 1
config_file = ''
db_file_path = ''
field_color_fg = ''
term_bar_color = ''


#===========================================================================
#                Database polling & argument parsing functions             #
#===========================================================================


def parse_args():

    """
    Parses commandline arguments & executes the desired functions

    """

    global term_len_h, term_len_v, config, theme, field_color_fg, term_bar_color

    argument_length = len(sys.argv)

    if (argument_length == 1):

        print_help()
        sys.exit(0)

    else:

        try:
            term_len_h, term_len_v = os.get_terminal_size()
        except (OSError):
            term_len_h = 75
            term_len_v = 75

        if (check_if_prog_exists(['keyctl'])[0] == False):
            print(text_error('The program keyctl was not found. It is required to store & manage keys on a system running systemd'))
            sys.exit(1)
        elif (check_if_prog_exists(['xclip'])[0] == False):
            print(text_error('The program xclip was not found. It is required to use clipboard functionality'))
            sys.exit(1)
        elif (check_if_prog_exists(['dmenu'])[0] == False):
            print(text_error('The program dmenu was not found. It is required to use the search bar functionality'))
            sys.exit(1)

        config = {}

        config_pwmgr()

        _theme = config.get('theme')

        if (_theme == 1):
            theme = color_theme_1()
            field_color_fg = '\x1B[1;38;5;33m'
            term_bar_color = '\x1B[1;38;5;75m'
        elif (_theme == 2):
            theme = color_theme_2()
            field_color_fg = '\x1B[1;38;5;46m'
            term_bar_color = '\x1B[1;38;5;48m'
        elif (_theme == 3):
            theme = color_theme_3()
            field_color_fg = '\x1B[1;38;5;214m'
            term_bar_color = '\x1B[1;38;5;216m'
        elif (_theme == 4):
            theme = color_theme_4()
            field_color_fg = '\x1B[1;38;5;44m'
            term_bar_color = '\x1B[1;38;5;14m'
        elif (_theme == 5):
            theme = color_theme_5()
            field_color_fg = '\x1B[1;38;5;208m'
            term_bar_color = '\x1B[1;38;5;216m'
        elif (_theme == 6):
            theme = color_theme_6()
            field_color_fg = '\x1B[1;38;5;38m'
            term_bar_color = '\x1B[1;38;5;45m'
        elif (_theme == 66):
            theme = color_theme_66()
            field_color_fg = '\x1B[1;38;5;87m'
            term_bar_color = '\x1B[1;38;5;45m'
        else:
            theme = color_theme_1()
            field_color_fg = '\x1B[1;38;5;33m'
            term_bar_color = '\x1B[1;38;5;75m'

        if (argument_length == 2):

            if (sys.argv[1] == 'add' or sys.argv[1] == '--add' or sys.argv[1] == '-a'):
                check_database()
                add()
                sys.exit(0)

            elif (sys.argv[1] == 'show' or sys.argv[1] == '--show' or sys.argv[1] == '-o'):

                check_database()
                exit_if_database_is_empty()
                show_summary()
                sys.exit(0)

            elif (sys.argv[1] == 'copy-searchbar' or sys.argv[1] == '--copy-searchbar' or sys.argv[1] == '-C'):

                if (check_if_prog_exists(['dmenu', 'xclip'])[0] == False):
                    print(text_error('Dmenu package & xclip needs to be installed.'))
                    sys.exit(1)
                
                check_database()
                exit_if_database_is_empty()
                search_bar_copy()
                sys.exit(0)

            elif (sys.argv[1] == 'show-searchbar' or sys.argv[1] == '--show-searchbar' or sys.argv[1] == '-O'):

                if (check_if_prog_exists(['dmenu'])[0] == False):
                    print(text_error('Dmenu package was not found. Please install it & try again!'))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()
                search_bar_show()

            elif (sys.argv[1] == 'show-recent' or sys.argv[1] == '--show-recent' or sys.argv[1] == '-sr'):

                check_database()
                exit_if_database_is_empty()
                show_last_modified()
                sys.exit(0)

            elif (sys.argv[1] == 'generate-pw' or sys.argv[1] == '--generate-pw' or sys.argv[1] == '-g'):

                menu_generate_password_standalone()
                sys.exit(0)

            elif (sys.argv[1] == 'generate-keyfile' or sys.argv[1] == '--generate-keyfile' or sys.argv[1] == '-gk'):

                if (check_if_prog_exists(['dd'])[0] == False): 
                    print(text_error('The program dd was not found. Please install it & try again!'))
                    sys.exit(1)

                generate_keyfile()
                print_block(1)
                sys.exit(0)

            elif (sys.argv[1] == 'use-keyfile' or sys.argv[1] == '--use-keyfile' or sys.argv[1] == '-uk'):

                fn = '/home/%s/.config/pwmgr/keyfile' % (os.getlogin())

                r = check_files([fn])

                print_block(1)

                if (not r):
                    print(text_error("No keyfile found, please specify one manually or run 'pwmgr.py -gk' to generate one"))
                    sys.exit(1)
                elif (check_if_prog_exists(['dd'])[0] == False): 
                    print(text_error('The program dd was not found. Please install it & try again!'))
                    sys.exit(1)
                else:
                    msg = 'Keyfile found in %s' % fn
                    print(text_debug(msg))
                    print_block(1)

                    choice = prompt_yes_no("Do you want to use this keyfile? (Y/n): ", True, True)

                    if (not choice):
                        print_block(1)
                        sys.exit(0)

                    check_database()
                    use_keyfile(fn)
                    print_block(1)
                    sys.exit(0)

            elif (sys.argv[1] == 'list-keyfile' or sys.argv[1] == '--list-keyfile' or sys.argv[1] == '-lk'):

                list_keyfile()
                sys.exit(0)

            elif (sys.argv[1] == 'remove-keyfile' or sys.argv[1] == '--remove-keyfile' or sys.argv[1] == '-rk'):

                check_database()
                remove_keyfile()
                sys.exit(0)

            elif (sys.argv[1] == 'audit' or sys.argv[1] == '--audit'):

                if (term_len_h < 50):
                    print(text_error('Screen size too small to display data'))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()
                audit_records()
                sys.exit(0)

            elif (sys.argv[1] == 'pw-reset' or sys.argv[1] == '--pw-reset'):

                check_database()
                pw_reset()
                sys.exit(0)

            elif (sys.argv[1] == 'key-show' or sys.argv[1] == '--key-show'):

                check_database()
                key_show()
                sys.exit(0)

            elif (sys.argv[1] == 'keyring-reset' or sys.argv[1] == '--keyring-reset'):

                keyring_reset()
                sys.exit(0)

            elif (sys.argv[1] == 'help' or sys.argv[1] == '--help' or sys.argv[1] == '-h'):

                if (sys.argv[1] == '-h'):
                    print(text_error("Option not found. Did u mean" + \
                                     color_b('orange') + " --help " + \
                                     color_reset() + "? ;]"))
                    sys.exit(0)

                print_help()
                sys.exit(0)

            else:
                print(text_error("The selected option doesn't exist"))
                sys.exit(1)

        elif (argument_length == 3):

            if (sys.argv[1] == 'show' or sys.argv[1] == '--show' or sys.argv[1] == '-o'):

                result = convert_str_to_int(sys.argv[2])

                if (result[0] == False):
                    print(text_error("Requires an integer value"))
                    sys.exit(1)

                if (type(result[1]) == list):

                    index_list = result[1]
                    new_list = [i-1 for i in index_list]

                    check_database()
                    exit_if_database_is_empty()
                    
                    result = enc_db_handler.validate_index(new_list)

                    if (result):
                        show_index_multiple(new_list)
                        sys.exit(0)
                    else:
                        print(text_error("Selected indexes are not within range"))
                        sys.exit(1)

                elif (type(result[1]) == int):

                    check_database()
                    exit_if_database_is_empty()

                    if (enc_db_handler.validate_index((result[1]-1))):
                        show_index((result[1]-1))
                        sys.exit(0)
                    else:
                        print(text_error("Selected index is not within range"))
                        sys.exit(1)
                else:
                    print(text_error("Requires an integer or comma separated integer values"))
                    sys.exit(1)

            elif (sys.argv[1] == 'edit' or sys.argv[1] == '--edit' or sys.argv[1] == '-e'):

                index = None

                result = convert_str_to_int(sys.argv[2])

                if (result[0]):
                    if (type(result[1]) == list):
                        print(text_error("Editing multiple values simultaneously is not supported at the moment"))
                        sys.exit(1)
                    else:
                        index = result[1]
                else:
                    print(text_error("Requires an integer value"))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()

                if (enc_db_handler.validate_index((index-1))):
                    secure_edit_index((index-1))
                    sys.exit(0)
                else:
                    print(text_error("Selected index is not within range"))
                    sys.exit(1)

            elif (sys.argv[1] == 'search' or sys.argv[1] == '--search' or sys.argv[1] == '-s'):

                check_database()
                exit_if_database_is_empty()
                keyword = (sys.argv[2]).strip()
                search(keyword)
                sys.exit(0)

            elif (sys.argv[1] == 'copy' or sys.argv[1] == '--copy' or sys.argv[1] == '-c'):

                index = None

                result = convert_str_to_int(sys.argv[2])

                if (result[0] and type(result[1]) == int):
                    index = result[1]
                else:
                    print(text_error("Requires an integer value"))
                    sys.exit(1)

                if (check_if_prog_exists(['xclip'])[0] == False): 
                    print(text_error('xclip utility was not found. Please install it & try again!'))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()

                if (enc_db_handler.validate_index((index-1))):
                    secure_copy_password((index-1))
                    sys.exit(0)
                else:
                    print(text_error("Selected index is not within range"))
                    sys.exit(1)

            elif (sys.argv[1] == 'remove' or sys.argv[1] == '--remove' or sys.argv[1] == '-d'):

                index = None

                result = convert_str_to_int(sys.argv[2])

                if (result[0]):
                    index = result[1]
                else:
                    print(text_error("Requires an integer value"))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()

                if (type(index) == int):

                    if (enc_db_handler.validate_index((index-1))):
                        delete_index((index-1))
                        sys.exit(0)
                    else:
                        print(text_error("Selected index is not within range"))
                        sys.exit(1)

                elif (type(index) == list):

                    new_list = [i-1 for i in index]
                    new_list = list(set(new_list))
                    
                    for i in new_list:
                        if (enc_db_handler.validate_index(i) == False):
                            print(text_error("Selected index %s is not within range" % (i+1))) 
                            sys.exit(1)

                    # delete_index function can work on both single index / list of indexes
                    delete_index(new_list)
                    sys.exit(0)

                else:
                    print(text_error("Requires an integer value or a comma separated list"))
                    sys.exit(1)

            elif (sys.argv[1] == 'generate-keyfile' or sys.argv[1] == '--generate-keyfile' or sys.argv[1] == '-gk'):

                if (sys.argv[2].strip() == ''):
                    print(text_error('Key file name cannot be empty'))
                    sys.exit(1)

                generate_keyfile(sys.argv[2].strip())
                print_block(1)
                sys.exit(0)

            elif (sys.argv[1] == 'use-keyfile' or sys.argv[1] == '--use-keyfile' or sys.argv[1] == '-uk'):

                if (sys.argv[2].strip() == ''):
                    print(text_error('Keyfile name cannot be empty'))
                    sys.exit(1)
                elif (not os.path.isfile(sys.argv[2])):
                    print(text_error('Specified keyfile not found'))
                    sys.exit(1)

                check_database()
                use_keyfile(sys.argv[2].strip())
                print_block(1)
                sys.exit(0)

            elif (sys.argv[1] == 'list-keyfile' or sys.argv[1] == '--list-keyfile' or sys.argv[1] == '-lk'):

                if (sys.argv[2].strip() == ''):
                    list_keyfile()
                elif (sys.argv[2].strip() == 'brief'):
                    list_keyfile()
                elif (sys.argv[2].strip() == 'full'):
                    list_keyfile(False)
                else:
                    print(text_error("The selected option doesn't exist"))
                    sys.exit(1)

                sys.exit(0)

            elif ((sys.argv[1] == 'audit' or sys.argv[1] == '--audit' and \
                    (sys.argv[2] == '--show-all' or sys.argv[2] == 'show-all'))):

                if (term_len_h < 50):
                    print(text_error('Screen size too small to display data'))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()
                audit_records(show_all_ratings=True)
                sys.exit(0)

            elif (sys.argv[1] == 'import' or sys.argv[1] == '--import'):

                if (sys.argv[2] == 'pass'):
                    print(text_error("Function is no longer supported"))
                    print(text_debug("Please import your database using " + \
                            color_b('orange') + "--import-csv" + color_reset() + ' function'))
                    print_block(1)
                    sys.exit(0)
                else:
                    print(text_error("The selected option doesn't exist"))
                    sys.exit(1)

            elif (sys.argv[1] == 'import-csv' or sys.argv[1] == '--import-csv'):

                fn = sys.argv[2].strip()

                if (fn != '' and os.path.exists(fn)):
                    check_database()
                    import_from_csv(fn)
                    sys.exit(0)
                else:
                    print(text_error("The specified file %s doesn't exist" % fn))
                    sys.exit(1)

            elif (sys.argv[1] == 'export-csv' or sys.argv[1] == '--export-csv'):

                fn = sys.argv[2].strip()

                if (fn != ''):
                    check_database()
                    export_to_csv(fn)
                    sys.exit(0)
                else:
                    print(text_error("Requires a file name"))
                    sys.exit(1)

            elif (sys.argv[1] == 'export-csv-brief' or sys.argv[1] == '--export-csv-brief'):

                fn = sys.argv[2].strip()

                if (fn != ''):
                    check_database()
                    export_to_csv(fn, brief=True)
                    sys.exit(0)
                else:
                    print(text_error("Requires a file name"))
                    sys.exit(1)

            elif (sys.argv[1] == 'search-font' or sys.argv[1] == '--search-font'):

                keyword = sys.argv[2].strip()

                if (keyword != ''):
                    search_font_name(keyword)
                    sys.exit(0)
                else:
                    print(text_error("Keyword cannot be empty"))
                    sys.exit(1)

            else:
                print(text_error("The selected option doesn't exist"))
                sys.exit(1)

        elif (argument_length == 4):

            if (sys.argv[1] == 'search' or sys.argv[1] == '--search' or sys.argv[1] == '-s'):

                options = ['group', 'site', 'email', 'username', 'all']

                if (sys.argv[2] not in options):
                    print(text_error("The selected option doesn't exist"))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()

                keyword = (sys.argv[3]).strip()

                if (sys.argv[2] == 'group'):
                    search_extended(keyword, 'group')
                    sys.exit(0)
                elif (sys.argv[2] == 'site'):
                    search_extended(keyword, 'site')
                    sys.exit(0)
                elif (sys.argv[2] == 'email'):
                    search_extended(keyword, 'email')
                    sys.exit(0)
                elif (sys.argv[2] == 'username'):
                    search_extended(keyword, 'username')
                    sys.exit(0)
                elif (sys.argv[2] == 'all'):
                    search(keyword)
                    sys.exit(0)


            elif (sys.argv[1] == 'convert-csv' or sys.argv[1] == '--convert-csv'):

                input_file = sys.argv[2]

                if (input_file == '' or not check_files([input_file])):
                    msg = "The input file (%s) is not valid" % (input_file)
                    print(text_error(msg))
                    sys.exit(1)

                data = read_csv_pwmgr(input_file)

                write_csv_pwmgr(data, sys.argv[3])

                sys.exit(0)

            else:
                print(text_error("The selected option doesn't exist"))
                sys.exit(1)


        elif (argument_length == 5):

            if (sys.argv[1] == 'select-cols-csv'):

                order_of_rows = []

                result = convert_str_to_int(sys.argv[2])

                if (result[0]):
                    order_of_rows = result[1]
                else:
                    print(text_error("Requires an integer value for [order] parameter"))
                    sys.exit(1)

                input_file = sys.argv[3]

                if (input_file == '' or not check_files([input_file])):
                    msg = "The input file '%s' does not exist" % (input_file)
                    print(text_error(msg))
                    sys.exit(1)

                data = read_csv_pwmgr(input_file)

                if (len(data) == 0):
                    print(text_error('No data found in file'))
                    sys.exit(1)

                row_len_max = len(data[0])

                for index in order_of_rows:

                    if ((index-1) < 0):
                        print(text_error("Index cannot be less than 1"))
                        sys.exit(1)
                    elif (index > row_len_max):
                        print(text_error('Index cannot be greater than max row length'))
                        sys.exit(1)

                if (sys.argv[4] == ''):
                    print(text_error('Output filename needs to be specified'))
                    sys.exit(1)

                new_data = []

                for item in data:

                    l = []

                    for i in order_of_rows:
                        l.append(item[i-1].strip())

                    new_data.append(l)

                write_csv_pwmgr(new_data, sys.argv[4])

                sys.exit(0)

            else:
                print(text_error("The selected option doesn't exist"))
                sys.exit(1)

        else:
            print(text_error("The selected option doesn't exist"))
            sys.exit(1)


def check_database():

    global file_name, db_file_path, app_name, enc_db_handler, pw_master, password_in_keyring, \
            config, config_file

    config_path = '/home/%s/.config/pwmgr/' % (os.getlogin())

    if (os.path.exists(config_path) == False):
        os.mkdir(config_path)

    db_file_path = '%s%s' % (config_path, file_name)

    enc_db_handler = ManageRecord()

    keyfile_path = config.get('keyfile_path')

    if (keyfile_path != ''):

        val = check_files([keyfile_path])

        if (not val):
            msg = 'Keyfile not found in %s' % keyfile_path
            print(text_error(msg))
            sys.exit(1)

    if (os.path.isfile(db_file_path) == False):
        # (No database found)

        print_block(1)

        if (prompt_yes_no("No database exists. Do you want to create a new one? (Y/n): ", True)):
            print_block(1)
            pw_master = prompt_password(enforce_min_length=True)
            print_block(1)

            #TODO: make keyfile_name global variable
            #TODO: test empty database code below
            keyfile_name = 'keyfile'
            keyfile_path = ''

            if (prompt_yes_no("Do you want to auto generate & add a keyfile? (Y/n): ", True)):
                keyfile_path = '/home/%s/.config/pwmgr/%s' % (os.getlogin(), keyfile_name)
                generate_keyfile(keyfile_path, False, True)

            enc_db_handler.generate_new_key(pw_master, True, True, keyfile_path)
            enc_db_handler.write_encrypted_database(db_file_path)
            config.update({'keyfile_path':keyfile_path})
            write_config(config, config_file)
            
            if (keyring_set(enc_db_handler.get_key()) == False):
                print(text_error("check_database(): error#01 Unable to store password in keyring"))
                sys.exit(1)

        else:
            print_block(1)
            sys.exit(0)
    else:
        # (Previous database exists)
        # We search for password in keyring, if nothing found we prompt user
        #       for master password & attempt to decrypt it
        #

        key = keyring_get()
        result = False

        ## * We use 2 exception handlers, cos IncorrectPasswordException & 
        ##   IncorrectKeyException() overlap with other exception handlers
        ##   so we try to minimise code repetition as much as possible
        ##   
        ## * Updated old code (commented out) which mainly used commandline
        ##   for interacting with user. The new one interacts with user
        ##   with GUI prompts for error, password input, etc. It is done
        ##   because if pwmgr is used with key bindings, the user might not
        ##   know if things go wrong as cmd prompt might just close without showing 
        ##   anything.

        try:
            try:
                if (key == False):
                    password_in_keyring = False
                    pw_master = prompt_password_gui() # GUI password prompt

                    if (pw_master == False):
                        sys.exit(0)

                    result = enc_db_handler.load_database(db_file_path, pw_master, False, keyfile_path)
                else:
                    result = enc_db_handler.load_database_key(db_file_path, bytes(key, 'utf-8'))

            except (UnsupportedFileFormatException):

                gui_msg("\nUnsupported file format detected!\n\n" + \
                        "1) Run '--export csv-brief data.csv' on older version of pwmgr < 2.0\n" + \
                        "2) Backup & remove ~/.config/pwmgr/data.enc\n" + \
                        "3) Run '--import data.csv' on latest version of pwmgr >= 2.0\n")

                sys.exit(0)

            except (IntegrityCheckFailedException):

                r = gui_confirmation('\nHash mismatch detected. Data could have been corrupted!\n\n' + \
                        'Press OK to repair database\n')

                if (r):
                    if (key):
                        result = enc_db_handler.load_database_key(db_file_path, bytes(key,'utf-8'), override_integrity_check=True)
                    else:
                        result = enc_db_handler.load_database(db_file_path, pw_master, True, keyfile_path)

                    if (result): # Database decryption succeeded
                        enc_db_handler.write_encrypted_database(db_file_path)
                        sys.exit(0)
                else:
                    sys.exit(0)


            if (result):  # Database decryption succeeded

                if (password_in_keyring == False):
                    if (keyring_set(enc_db_handler.get_key()) == False):
                        gui_msg("Unable to store password in keyring")
                    else:
                        keyring_set_expiration()

        except (IncorrectPasswordException):
            gui_msg('\nUnable to decrypt data due to incorrect password / keyfile\n')
            sys.exit(1)

        except (IncorrectKeyException):
            gui_msg("\nUnable to decrypt data as stored key is incorrect." + \
                    "\n\nPlease use 'pwmgr --keyring reset' to remove it\n")
            sys.exit(1)


def exit_if_database_is_empty():

    global enc_db_handler

    n = enc_db_handler.get_number_of_records()

    if (n == 0):
        print_block(1)
        print(text_debug('Database is empty'))
        print_block(1)
        sys.exit(0)


def keyring_get():

    """
    Returns the encryption key stored in keyring

    """
    global app_name
    cmd1 = 'keyctl request user %s' % (app_name)
    stdout,stderr,rc = run_cmd(cmd1)

    #print("stdout: %s" % stdout)
    #print("stderr: %s" % stderr)

    if (stderr):
        return False

    key_id = stdout

    cmd2 = 'keyctl print %s' % key_id
    stdout,stderr,rc = run_cmd(cmd2)

    if (stderr):
        return False

    return stdout


def keyring_set(value):

    """
    Set the encryption key in keyring

    """

    global app_name

    cmd = 'keyctl add user %s %s @u' % (app_name, value)
    stdout,stderr,rc = run_cmd(cmd)

    if (stderr):
        return False

    return True


def keyring_reset():

    """
    Remove the current key from the keyring

    """

    global app_name

    cmd = 'keyctl purge -s user %s' % app_name
    stdout,stderr,rc = run_cmd(cmd)
    
    value = stdout.strip().split(' ')[1]
    
    if (int(value) == 0):
        print(text_error('No password found in keyring'))
    else:
        print_block(1)
        print(text_debug('Password has been deleted from keyring'))
        print_block(1)


def keyring_set_expiration():

    global config, app_name

    t = config.get('keyring_wipe_interval')

    cmd1 = 'keyctl request user %s' % (app_name)
    stdout,stderr,rc = run_cmd(cmd1)

    if (stderr):
        return False

    key_id = stdout

    cmd2 = 'keyctl timeout %s %s' % (key_id, t)

    stdout2,stderr2,rc2 = run_cmd(cmd2)

    if (stderr2):
        return False

    return True


def pw_reset():

    """
    Change the current password that is used for database encryption 

    Note: Needs to be called after database has been loaded in memory using
          the check_database() function

    """

    global app_name, enc_db_handler, db_file_path, config

    custom_refresh()

    kf = config.get('keyfile_path')

    new_pwd = prompt_password_master(8)

    if (kf != ''):

        try:
            enc_db_handler.use_keyfile(new_pwd, kf)
        except (KeyFileInvalidException):
            print(text_error("Key file is not valid. Need to have a min size of 2048 bits"))
            print(text_debug("Use -gk to generate a new key file"))
            sys.exit(0)
    else:
        enc_db_handler.change_password(new_pwd)

    enc_db_handler.write_encrypted_database(db_file_path)

    keyring_set(enc_db_handler.get_key())

    print_block(1)
    print(text_debug('Password has been reset successfully!'))
    print_block(1)
    print(color_menu_bars())
    print_block(1)


def key_show():

    """
    Display the current key that is being used for encryption

    Note: Needs to be called after database has been loaded in memory using
          the check_database() function
        
    """

    global enc_db_handler

    c_value = color_b('green')
    c_rst = color_reset()

    key = enc_db_handler.get_key()
    print()
    msg = 'Current Key: %s%s%s' % (c_value, key, c_rst)
    print(text_debug(msg))
    print()


def add():

    """
    Adds a record to database
    """

    global enc_db_handler, db_file_path, field_color_fg

    cursor_show()
    clear_screen()
    print_block(3)
    print(color_menu_informational("   Press (Enter) to Skip | (Ctrl+C) Quit without saving" + ' '*4))
    print_block(2)

    site = prompt("Website: ")

    pwd = ''

    r = Record(site, pwd)

    if (enc_db_handler.check_duplicate_entry(r)):

        print_block(1)

        if (not prompt_yes_no("Duplicate entry found. Do you want to continue? (y/N): ", False, False)):
            print_block(1)
            print(text_debug("Record has been discarded"))
            print_block(1)
            print(plain_menu_bars())
            print_block(1)
            sys.exit(0)

    print_block(1)

    if (prompt_yes_no("Auto generate new password? (Y/n): ")):
        print_block(1)
        pwd = menu_generate_password()
    else:
        print_block(1)
        pwd = prompt_password(True, 1)

    r = Record(site, pwd)

    print_block(1)

    choice = prompt_yes_no("Do you want to add more info? (y/N): ", False)

    if (choice):
        clear_screen()
        print_block(3)
        print(color_menu_informational("The information below is Optional." + \
                " (Press Enter if you want to skip)   "))

        print_block(2)
        email = prompt_blank_fixed_width("Email: ")
        print_block(1)
        group = prompt_blank_fixed_width("Group: ")
        print_block(1)
        usr = prompt_blank_fixed_width("Username: ")
        print_block(1)
        phone = prompt_blank_fixed_width("Phone#: ")
        print_block(1)
        remark = prompt_blank_fixed_width("Notes: ")
        print_block(1)
        recovery_email = prompt_blank_fixed_width("Recovery email: ", 16)
        print_block(1)
        two_factor = prompt_yes_no("Two Factor enabled? (y/N): ", False)

        if (usr != ''):
            r.set_username(usr)

        if (email != ''):
            r.set_email(email)

        if (group != ''):
            r.set_group(group)

        if (remark != ''):
            r.set_remark(remark)

        if (recovery_email != ''):
            r.set_recovery_email(recovery_email)

        if (phone != ''):
            r.set_phone_number(phone)

        if (two_factor != ''):
            r.set_two_factor(two_factor)

        enc_db_handler.add(r)
        enc_db_handler.write_encrypted_database(db_file_path)

        print_block(1)
        print(text_debug("Record has been added successfully!"))
        print_block(1)
        print(plain_menu_bars())
        print_block(1)

    else:
        ## We could have removed redundant logic but this way ensures we don't
        ## have menu bars displayed right beneath pw generation menu

        enc_db_handler.add(r)
        enc_db_handler.write_encrypted_database(db_file_path)

        print_block(1)
        print(text_debug("Record has been added successfully!"))
        print_block(1)


def audit_records(show_all_ratings=False):

    """
    Performs security audit on internal database

    """
    ## Requires >= 100 width term, this check is 
    ## being done by arg_parser() so skipping this one
    #global term_len_h

    #if (term_len_h < 100):
    #    print(text_error('Screen size too small to display data'))
    #    sys.exit(1)

    global enc_db_handler

    header, data = process_security_data(show_all_ratings=show_all_ratings)

    print_block(1)
    print(color_menu_column_header(header))
    print_block(1)

    for r in data:
        ratio = [5,4,4,2,2.5]
        print_audit_info(r, ratio)

    print_block(1)
    print(plain_menu_bars())
    print_block(1)


def process_security_data(show_all_ratings=False):

    global enc_db_handler, db_file_path

    enc_db_handler.audit_security()
    enc_db_handler.write_encrypted_database(db_file_path)

    sorted_indexes = enc_db_handler.sort_security_rating(sort_ascending=True)

    header = [['Site',4.2] , ['PW Age',3.4], ['PW Reuse',3], ['    PW Strength',2],  ['Security Rating',1.5]]

    data = []

    color_rst = color_reset()
    color_white = color_b('white')
    color_green = color_b('green')
    color_yellow = color_b('yellow')
    color_gray = '\x1B[1;38;5;246m' 
    color_red = color_b('red')
    color_special = '\x1B[1;38;5;51m'

    for i in range(len(sorted_indexes)):
        
        index = sorted_indexes[i]

        r = enc_db_handler.get_index_with_enc_pw(index)

        if (not show_all_ratings):

            if (not (int(r.get_security_rating()) <= 11)):
                continue

        site = r.get_website()

        site_info = [site, color_rst]

        """
        Ratings:
     
        pw_age (3):          'n' =  3, 'o' =  2, 'r' = -1
        pw_reuse (6):        '0' =  6, '1' =  0
        pw_complexity (6):   'e' =  6, 'g' =  4, 'a' = 2, 'w' = -2, 'u' = -4
        ___________________________________________________________________________
        Total score (15):    max = 15, min = 0 (negative values are set to 0)

        (14-15) : Outstanding
        (12-13) : Good
        (10-11) : Average
        (7-9)   : Poor
        (0-6)   : Critical
        """

        pw_cmpx = r.get_pw_complexity()
        pw_cmpx_info = ''

        ## Adding data & color information as a list instead of hardcoded strings
        ## cos during display function it causes issues with text alignment

        if (pw_cmpx == 'e'):
            color_info = '%s' % (color_special)
            pw_cmpx_info = ['Excellent', color_info]
        elif (pw_cmpx == 'g'):
            color_info = '%s' % (color_green)
            pw_cmpx_info = ['Good', color_info]
        elif (pw_cmpx == 'a'):
            color_info = '%s' % (color_yellow)
            pw_cmpx_info = ['Average', color_info]
        elif (pw_cmpx == 'w'):
            color_info = '%s' % (color_gray)
            pw_cmpx_info = ['Weak', color_info]
        elif (pw_cmpx == 'u'):
            color_info = '%s' % (color_red)
            pw_cmpx_info = ['Unsuitable', color_info]
        elif (pw_cmpx == ''):
            color_info = '%s' % (color_white)
            pw_cmpx_info = ['Audit Pending', color_info]

        pw_age = r.get_pw_age()
        pw_age_info = ''
        
        if (pw_age == 'n'):
            color_info = '%s' % (color_green)
            pw_age_info = ['< 6 months', color_info]
        elif (pw_age == 'o'):
            color_info = '%s' % (color_yellow)
            pw_age_info = ['>= 6 months', color_info]
        elif (pw_age == 'r'):
            color_info = '%s' % (color_red)
            pw_age_info = ['>= 1 year', color_info]
        elif (pw_age == ''):
            color_info = '%s' % (color_white)
            pw_age_info = ['Audit Pending', color_info]

        pw_reuse = r.get_pw_reuse()
        pw_reuse_info = ''

        if (pw_reuse == '0'):
            color_info = '%s' % (color_yellow)
            pw_reuse_info = ['Not Found', color_info]
        elif (pw_reuse == '1'):
            color_info = '%s' % (color_red)
            pw_reuse_info = ['Found', color_info]
        elif (pw_reuse == ''):
            color_info = '%s' % (color_white)
            pw_reuse_info = ['Audit Pending', color_info]

        s_rating = r.get_security_rating()
        s_rating_info = ''

        if (s_rating == ''):
            color_info = '%s' % (color_white)
            s_rating_info = ['Audit Pending', color_info]
        else:
            s_rating = int(s_rating)

            if (s_rating in [14,15]):
                color_info = '%s' % (color_special)
                s_rating_info = ['Outstanding', color_info]
            elif (s_rating in [12,13]):
                color_info = '%s' % (color_green)
                s_rating_info = ['Good', color_info]
            elif (s_rating in [10,11]):
                color_info = '%s' % (color_yellow)
                s_rating_info = ['Average', color_info]
            elif (s_rating in [7,9]):
                color_info = '%s' % (color_gray)
                s_rating_info = ['Weak', color_info]
            elif (s_rating in [0,1,2,3,4,5,6]):
                color_info = '%s' % (color_red)
                s_rating_info = ['Critical', color_info]

        color_info = '%s' % (color_yellow)

        _index = [index+1, color_info]

        tmp_data = [ _index, site_info, pw_age_info, pw_reuse_info, pw_cmpx_info, s_rating_info ]

        data.append(tmp_data)

    return header, data


def show_summary(input_list=None):

    """
    Display a summary of the entries in the database

    """

    global enc_db_handler

    data_summary = []

    length = enc_db_handler.get_number_of_records()

    if (input_list == None):

        for i in range(length):
            r = enc_db_handler.get_index_with_enc_pw(i)
            data = [(i+1), r.get_website(), r.get_email(), r.get_username(),  r.get_group()]
            data_summary.append(data)
    else:

        data_summary = []

        for i in range(len(input_list)):
            r = enc_db_handler.get_index_with_enc_pw(input_list[i])
            data = [(input_list[i]+1), r.get_website(), r.get_email(), r.get_username(), r.get_group()]
            data_summary.append(data)

    # This is for partitioning space & printing out header according to the
    # ratio specified by the second index
    new_header = [['Site', 4], ['   Email',4], ['      Username',2], ['       Group', 2]]

    print_block(1)
    print(color_menu_column_header(new_header))
    print_block(1)

    for item in data_summary:
        formatted_data = format_data_with_spacing(item)
        print(formatted_data)

    print_block(1)
    print(plain_menu_bars())
    print_block(1)


def show_last_modified():

    """
    Display entries from database sorted by most recently modified

    """

    global enc_db_handler

    data_summary = []

    input_list = enc_db_handler.get_records_last_modified()

    for i in range(len(input_list)):
        r = input_list[i][0]
        index = input_list[i][1]
        data = [(index+1), r.get_website(), r.get_group(), r.get_last_modified()]
        data_summary.append(data)

    # This is for partitioning space & printing out header according to the
    # ratio specified by the second index
    new_header = [['Site', 2.8], ['  Group', 3], [' Last Modified', 2.5]]

    print_block(1)
    print(color_menu_column_header(new_header))
    print_block(1)

    for item in data_summary:
        formatted_data = format_data_with_spacing(item)
        print(formatted_data)

    print_block(1)
    print(plain_menu_bars())
    print_block(1)


def show_index(index=None, display_multiple_index=False):

    """
    Display the record at the specified index from database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global enc_db_handler

    if (index == None):
        return

    r = enc_db_handler.get_index_with_enc_pw(index)

    header = ['Site', 'Password', 'Email', 'Username', 'Group', 'Phone#', \
            'Two Factor', 'Recovery Email', 'Last Modified', 'Notes']

    data = [r.get_website(), '', r.get_email(), r.get_username(), \
            r.get_group(), r.get_phone_number(), r.get_two_factor(), \
            r.get_recovery_email(), r.get_last_modified(), r.get_remark()]

    if (not display_multiple_index):
        print_block(1)
        # print(color_menu_bars())
        print(plain_menu_bars())
        print_block(1)

        display_row_with_sec_mem(header, data, index)

        print_block(1)
        # print(color_menu_bars())
        print(plain_menu_bars())
        print_block(1)
    else:
        display_row_with_sec_mem(header, data, index)


def get_record_at_index(index=None):

    """
    Display the record at the specified index from database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global enc_db_handler

    if (index == None):
        return

    r = enc_db_handler.get_index_with_enc_pw(index)

    header = ['Site', 'Password', 'Email', 'Username', 'Group', 'Phone#', \
            'Two Factor', 'Recovery Email', 'Last Modified', 'Notes']

    data = [r.get_website(), '', r.get_email(), r.get_username(), \
            r.get_group(), r.get_phone_number(), r.get_two_factor(), \
            r.get_recovery_email(), r.get_last_modified(), r.get_remark()]

    return header, data


def show_index_static(header=[], data=[], index=0):

    """
    Display a record without touching database

    """

    if (len(header) == 0 or len(data) == 0):
        return

    display_row_static_with_sec_mem(header, data, index)


def show_index_multiple(index_list=None):

    """
    Display the record at the specified index from database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global term_len_h

    print_block(1)
    print(plain_menu_bars())
    print_block(1)

    for i in index_list:

        show_index(i, display_multiple_index=True)

        if (i == index_list[-1]):
            pass
        else:
            print_block(2)
            # print(plain_menu_bars('\u2500', color_enable=False))
            # print_block(1)

    print_block(1)
    print(plain_menu_bars())
    print_block(1)


def delete_index(index=None):

    """
    Deletes record at the specified index, supports list of indexes
    """

    global enc_db_handler, db_file_path

    if (index == None):
        return
    elif (type(index) == int):
        enc_db_handler.remove_index(index)
        enc_db_handler.write_encrypted_database(db_file_path)
        print_block(1)
        print(text_debug("Record has been deleted."))
        print_block(1)
    elif (type(index) == list):

        show_summary(index)

        choice = prompt_yes_no("The records above will be deleted, continue? (y/N): ", False, False)

        print_block(1)

        if (choice):
            enc_db_handler.remove_index(index) # This function is aware of lists 
            enc_db_handler.write_encrypted_database(db_file_path)
            print(text_debug("Specified records have been deleted"))
            print_block(1)
            #print(color_menu_bars())
            #print_block(1)
        else:
            print(text_debug("No changes have been made to database"))
            print_block(1)


def secure_copy_password(index=None):

    """
    Uses a secure version of the original method, differece being that it
        erases memory after operation is complete

    Copy the specified index from database to clipboard

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global enc_db_handler, config

    if (index == None):
        return

    sec_mem_handler = None

    try:

        sec_mem_handler = enc_db_handler.get_pw_of_index_with_sec_mem(index)
        sec_mem_handler.copy_to_clipboard() # Auto wipes memory so no further action needed
        print()
        clear_clipboard()

    except IncorrectPasswordException:
        gui_msg('\nDecyption of password field in database failed!' + \
                '\n\n       Database could be partially corrupted')
        sys.exit(1)

    except MemoryAllocationFailedException:
        print(text_error('Secure memory function failed due to insufficient memory, using insecure method!'))
        copy_password(index)

    except SecureClipboardCopyFailedException:
        print(text_error('Secure memory function is unavailable (libc.so.6 not found), using insecure method!'))
        copy_password(index)


def copy_password(index=None):

    """
    Copy the specified index from database to clipboard

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global enc_db_handler, config

    if (index == None):
        return

    try:

        pw = enc_db_handler.get_pw_of_index(index)

        ## Almost impossible to escape single quote in bash
        ## therefore current solution is to write the pass to a file (@home dir)
        ## only if single quote is present & ask xclip to copy.
        ## Obviously we wipe it off as soon as copying is done in milliseconds

        ## This is an exceptional case, in general we never use this approach

        cmd1 = ''

        if ("'" in pw):

            path_pw = '/home/%s/pw.txt' % os.getlogin()

            if (write_str_to_file(pw, path_pw)):

                cmd1 = 'xclip -i \'%s\' -selection clipboard' % path_pw
                os.system(cmd1)
                
                try:
                    os.remove(path_pw)
                except FileNotFoundError:
                    pass

            else:
                gui_msg('\n\t\t   Unable to copy password to clipboard' + \
                        "\n\nPlease update your password so that it doesn't use single quotes")

                sys.exit(1)
        else:

            cmd1 = 'echo -n \'%s\' | xclip -selection clipboard' % pw
            os.system(cmd1)

        clear_clipboard()

    except IncorrectPasswordException:
        gui_msg('\nDecyption of password field in database failed!' + \
                '\n\n       Database could be partially corrupted')



def clear_clipboard():

    """
    This function uses wipe_pwmgr.py to clear clipboard & expire keys in tpm

    Initially I wasn't aware that keyctl function supports expiration therefore
    used this script to clear keys from tpm, now it's not required anymore.

    #TODO wipe_pwmgr.py code needs to be updated to remove unused functionality

    """

    global config

    t1 = int(config.get('clipboard_wipe_interval'))

    if (t1 != 0):
        print('%s Clipboard will be cleared in %ss' % (color_symbol_debug(), t1))

    t2 = 0 # Ignore keyring wipe as we automatically set expiration
           # on keys when they're set

    if (check_files(['/usr/bin/wipe_pwmgr.py'])):
        cmd = 'python3 /usr/bin/wipe_pwmgr.py %s %s' % (t1, t2)
        os.system(cmd)
    elif (check_files(['./wipe_pwmgr.py'])):
        cmd = 'python3 ./wipe_pwmgr.py %s %s' % (t1, t2)
        os.system(cmd)
    else:
        text_error('File wipe_pwmgr.py not found, please copy it to /usr/bin')

    print_block(1)


def clear_keyring():

    global config

    t1 = config.get('keyring_wipe_interval')
    t2 = 0

    if (check_files(['/usr/bin/wipe_pwmgr.py'])):
        cmd = 'python3 /usr/bin/wipe_pwmgr.py %s %s' % (t2, t1)
        os.system(cmd)
    elif (check_files(['./wipe_pwmgr.py'])):
        cmd = 'python3 ./wipe_pwmgr.py %s %s' % (t2, t1)
        os.system(cmd)
    else:
        text_error('File wipe_pwmgr.py not found, please copy it to /usr/bin')


def secure_edit_index(index=None):

    """
    Edit a record at the specified index & update it to database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global enc_db_handler, db_file_path, field_color_fg

    if (index == None):
        return

    r = enc_db_handler.get_index_with_enc_pw(index)

    header = ['Website', 'Password', 'Username', 'Email', 'Group', 'Notes', \
            'Two-factor', 'Recovery-email', 'Phone-number']

    data = [r.get_website(), '', r.get_username(), \
            r.get_email(), r.get_group(), r.get_remark(), r.get_two_factor(), \
            r.get_recovery_email(), r.get_phone_number()]

    sec_mem_handler = None

    sec_mem_handler_new = None

    try:
        sec_mem_handler = enc_db_handler.get_pw_of_index_with_sec_mem(index)

    except IncorrectPasswordException:
        gui_msg('\nDecyption of password field in database failed!' + \
                '\n\n       Database could be partially corrupted')
        sys.exit(1)

    except MemoryAllocationFailedException:
        gui_msg('\nSecure memory function failed due to insufficient memory!' + \
                '\n\n       If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    except SecureClipboardCopyFailedException:
        gui_msg('\n        Secure memory function is unavailable (libc.so.6 not found)' + \
                '\n\nTry installing glibc package. If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    cursor_hide()
    custom_refresh(print_menu_bars=False)
    print(color_menu_informational("    Press (e) to Edit | (Enter) to Skip | (q) Quit without saving" + ' '*6))
    print_block(3)

    color = field_color_fg
    rst = color_reset()

    data_changed = False
    pw_changed   = False

    for i in range(len(header)):

        category_name = '  %s:' % (header[i])
        category_name = "{0:<20}".format(category_name)

        if (i == 1):

            text = '%s%s%s ' % (color,category_name,rst) 
            sys.stdout.write(text)
            sec_mem_handler.print_str()
            sys.stdout.flush()

        elif (i == 2): 
            
            if (not pw_changed):
                print_block(1)

            if (data[i] == "''"):
                print('%s%s%s' % (color,category_name,rst))
            else:
                print('%s%s%s %s' % (color,category_name,rst,data[i]))

        else:

            if (data[i] == "''"):
                print('%s%s%s' % (color,category_name,rst))
            else:
                print('%s%s%s %s' % (color,category_name,rst,data[i]))

        try:

            while (True):

                char = getch()

                if (char == 'e' or char == 'E'):

                    cursor_show()

                    if (i == 1):

                        print_block(1)

                        sec_mem_handler_new = prompt_with_sec_mem("           " + ' '*5)

                        data_changed = True
                        pw_changed   = True
                        cursor_hide()
                        break

                    if (i == 6):
                        data[i] = prompt_yes_no("Enable Two Factor? (y/N): ", "")
                        data_changed = True
                        cursor_hide()
                        break
                    else:
                        data[i] = prompt_blank_for_edit("           " + ' '*5)
                        data_changed = True
                        cursor_hide()
                        break

                elif (char == '\n' ):

                    print_block(1)
                    break

                elif (char in ('q', 'Q')):

                    sec_mem_handler.wipe_memory()

                    if (sec_mem_handler_new != None):
                        sec_mem_handler_new.wipe_memory()

                    print_block(1)
                    cursor_show()
                    sys.exit(1)

        except KeyboardInterrupt:

            sec_mem_handler.wipe_memory()

            if (sec_mem_handler_new != None):
                sec_mem_handler_new.wipe_memory()

            print_block(1)
            cursor_show()
            sys.exit(1)

    if (data_changed):

        r.set_website(data[0])
        r.set_username(data[2])
        r.set_email(data[3])
        r.set_group(data[4])
        r.set_remark(data[5])
        r.set_two_factor(data[6])
        r.set_recovery_email(data[7])
        r.set_phone_number(data[8])

        if (pw_changed):

            r.update_last_modified()
            r.set_pw_age('')
            r.set_pw_complexity('')
            r.set_pw_reuse('')
            r.set_security_rating('')

            enc_db_handler.update_index_with_sec_mem(r, index, sec_mem_handler_new)

        else:

            enc_db_handler.update_index_with_sec_mem(r, index, sec_mem_handler)

        enc_db_handler.write_encrypted_database(db_file_path)

    sec_mem_handler.wipe_memory()

    if (sec_mem_handler_new != None):
        sec_mem_handler_new.wipe_memory()

    cursor_show()
    print(plain_menu_bars())
    print_block(1)


def search(keyword=''):

    global enc_db_handler

    if (keyword == ''):
        return

    result = enc_db_handler.search_all(keyword)

    if (len(result) == 0):
        print_block(1)
        print(text_debug('Nothing found'))
        print_block(1)
    else:
        show_summary(result)


def search_extended(keyword='', category=''):

    global enc_db_handler

    if (keyword == '' or category == ''):
        return

    result = []

    if (category == 'group'):
        result = enc_db_handler.search_group(keyword)
    elif (category == 'site'):
        result = enc_db_handler.search_website(keyword)
    elif (category == 'email'):
        result = enc_db_handler.search_email(keyword)
    elif (category == 'username'):
        result = enc_db_handler.search_username(keyword)

    if (len(result) == 0):
        print_block(1)
        print(text_debug('Nothing found'))
        print_block(1)
    else:
        show_summary(result)


#==========================================================================#
#                              PWMGR Configuration                         #
#==========================================================================#


def config_pwmgr():

    global config, config_file


    c_dir = '/home/%s/.config/pwmgr/' % (os.getlogin())

    if (os.path.exists(c_dir) == False):
        os.mkdir(c_dir)

    fn = 'config.txt'
    fp = '%s%s' % (c_dir, fn)

    config_file = fp

    if (os.path.isfile(fp) == False):
        validate_config()
        write_config(config, config_file)
    else:
        config = load_config(config_file)
        validate_config() 
        write_config(config, config_file)


def validate_config():

    """
    This function will setup default values for config 
    if they are missing and validate existing values

    Config attributes: searchbar_font_name, searchbar_font_size, 
                       clipboard_wipe_interval,
                       theme 

    Return: None

    Notes: Global variable config is probed & updated as required
    """
    
    global config 

    fn = config.get('searchbar_font_name')
    cw = config.get('clipboard_wipe_interval')
    kw = config.get('keyring_wipe_interval')
    th = config.get('theme')
    kf = config.get('keyfile_path')

    default_cw = 30
    default_kw = 1800

    if (not fn):
        set_default_font()
    else:
        ## Removing font config restriction, do what you want :]
        # r = check_if_font_exists(fn)

        # if (not r):
        #     set_default_font()
        pass

    try:

        cw = int(cw)

        if (cw <= 0):
            config.update({'clipboard_wipe_interval':0})
        else:
            config.update({'clipboard_wipe_interval':cw})

    except (ValueError, TypeError):
        config.update({'clipboard_wipe_interval':default_cw})

    try:

        kw = int(kw)

        if (kw <= 0):
            config.update({'keyring_wipe_interval':0})
        else:
            config.update({'keyring_wipe_interval':kw})

    except (ValueError, TypeError):
        config.update({'keyring_wipe_interval':default_kw})

    if (not th or type(th) != int):
        config.update({'theme':1})

    if (not kf):
        config.update({'keyfile_path':''})


def load_config(filename=''):

    config = {}

    if (filename == ''):
        return False

    output = []

    with open(filename, 'r') as fd:
        output = fd.readlines()

    output_parsed = []

    for i in range(len(output)):
        output[i] = output[i].strip()

        if (output[i] == '' or output[i].startswith('#')):
            pass
        else:
            output_parsed.append((output[i], (i+1)))

    # Checking whether there are errors in config
    for i in range(len(output_parsed)):
        if (not check_formatting(output_parsed[i][0])):
            print('[!] Formatting error detected, line number: %d' % (output_parsed[i][1]))
            return False

    # Parsing config file & loading values
    for i in range(len(output_parsed)):
        tmp = output_parsed[i][0].split('=')
        tmp[0] = tmp[0].strip()
        tmp[1] = tmp[1].strip()

        try:
            v = int(tmp[1])
            tmp[1] = v
            config.update({tmp[0]:tmp[1]})
            continue
        except (ValueError):
            pass

        if (tmp[1].lower() == 'true'):
            tmp[1] = True
        elif(tmp[1].lower() == 'false'):
            tmp[1] = False
        elif ( '"' in tmp[1]):
            tmp[1] = tmp[1].strip('"')
        elif ("'" in tmp[1]):
            tmp[1] = tmp[1].strip("'")

        config.update({tmp[0]:tmp[1]})

    return config
    

def write_config(config={}, filename=''):

    if (len(config) == 0 or filename == ''):
        return False

    with open(filename, 'w') as fw:

        for item in config:

            s = ''

            if (type(config[item]) == bool):
                s = '%s = %s' % (item, config[item])
            elif (type(config[item]) == int):
                s = '%s = %d' % (item, config[item])
            else:
                s = '%s = "%s"' % (item, config[item])

            fw.writelines(s)
            fw.writelines('\n')

    return True


def write_str_to_file(s='', fn=''):

    if (len(s) == 0 or fn == ''):
        return False

    try:

        with open(fn, 'w') as fh:
            fh.write(s)

    except (IOError, BaseException):
        #print('Error occured')
        #print(e)
        return False

    return True


def set_default_font():

    global config

    f_name = ''
    f_size = 11

    biggy_fonts = False

    w,h = get_screen_resolution()

    if (w >= 1920):
        biggy_fonts = True

    f = get_default_fonts() 

    if (f == None):
        pass
    else:
        if (f == 'firacode'):
            f_name = 'FiraCode SemiBold'
            if (biggy_fonts):
                f_size = 15
            else:
                f_size = 11
        elif (f == 'fantasque'):
            f_name = 'Fantasque Sans Mono'
            if (biggy_fonts):
                f_size = 16
            else:
                f_size = 12
        elif (f == 'droidsans'):
            f_name = 'DroidSans'

            if (biggy_fonts):
                f_size = 16
            else:
                f_size = 12
        elif (f == 'ubuntumono'):
            f_name = 'UbuntuMono'

            if (biggy_fonts):
                f_size = 18
            else:
                f_size = 14

        config.update({'searchbar_font_name':f_name})
        config.update({'searchbar_font_size':f_size})


def get_screen_resolution():

    cmd = "xrandr | grep '*' | awk '{print $1}'"

    stdout, stderr, rc = run_cmd(cmd)

    if rc != 0 or not stdout:
        return None

    w = int(stdout.split('x')[0])
    h = int(stdout.split('x')[1])

    return w,h


def get_default_fonts():

    r, e, rc = run_cmd(['find /usr/share/fonts -iname "firacode*semibold*"'])

    if r:
        return 'firacode'

    r, e, rc = run_cmd(['find /usr/share/fonts -iname "fantasquesansmono*"'])

    if r:
        return 'fantasque'

    r, e, rc = run_cmd(['find /usr/share/fonts -iname "droidsans*"'])

    if r:
        return 'droidsans'

    r, e, rc = run_cmd(['find /usr/share/fonts -iname "ubuntumono*"'])
    
    if r:
        return 'ubuntumono'

    return None


def check_if_font_exists(fn=''):

    if (fn == ''):
        return False

    _fn = rm_space_with_asterisk(fn)

    cmd = 'find /usr/share/fonts -iname "%s*"' % (_fn)

    r, e, rc = run_cmd([cmd])

    if r:
        return True
    else:
        return False


def rm_space_with_asterisk(s=''):

    l = list(s)

    _l = []

    for i in range(len(l)):
        if (l[i] == ' '):
            _l.append('*')
        else:
            _l.append(l[i])

    return ''.join(_l)


def check_formatting(line=''):

    if (line == ''):
        return True
    elif (line.count('=') != 1):
        return False
    elif (check_arg(line) == False):
        return False
    else:
        return True


def check_arg(line=''):

    l = line.split('=')[1].strip()

    try:
        v = int(l)
        return True
    except (ValueError):
        pass

    if (l.lower() == 'true' or l.lower() == 'false'):
        return True
    if ("'" in l):
        if (l.count("'") == 2 and l[0] == "'" and l[-1] == "'"):
            return True
        else:
            return False
    elif ('"' in l):
        if (l.count('"') == 2 and l[0] == '"' and l[-1] == '"'):
            return True
        else:
            return False
    else:
        return False


#===========================================================================
#                      User input parsing functions                        #
#===========================================================================

def prompt(question="", enable_color=True):

    color = color_b('yellow')
    rst = color_reset()

    value = ""

    while (value == ""):

        if (enable_color):
            value = input(color_symbol_info() + ' ' + color + question + rst)
        else:
            value = input(color_symbol_info() + ' ' + text_highlight(question) + rst)

        if (value == ""):
            print(text_error("Field cannot be blank"))

    return value.lower()


def prompt_for_edit(question="", enable_color=True):

    color = color_b('yellow')
    rst = color_reset()

    value = ""

    while (value == ""):

        if (enable_color):
            value = input(color_symbol_prompt() + ' ' + color + question + rst)
        else:
            value = input(color_symbol_prompt() + ' ' + text_highlight(question) + rst)

        if (value == ""):
            print(text_error("Field cannot be blank"))

    return value.lower()


def prompt_with_sec_mem(question=""):

    sec_mem_handler = AllocateSecureMemory()

    color = color_b('yellow')
    rst = color_reset()

    while (True):

        sec_mem_handler.add_str_start(input(color_symbol_prompt() + ' ' + color + text_highlight(question) + rst))

        sec_mem_handler.lstrip()

        if (sec_mem_handler.has_space()):
            sec_mem_handler.clear_str()
            print(text_error('Password cannot contain space'))

        elif (not sec_mem_handler.is_empty()):
            break
        else:
            sec_mem_handler.clear_str()
            print(text_error('Password cannot be empty'))

    return sec_mem_handler


def prompt_blank(question="", enable_color=True):

    value = ''

    if (enable_color):
        color = color_b('yellow')
        rst = color_reset()
        value = input(color_symbol_info() + ' ' + color + question + rst)
    else:
        value = input(color_symbol_info() + ' ' +  text_highlight(question))

    return value


def prompt_blank_for_edit(question="", enable_color=True):

    value = ''

    if (enable_color):
        color = color_b('yellow')
        rst = color_reset()
        value = input(color_symbol_prompt() + ' ' + color + question + rst)
    else:
        value = input(color_symbol_prompt() + ' ' +  text_highlight(question))

    return value


def prompt_blank_fixed_width(question="", question_width=10, left_indent=2):

    color = color_b('yellow')
    rst = color_reset()

    symbol = '[+] '

    tl1 = list(' ' * (left_indent))
    tl2  = list(symbol)
    tl3 = list(' ' * (question_width))

    q_list = list(question)

    for i in range(len(q_list)):
        tl3[i] = q_list[i]

    text = ''.join(tl1) + color_b('green') + ''.join(tl2) + rst + \
           color + ''.join(tl3) + rst

    value = input(text)

    return value


def prompt_int(question="", default=0, min_value=0, max_value=30):

    while (True):
        try:
            tmp_value = input(color_symbol_info() + text_highlight(question))

            if (tmp_value == ''):
                return default

            tmp_value = int(tmp_value)
        except (ValueError):
            print(text_error('Please type an integer'))
            continue

        if (tmp_value < min_value):
            print(text_error('Need minimum length of %d characters' % min_value))
        elif (tmp_value > max_value):
            print(text_error('Maximum length limit of %d characters' % min_value))
        else:
            return tmp_value


def prompt_password(enforce_min_length=False, min_length=8, blacklisted_chars=[]):

    """
    Used during password generation, prompts for password twice
        in case user mistypes
    """

    color = color_b('yellow')
    rst = color_reset()

    value1 = ""
    value2 = ""

    while True:
        value1 = getpass(color_symbol_info() + color + " Enter new password: " + rst)
        value1 = value1.strip()

        if (value1 == ""):
            print(text_error("Field cannot be blank"))
            continue

        if (len(blacklisted_chars) != 0):

            found_blacklist_char = False

            for char in blacklisted_chars:

                if (char in value1):
                    found_blacklist_char = True
                    break

            if (found_blacklist_char):
                print(text_error("The following characters are not permitted (%s)" % convert_list_to_str(blacklisted_chars)))
                continue


        if (enforce_min_length and len(value1) < min_length):
            print(text_error("Minimum password length: %d " % min_length))
            continue
        else:

            while True:    

                print_block(1)

                value2 = getpass(color_symbol_info() + color + " Retype password: " + rst)
                value2 = value2.strip()

                if (value2 == ""):
                    print(text_error("Field cannot be blank"))
                    continue
                elif (value2 == value1):
                    return value1
                else:
                    print(text_error("Password don't match, try again!"))
                    break


def prompt_password_master(min_length=8):

    """
    Used to change master password of database
    """

    global enc_db_handler, config

    master_key = enc_db_handler.get_key()
    kf = config.get('keyfile_path')

    color = color_b('yellow')
    rst = color_reset()

    value1 = ""
    value2 = ""

    while True:

        key = ''

        value1 = getpass(color_symbol_info() + color + " Enter new password: " + rst)
        value1 = value1.strip()

        if (value1 == ""):
            print(text_error("Field cannot be blank"))
            continue
        elif (len(value1) < min_length):
            print(text_error("Minimum password length: %d " % min_length))
            continue
        else:

            if (kf != ''):
                key = enc_db_handler.generate_new_key(value1, False, False, kf)
            else:
                key = enc_db_handler.generate_new_key(value1, False, False)

            if (key == master_key):
                print(text_error("New password cannot be the same as old password"))
                continue
            else:
                break

    while True:    
        value2 = getpass(color_symbol_info() + color + " Retype password: " + rst)
        value2 = value2.strip()

        if (value2 == ""):
            print(color_symbol_info() + text_highlight(" Field cannot be blank"))
            continue
        elif (value2 == value1):
            return value1
        else:
            print(text_error("Password don't match, try again"))


def prompt_password_gui():

    app = wx.App()

    frame = wx.Frame(None, title='pwmgr')

    t_entry = wx.TextEntryDialog(frame, 'Enter Master Password: ', caption='pwmgr',
            style=wx.TE_PASSWORD|wx.CENTRE|wx.OK|wx.CANCEL, value='')

    if (t_entry.ShowModal() == wx.ID_OK and t_entry.GetValue() != ''):
        pwd = t_entry.GetValue()
        t_entry.Destroy()
        return pwd
    else:
        t_entry.Destroy()
        return False


def gui_msg(value=''):

    if (value == ''):
        return

    app = wx.App()

    frame = wx.Frame(None, title='pwmgr')
    msg = wx.MessageDialog(frame, value, caption='pwmgr', style=wx.OK|wx.CENTRE)

    msg.ShowModal()
    msg.Destroy()


def gui_confirmation(value=''):

    app = wx.App()

    frame = wx.Frame(None, title='pwmgr')

    msg = wx.MessageDialog(frame, value, caption='pwmgr', style=wx.OK|wx.CANCEL|wx.CENTRE)

    ID = msg.ShowModal()

    if (ID == wx.ID_OK):
        msg.Destroy()
        return True
    else:
        msg.Destroy()
        return False


def prompt_yes_no(question="", default=True, enable_color=True):

    """
    Asks yes/no & returns a boolean value.
    """

    choice_list = ['y', 'yes', 'yesh', 'n', 'no', 'nou']

    while (True):
        choice = prompt_blank(question, enable_color)

        if (choice in choice_list):
            if (choice in choice_list[:3]):
                return True
            else:
                return False
        elif (choice == ''):
            return default
        else:
            print(text_error("Invalid answer.  Please answer 'yes/no'"))


def prompt_yes_no_blank(question=""):

    """
    Asks yes/no & returns a boolean value.
    """

    choice_list = ['y', 'yes', 'yesh', 'n', 'no', 'nou']

    while (True):
        choice = prompt_blank(question)

        if  (choice in choice_list):
            if (choice in choice_list[:3]):
                return True
            else:
                return False
        elif (choice == ''):
            return ''
        else:
            print(text_error("Invalid answer. Please answer 'yes/no' or leave blank"))


#===========================================================================
#                           Printing functions                             #
#===========================================================================


def cursor_hide():

    print("\033[?25l")


def cursor_show():

    print("\033[?25h")


def text_b():

    return "\x1B[1m"


def color_n(c=''):

    """
    Normal colors
    """

    if (c == 'white'):
        return "\x1B[0;37m"
    elif (c == 'blue'):
        return "\x1B[0;34m"
    elif (c == 'yellow'):
        return "\x1B[0;38;5;220m"
    elif (c == 'red'):
        return "\x1B[0;31m"
    elif (c == 'green'):
        return "\x1B[0;32m"
    elif (c == 'black'):
        return "\x1B[0;30m"
    else:
        return ""


def color_b(c=''):

    """
    Bold colors
    """

    if (c == 'white'):
        return '\x1B[1;38;5;15m'
    elif (c == 'blue'):
        return '\x1B[1;34m'
    elif (c == 'purple'):
        return '\x1B[1;38;5;141m'
    elif (c == 'cyan'):
        return '\x1B[1;38;5;51m'
    elif (c == 'yellow'):
        return '\x1B[1;33m'
    elif (c == 'light_yellow'):
        return '\x1B[1;38;5;229m'
    elif (c == 'orange'):
        return '\x1B[1;38;5;214m'
    elif (c == 'red'):
        return '\x1B[1;31m'
    elif (c == 'green'):
        return '\x1B[1;38;5;118m'
    elif (c == 'black'):
        return '\x1B[1;38;5;0m'
    else:
        return ""


def color_bg(c=''):

    """
    Background colors
    """

    if (c == 'reset'):
        return "\x1B[40m"
    elif (c == 'white'):
        return '\x1B[1;48;5;15m'
    elif (c == 'blue'):
        return '\x1B[1;44m'
    elif (c == 'purple'):
        return '\x1B[1;48;5;141m'
    elif (c == 'cyan'):
        return '\x1B[1;48;5;51m'
    elif (c == 'yellow'):
        return '\x1B[1;48;5;229m'
    elif (c == 'orange'):
        return '\x1B[1;48;5;214m'
    elif (c == 'red'):
        return '\x1B[1;41m'
    elif (c == 'green'):
        return '\x1B[1;48;5;118m'
    elif (c == 'black'):
        return '\x1B[1;48;5;0m'
    else:
        return ""


def color_pair(p=''):

    """
    Color pair combination

    parameter format: 
        foreground_background
            e.g: 'white_black'
    """

    if (p == 'white_blue'):
        s = '%s%s' % (color_b('white'), color_bg('blue'))
        return s
    elif (p == 'white_yellow'):
        s = '%s%s' % (color_b('white'), color_bg('yellow'))
        return s
    elif (p == 'white_red'):
        s = '%s%s' % (color_b('white'), color_bg('red'))
        return s
    elif (p == 'white_green'):
        s = '%s%s' % (color_b('white'), color_bg('green'))
        return s
    elif (p == 'white_black'):
        s = '%s%s' % (color_b('white'), color_bg('black'))
        return s
    elif (p == 'blue_white'):
        s = '%s%s' % (color_b('blue'), color_bg('white'))
        return s
    elif (p == 'blue_yellow'):
        s = '%s%s' % (color_b('black'), color_bg('yellow'))
        return s
    elif (p == 'blue_red'):
        s = '%s%s' % (color_b('black'), color_bg('red'))
        return s
    elif (p == 'blue_green'):
        s = '%s%s' % (color_b('black'), color_bg('green'))
        return s
    elif (p == 'blue_black'):
        s = '%s%s' % (color_b('blue'), color_bg('black'))
        return s
    elif (p == 'yellow_white'):
        s = '%s%s' % (color_b('yellow'), color_bg('white'))
        return s
    elif (p == 'yellow_blue'):
        s = '%s%s' % (color_b('yellow'), color_bg('blue'))
        return s
    elif (p == 'yellow_red'):
        s = '%s%s' % (color_b('yellow'), color_bg('red'))
        return s
    elif (p == 'yellow_green'):
        s = '%s%s' % (color_b('yellow'), color_bg('green'))
        return s
    elif (p == 'yellow_black'):
        s = '%s%s' % (color_b('yellow'), color_bg('black'))
        return s
    elif (p == 'red_white'):
        s = '%s%s' % (color_b('red'), color_bg('white'))
        return s
    elif (p == 'red_blue'):
        s = '%s%s' % (color_b('red'), color_bg('blue'))
        return s
    elif (p == 'red_yellow'):
        s = '%s%s' % (color_b('red'), color_bg('yellow'))
        return s
    elif (p == 'red_green'):
        s = '%s%s' % (color_b('red'), color_bg('green'))
        return s
    elif (p == 'red_black'):
        s = '%s%s' % (color_b('red'), color_bg('black'))
        return s
    elif (p == 'green_white'):
        s = '%s%s' % (color_b('green'), color_bg('white'))
        return s
    elif (p == 'green_blue'):
        s = '%s%s' % (color_b('green'), color_bg('blue'))
        return s
    elif (p == 'green_yellow'):
        s = '%s%s' % (color_b('green'), color_bg('yellow'))
        return s
    elif (p == 'green_red'):
        s = '%s%s' % (color_b('green'), color_bg('red'))
        return s
    elif (p == 'green_black'):
        s = '%s%s' % (color_b('green'), color_bg('black'))
        return s
    elif (p == 'black_white'):
        s = '%s%s' % (color_b('black'), color_bg('white'))
        return s
    elif (p == 'black_blue'):
        s = '%s%s' % (color_b('black'), color_bg('blue'))
        return s
    elif (p == 'black_yellow'):
        s = '%s%s' % (color_b('black'), color_bg('yellow'))
        return s
    elif (p == 'black_red'):
        s = '%s%s' % (color_b('black'), color_bg('red'))
        return s
    elif (p == 'black_green'):
        s = '%s%s' % (color_b('black'), color_bg('green'))
        return s


def color_pair_error():

    return '\x1B[1;38;5;196m'


def color_theme_1():

    s = '\x1B[1;38;5;15m\x1B[1;48;5;25m'
    return s


def color_theme_2():

    s = '\x1B[1;38;5;15m\x1B[1;48;5;30m'
    return s


def color_theme_3():

    s = '\x1B[1;38;5;214m\x1B[1;48;5;233m'
    return s


def color_theme_4():

    s = '\x1B[1;38;5;15m\x1B[1;48;5;24m'
    return s


def color_theme_5():

    s = '\x1B[1;38;5;15m\x1B[1;48;5;130m'
    return s


def color_theme_6():

    s = '\x1B[1;38;5;214m\x1B[1;48;5;24m'
    return s


def color_theme_66():

    s = '\x1B[1;38;5;14m\x1B[1;48;5;233m'
    return s


def color_reset():
    """
    Reset bg & fg colors
    """

    return "\x1B[0m"


def text_error(text=''):

    text = '\n  ' + color_pair_error() + color_symbol_error() + \
            color_reset() + ' ' + text + ' ' + color_reset() + '\n'     

    return text


def text_color(text=''):

    global theme
    text = theme + text + color_reset()
    return text


def text_highlight(text=''):

    text = text_b() + text + color_reset()
    return text


def text_debug(text=''):

    text = color_symbol_debug() + " " + text_highlight(text)
    return text


def color_menu_bars(text=' '):

    global term_len_h, theme

    text = text * term_len_h
    rst = color_reset()
    text =  theme + text + rst

    return text


def plain_menu_bars(text='\u2501', color_enable=True):

    global term_len_h, term_bar_color

    text = text * term_len_h

    if (color_enable):
        text = term_bar_color + text + color_reset()

    return text


def color_menu_bars_dynamic(text=' ', term_len=[100,100]):

    global theme

    text = text * term_len
    rst = color_reset()
    text =  theme + text + rst

    return text

def color_menu_text(text=''):

    global term_len_h

    text_size = len(text)
    remaining_length = int(term_len_h - text_size)

    left  = 0
    right = 0

    if (remaining_length%2 == 0): # Even
        left  = int(remaining_length/2)
        right = int(remaining_length/2)
    else:
        left = int(remaining_length/2)
        right = remaining_length - left


    text =  theme + ' '*left + text + ' '*right + color_reset()

    return text


def color_menu_informational(text='', left_indent=0):

    global theme

    indent = '  '

    for i in range(left_indent):
        indent = '%s ' % indent

    text =  indent + theme + ' ' + text + color_reset()

    return text


def color_menu_column_header(header_list=[], left_indent=7):

    global term_len_h, theme

    text  = ' '*(term_len_h-left_indent)

    text_list = list(text)

    if (len(header_list) == 0):
        text = theme + text + color_reset()
        return text

    ratio_total = 0

    for i in range(len(header_list)):
        ratio_total = ratio_total + header_list[i][1]

    total_length = len(text_list) - left_indent

    mark = 0

    for i in range(len(header_list)):
        space_partition = int((total_length * header_list[i][1]) / ratio_total)
        char_str = list(header_list[i][0])
        char_length = len(header_list[i][0])
        right_space = space_partition - char_length


        for i in range(len(char_str)):
            text_list[mark] = char_str[i]
            mark += 1

        while (right_space > 0):
            text_list[mark] = ' '
            mark += 1
            right_space -= 1

    text = theme + ' ' * left_indent + ''.join(text_list) + color_reset()

    return text


def format_data_with_spacing(data_list=[], ratio=[4,4,2,2]):

    global term_len_h
    
    # Format (data_list)  = '#', 'Site', 'Username', 'Email', 'Group'

    # width of index is fixed at 6 chars, & ratio parameter is used to 
    # allocate space between the remaining fields site .. group

    number_indent = 7

    text  = ' '*(term_len_h - number_indent)

    text_list = list(text)

    if (len(data_list) == 0):
        text = ' '*term_len_h + color_reset()
        return text

    ratio_total = 0

    for i in ratio:
        ratio_total = ratio_total + i

    str_list = list(str(data_list[0]))

    # Adding additional space on left side, for record index
    while (len(str_list) < (number_indent-2)):
        str_list.insert(0, ' ')

    str_list.append(')')
    str_list.append(' ')

    mark = 0

    for i in range(1,len(data_list)):
        space_partition = int((len(text_list) * ratio[i-1]) / ratio_total)
        char_list = list(data_list[i])

        if (len(char_list) > space_partition):
            new_list = char_list[:space_partition-5]

            for j in range(len(new_list)):
                text_list[mark] = new_list[j]
                space_partition -= 1
                mark += 1

            while (space_partition > 0):
                if (space_partition <= 2):
                    text_list[mark] = ' '
                    space_partition -= 1
                    mark += 1
                else:
                    text_list[mark] = '.'
                    space_partition -= 1
                    mark += 1
        else:
            for j in range(len(char_list)):
                text_list[mark] = char_list[j]
                space_partition -= 1
                mark += 1

            while (space_partition > 0):
                text_list[mark] = ' '
                space_partition -= 1
                mark += 1

    text = color_b('yellow') + ''.join(str_list) + color_reset() + ''.join(text_list) 

    return text


def print_audit_info(data_list=[], ratio=[3,2,2,1,1]):

    global term_len_h

    # Format (data_list)  = '#', 'Site', 'pw str', 'pw age', 'pw reuse', 'sec rating'
    # width of index is fixed at 6 chars, & ratio parameter is used to
    # allocate space between the remaining fields site .. group

    number_indent = 7

    text  = ' '*(term_len_h - number_indent)

    text_list = list(text)

    if (len(data_list) == 0):
        text = ' '*term_len_h + color_reset()
        return text

    ratio_total = 0

    for i in ratio:
        ratio_total = ratio_total + i

    # Adding additional space on left side, for record index
    str_list = list(str(data_list[0][0]))

    while (len(str_list) < (number_indent-2)):

        str_list.insert(0, ' ')

    str_list.append(')')
    str_list.append(' ')

    list_to_be_processed = []

    for i in range(1, len(data_list)):

        space_partition = int((len(text_list) * ratio[i-1]) / ratio_total)
        char_list = list(data_list[i][0])

        if ((len(char_list)+2) >= space_partition):
            l = list(space_partition * ' ')

            l_len = len(l)
            c_len = len(char_list)
            v = max(l_len, c_len)

            if (v == l_len):
                for j in range(0, c_len):
                    l[j] = char_list[j]

                l[-1] = ' '
                l[-2] = ' '
                l[-3] = ' '
                l[-4] = '.'
                l[-5] = '.'
                l[-6] = '.'
            else:
                for j in range(0, l_len):
                    l[j] = char_list[j]

                l[-1] = ' '
                l[-2] = ' '
                l[-3] = ' '
                l[-4] = '.'
                l[-5] = '.'
                l[-6] = '.'

            list_to_be_processed.append(l)

        else:

            l = list(space_partition * ' ')

            for j in range(0, len(char_list)):
                l[j] = char_list[j]

            list_to_be_processed.append(l)

    color_rst = color_reset()

    text = color_b('yellow') + ''.join(str_list) + color_rst + \
            data_list[1][1] + ''.join(list_to_be_processed[0]) + color_rst + \
            data_list[2][1] + ''.join(list_to_be_processed[1]) + color_rst + \
            data_list[3][1] + ''.join(list_to_be_processed[2]) + color_rst + \
            data_list[4][1] + ''.join(list_to_be_processed[3]) + color_rst + \
            data_list[5][1] + ''.join(list_to_be_processed[4]) + color_rst 

    print(text)


def display_row_with_sec_mem(field_list=[], data_list=[], index=None, header_width=20, indent=5):

    global term_len_h, theme, field_color_fg

    if (len(data_list) == 0 or len(field_list) == 0):
        return

    if (term_len_h < 50):
        print(text_error('Terminal size too small to display data'))
        sys.exit(1)

    try:

        sec_mem_handler = enc_db_handler.get_pw_of_index_with_sec_mem(index)

    except IncorrectPasswordException:
        gui_msg('\nDecyption of password field in database failed!' + \
                '\n\n       Database could be partially corrupted')
        sys.exit(1)

    except MemoryAllocationFailedException:
        gui_msg('\nSecure memory function failed due to insufficient memory!' + \
                '\n\n       If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    except SecureClipboardCopyFailedException:
        gui_msg('\n        Secure memory function is unavailable (libc.so.6 not found)' + \
                '\n\nTry installing glibc package. If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    theme_num = config.get('theme')

    color_not_audited = '\x1B[1;38;5;250m\x1B[1;48;5;232m'
    color_good = '\x1B[1;38;5;10m\x1B[1;48;5;232m'
    color_neutral = '\x1B[1;38;5;226m\x1B[1;48;5;232m'
    color_bad = '\x1B[1;38;5;9m\x1B[1;48;5;232m'

    color_rst = color_reset()

    record = enc_db_handler.get_index_with_enc_pw(index) 

    audit_rating = record.get_pw_complexity()

    last_mod_rating = enc_db_handler.audit_pw_age_single_record(index)

    max_length = 0

    for i in range(len(data_list)):
        if (len(data_list[i]) > max_length):
            max_length = len(data_list[i])

    indent_text = ' ' * indent

    for i in range(len(data_list)):

        h_list = list(' ' * header_width)

        text_list = []

        field = '%s ' % field_list[i]
        f_list_char = list(field)
        
        d_list_char = list(data_list[i])

        for j in range(len(f_list_char)):
            h_list[j] = f_list_char[j]

        text = ''

        text_l_obj  = list(' ' * (term_len_h - ((2 * indent) + header_width)))

        if (len(text_l_obj) <= 0):
            print(text_error('Terminal size too small to display data'))
            sys.exit(1)

        if (len(d_list_char) > len(text_l_obj)):

            current_index = 0

            while (current_index < len(d_list_char)):

                for l in range(0, len(text_l_obj)):

                    if (current_index >= len(d_list_char)):
                        break

                    text_l_obj[l] = d_list_char[current_index]
                    current_index += 1

                text_list.append(text_l_obj)
                text_l_obj  = list(' ' * (term_len_h - ((2 * indent) + header_width)))

            text = ''

            if (theme_num == 66):
                text = '\x1B[1;38;5;214m' + indent_text + \
                        text_highlight(''.join(h_list)) + color_rst + \
                        field_color_fg + ''.join(text_list[0]) + color_rst
            else:
                text = field_color_fg + indent_text + \
                        text_highlight(''.join(h_list)) + color_rst + \
                        field_color_fg + ''.join(text_list[0]) + color_rst

            print(text)

            blank_header = h_list

            for crab_c in range(len(blank_header)):

                blank_header[crab_c] = ' '

            blank_header = ''.join(blank_header)

            for line in text_list[1:]:

                text = indent_text + blank_header + field_color_fg + ''.join(line) + color_rst

                print(text)
        else:

            for k in range(len(d_list_char)):
                text_l_obj[k] = d_list_char[k]

            if (i == 1):

                text = ''

                if (theme_num == 66):

                    text = '\x1B[1;38;5;214m' + indent_text + \
                            text_highlight(''.join(h_list)) + color_rst 
                else:

                    text = field_color_fg + indent_text + \
                            text_highlight(''.join(h_list)) + color_rst 

                sys.stdout.write(text)
                
                pw_sec_color = ''

                if (theme_num == 66):

                    if (audit_rating == ''):
                        pw_sec_color = color_not_audited
                    elif (audit_rating == 'e' or audit_rating == 'g'):
                        pw_sec_color = color_good
                    elif (audit_rating == 'a'):
                        pw_sec_color = color_neutral
                    else:
                        pw_sec_color = color_bad

                sys.stdout.write('%s' % pw_sec_color)
                sec_mem_handler.print_str()
                sys.stdout.write('%s' % color_rst)
                print()

            elif (i == 8 and theme_num == 66):

                # pw_age (3): 'n' =  3, 'o' =  2, 'r' = -1

                last_mod_color = ''

                if (last_mod_rating == 'n'):
                    last_mod_color = color_good
                elif (last_mod_rating == 'o'):
                    last_mod_color = color_neutral
                elif (last_mod_rating == 'r'):
                    last_mod_color = color_bad
                else:
                    last_mod_color = color_not_audited


                start_index = len(text_l_obj) - 1

                while (start_index > 0):

                    if (text_l_obj[start_index] == ' '):
                        pass
                    else:
                        text_l_obj[start_index+1] = color_rst
                        break

                    start_index -= 1


                text = '\x1B[1;38;5;214m' + indent_text + text_highlight(''.join(h_list)) + color_rst + \
                        last_mod_color + ''.join(text_l_obj) 

                print(text)

            else:

                text = ''

                if (theme_num == 66):

                    text = '\x1B[1;38;5;214m' + indent_text + \
                            text_highlight(''.join(h_list)) + color_rst + \
                            field_color_fg + ''.join(text_l_obj) + color_rst
                else:

                    text = field_color_fg + indent_text + \
                            text_highlight(''.join(h_list)) + color_rst + \
                            field_color_fg + ''.join(text_l_obj) + color_rst

                print(text)

    sec_mem_handler.wipe_memory()


def display_row_static_with_sec_mem(field_list=[], data_list=[], index=None, header_width=20, indent=5):

    global config, term_len_h, term_len_v, theme, field_color_fg, enc_db_handler, sec_mem_handler

    if (len(data_list) == 0 or len(field_list) == 0 or index == None):
        return

    if (term_len_h < 50):
        print(text_error('Terminal size too small to display data'))
        sys.exit(1)

    theme_num = config.get('theme')

    sec_mem_handler = None

    color_not_audited = '\x1B[1;38;5;250m\x1B[1;48;5;232m'
    color_good = '\x1B[1;38;5;10m\x1B[1;48;5;232m'
    color_neutral = '\x1B[1;38;5;226m\x1B[1;48;5;232m'
    color_bad = '\x1B[1;38;5;9m\x1B[1;48;5;232m'

    color_rst = color_reset()

    record = enc_db_handler.get_index_with_enc_pw(index) 

    audit_rating = record.get_pw_complexity()

    last_mod_rating = enc_db_handler.audit_pw_age_single_record(index)

    try:

        sec_mem_handler = enc_db_handler.get_pw_of_index_with_sec_mem(index)

    except IncorrectPasswordException:
        gui_msg('\nDecyption of password field in database failed!' + \
                '\n\n       Database could be partially corrupted')
        sys.exit(1)

    except MemoryAllocationFailedException:
        gui_msg('\nSecure memory function failed due to insufficient memory!' + \
                '\n\n       If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    except SecureClipboardCopyFailedException:
        gui_msg('\n        Secure memory function is unavailable (libc.so.6 not found)' + \
                '\n\nTry installing glibc package. If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    count = 0

    term_settings_original = get_term_settings()
    unset_term_mode_raw()

    try:

        while (True):

            sleep(0.05)

            term_length_var_h, term_length_var_v = os.get_terminal_size()

            if (term_length_var_h == term_len_h and \
                    term_length_var_v == term_len_v and \
                    count != 0):

                continue

            else:

                if (term_length_var_v < 14):

                    clear_screen()
                    print_block(1)
                    print(text_error('Vertical screen size too small to display data'))
                    sleep(1)
                    clear_screen()
                    sleep(0.5)
                    continue

                count += 1

                term_len_h = term_length_var_h
                term_len_v = term_length_var_v

                num_vert_lines = term_len_v - 14
                num_lines_top = int(num_vert_lines/2) 

                if ((num_vert_lines % 2) != 0):
                    num_lines_top = int(num_vert_lines/2) - 1

                clear_screen()

                print_block(num_lines_top)

                print(plain_menu_bars())

                print_block(1)

                max_length = 0

                for i in range(len(data_list)):
                    if (len(data_list[i]) > max_length):
                        max_length = len(data_list[i])

                indent_text = ' ' * indent

                for i in range(len(data_list)):

                    h_list = list(' ' * header_width)

                    text_list = []

                    field = '%s ' % field_list[i]
                    f_list_char = list(field)
                    d_list_char = list(data_list[i])

                    if (theme_num == 66):

                        f_list_char.insert(0, '\x1B[1;38;5;214m')

                        if (f_list_char[-1] == ' '):
                            f_list_char[-1] = color_rst
                        else:
                            f_list_char.append(color_rst)

                        if (not (i == 1 or i == 8)):
                            d_list_char.insert(0, field_color_fg)

                    for j in range(len(f_list_char)):
                        h_list[j] = f_list_char[j]

                    text = ''

                    text_l_obj  = list(' ' * (term_len_h - ((2 * indent) + header_width)))

                    if (len(text_l_obj) <= 0):
                        print(text_error('Terminal size too small to display data'))
                        restore_term_settings(term_settings_original)
                        sys.exit(1)

                    if (len(d_list_char) > len(text_l_obj)):

                        current_index = 0

                        while (current_index < len(d_list_char)):

                            for l in range(0, len(text_l_obj)):

                                if (current_index >= len(d_list_char)):
                                    break

                                text_l_obj[l] = d_list_char[current_index]
                                current_index += 1

                            text_list.append(text_l_obj)
                            text_l_obj = list(' ' * (term_len_h - ((2 * indent) + header_width)))

                        text = field_color_fg + indent_text + \
                                text_highlight(''.join(h_list)) + color_rst + ''.join(text_list[0]) + color_rst

                        print(text)

                        blank_header = h_list

                        for crab_c in range(len(blank_header)):

                            blank_header[crab_c] = ' '

                        blank_header = ''.join(blank_header)

                        for line in text_list[1:]:

                            if (theme_num == 66):
                                text = indent_text + blank_header + field_color_fg + ''.join(line) + color_rst
                            else:
                                text = field_color_fg + indent_text + blank_header + color_rst + ''.join(line) + color_rst

                            print(text)
                    else:

                        for k in range(len(d_list_char)):
                            text_l_obj[k] = d_list_char[k]

                        if (i == 1):

                            pw_sec_color = ''

                            text = field_color_fg + indent_text + text_highlight(''.join(h_list)) + color_rst
                            sys.stdout.write(text)

                            if (theme_num == 66):

                                ## pw_complexity (6):   'e' =  6, 'g' =  4, 'a' = 2, 'w' = -2, 'u' = -4

                                if (audit_rating == ''):
                                    pw_sec_color = color_not_audited
                                elif (audit_rating == 'e' or audit_rating == 'g'):
                                    pw_sec_color = color_good
                                elif (audit_rating == 'a'):
                                    pw_sec_color = color_neutral
                                else:
                                    pw_sec_color = color_bad

                                sys.stdout.write('%s' % pw_sec_color)
                                sec_mem_handler.print_str()
                                sys.stdout.write('%s' % color_rst)

                            else:
                                sec_mem_handler.print_str()

                            print()

                        else:

                            if (i == 8 and theme_num == 66):

                                # pw_age (3): 'n' =  3, 'o' =  2, 'r' = -1

                                last_mod_color = ''

                                if (last_mod_rating == 'n'):
                                    last_mod_color = color_good
                                elif (last_mod_rating == 'o'):
                                    last_mod_color = color_neutral
                                elif (last_mod_rating == 'r'):
                                    last_mod_color = color_bad
                                else:
                                    last_mod_color = color_not_audited

                                text_l_obj.insert(0, last_mod_color)

                                index_text_l = len(text_l_obj) - 1

                                while (index_text_l >= 0):

                                    if (text_l_obj[index_text_l] == ' '):
                                        index_text_l -= 1
                                    else:
                                        text_l_obj[index_text_l+1] = color_rst
                                        break

                                text = field_color_fg + indent_text + text_highlight(''.join(h_list))
                                sys.stdout.write(text)
                                sys.stdout.write(''.join(text_l_obj))
                                print()

                            else:
                                text = field_color_fg + indent_text + text_highlight(''.join(h_list)) + color_rst + ''.join(text_l_obj) + color_rst
                                print(text)

                print_block(1)
                print(plain_menu_bars())
                print_block(1)

    except OSError:
        pass
    except KeyboardInterrupt:
        pass

    if (sec_mem_handler != None):
        sec_mem_handler.wipe_memory()

    restore_term_settings(term_settings_original)
    cursor_show()
    clear_screen()
    sys.exit(0)


def color_symbol_prompt():

    text = '  ' + color_b('yellow') + '\u25BA ' + color_reset()
    return text


def color_symbol_info():

    text = '  ' + color_b('green') + '[+]' + color_reset()
    return text


def color_symbol_error():

    return '[-]'


def color_symbol_debug():

    text = '  ' + color_b('yellow') + '[*]' + color_reset()
    return text


def print_not_implemented():

    print(text_error("Feature not implemented yet"))


def print_block(n=3):
    for i in range(n):
        print()


def print_header():

    global __title, __version__

    txt_color = '\x1B[1;38;5;87m' 

    # header = \
    # """
    # ------------------------------------------------------------------


    #                        %s%s %s%s%s


    # ------------------------------------------------------------------""" \
    #         % (txt_color, text_highlight(__title__), \
    #         txt_color, text_highlight(__version__), color_reset())

    lines = '    ' + '\u2501' * 71

    print()
    print(lines)

    header = \
    """

                             %s%s %s%s%s

    """ % (txt_color, text_highlight(__title__), \
            txt_color, text_highlight(__version__), color_reset())

    print(text_highlight(header))

    print(lines)


def print_help():

    print_header()

    txt_color = '\x1B[1;38;5;255m'

    print(
    """

    %s[add, -a]

         %sAllows the user to add a new record to the database%s


    %s[edit, -e] %s[record number]

         %sAllows the user to edit the specified entry in the database%s


    %s[search, -s] [group | site | email | username | all] %s[keyword]

         %sSearch by group, site, ..., etc. 

         %sAll records that match the specified keyword will be shown 

         %s* By default the search keyword without any other additional
         %s  parameters uses the 'search all' function
         
         %sgroup     - Search for the keyword by group 
         %ssite      - Search for the keyword by website 
         %semail     - Search for the keyword by email address
         %susername  - Search for the keyword by username
         %sall       - Search for the keyword in in all of the
         %s            above categories%s


    %s[show, -o] %s[record number]

         %sShow details about the specific record from the database

         %s* Without a record number (pwmgr -o), the show command 
         %s  displays a brief summary of the entire database

         %s* Multiple comma separated values can also be passed 
         %s  to the show command, e.g: 'pwmgr -o 1,2,3'%s


    %s[show-searchbar, -O]
        
         %sSearch & display record using search bar%s


    %s[show-recent, -sr]
    
         %sShow all entries from database sorted by most recently updated%s 


    %s[copy, -c] %s[record number]

         %sCopies the password for the specific entry to the clipboard%s 
    

    %s[copy-searchbar, -C]
        
         %sSearches for record using search bar & copies password to clipboard%s 
          

    %s[remove, -d] %s[record number]

         %sRemove the specified entry from the database

         %s* This command also accepts comma separated values & 
         %s  can remove multiple entries. e.g: 'pwmgr -d 55,48'%s


    %s[generate-pw, -g]

         %sGrants access to the password generator%s 


    %s[generate-keyfile, -gk] %s[file path]
        
         %sAllows the user to generate a secure, pseudo random keyfile

         %s* If a path is not provided, the key file is saved in 
         %s  '~/.config/pwmgr' directory%s 


    %s[use-keyfile, -uk] %s[file path]

         %sAdd key file to compliment the master password

         %s* If a path is not provided, pwmgr will search for key file
         %s  in '~/.config/pwmgr' directory 

         %s* This function can also be used to change an existing keyfile%s


    %s[list-keyfile, -lk] [brief | full]

         %sList the keyfile that is currently being used by the database

         %s* Option brief shows the last 50 bits of base64 encoded keyfile 
         %s  whereas full option displays the complete form. If no option 
         %s  is specified, brief is used%s
        

    %s[remove-keyfile, -rk]

         %sRemoves the existing key file that is being used by the database

         %s* Without a key file, only master password will be used for 
         %s  encryption / decryption of database%s


    %saudit [show-all]

         %sPerforms a security audit on all records & reports 
         %sthe overall security posture. Factors such as password 
         %scomplexity, whether the password was reused in another
         %srecord and password age is used to determine the overall 
         %srisk of using that password
 
         %s* If show-all is specified, rating for all records are displayed%s


    %spw-reset

         %sAllows the user to change the master password%s


    %skey-show

         %sDisplays the current master key that is being used 
         %sfor encryption / decryption%s


    %skeyring-reset

         %sAllows the user to remove password from keyring

         %s* This command can be useful for example if you have 
         %s  a different password database & you want to remove
         %s  the previous password that was set on the keyring%s


    %sconvert-csv %s[input file] [output file]
    
         %sConverts an unquoted or single quoted csv file to double quoted format%s


    %sselect-cols-csv %s[order of rows] [input file] [output file]
    
         %sLoads csv database, selects & rearranges columns in the specified order

         %s* Can also be used to remove columns that are not needed%s


    %simport-csv %s[input file]

         %sImports database from csv file, the following formats are supported:

             %s1) site,password
             %s2) site,password,username
             %s3) site,password,username,email
             %s4) site,password,username,email,notes

             %s5) site,pass,last_modified,email,notes, ..

             %s   (14 fields, including security audit attributes)
             %s      * Used in pwmgr version >= 1.9%s


    %sexport-csv %s[output file]

         %sExports all fields in the database to csv format%s


    %sexport-csv-brief %s[output file]

         %sExports only 'site,password,username' fields to csv format%s


    %ssearch-font %s[keyword]

         %sLists fonts found on your system based on keyword%s

    """ % (color_b('orange'), txt_color, color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,  color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color, \
            txt_color,txt_color,txt_color,txt_color,txt_color, \
            txt_color,txt_color,txt_color,txt_color, color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,txt_color,txt_color,txt_color,txt_color, color_reset(), \
            color_b('orange'), txt_color, color_reset(), \
            color_b('orange'), txt_color, color_reset(), 
            color_b('orange'), color_b('yellow'), txt_color, color_reset(), \
                    color_b('orange'), txt_color, color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color, txt_color, txt_color, color_reset(), \
            color_b('orange'), txt_color, color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,txt_color,txt_color, color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,txt_color,txt_color,txt_color, color_reset(), \
            color_b('orange'), txt_color,txt_color,txt_color,txt_color, color_reset(), \
            color_b('orange'), txt_color,txt_color,txt_color, color_reset(), 
            color_b('orange'), txt_color,txt_color,txt_color,txt_color,txt_color,txt_color,color_reset(), \
            color_b('orange'), txt_color, color_reset(), \
            color_b('orange'), txt_color,txt_color,color_reset(), \
            color_b('orange'), txt_color,txt_color,txt_color,txt_color,color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,txt_color,color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,txt_color,txt_color,txt_color,txt_color,txt_color,txt_color,txt_color, color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,color_reset(), \
            color_b('orange'), color_b('yellow'), txt_color,color_reset()))


#===========================================================================
#                           Utility functions                              #
#===========================================================================


def l(value=''):

    """
    Returns lower case version of input string

    """

    return value.lower()


def convert_list_to_str(l=[]):

    return ','.join(l)


def parse_comma(value=''):

    if (type(value) == str and value != ''):
        if (',' in value):
            data = value.strip().split(',')
            return data
        else:
            return value

    return []


def escape_str(s='', char="'"):

    _s = ''

    for i in range(len(s)):

        if (s[i] == char):
            _s += '\\'

        _s += s[i]

    return ''.join(_s)


def convert_str_to_int(val=None):

    """
    Takes a string or a comma separated value, converts them
        and returns a list.

    Args: Either string representation of int or a list of
          comma separated integer in the form of a string.
          Example: '1' or '1,2,3'

    Returns: [True/False, [integer list]]
             - First parameter is False if any of the integer
               conversion failed. It is only True if all conversions
               succeed
             - Second Second parameter is the converted integer
               values from the comma separated values or just
               an integer depending on the input
                

    """

    if (val == None):
        return [False, []]
    elif (type(val) == str):

        val = parse_comma(val)

        if (type(val) == str):
            try:
                val = val.strip()
                index = int(val)
            except (ValueError):
                return [False, []]
            return [True, index]
        elif (type(val) == list):
            val_list = []
            try:
                for i in val:
                    val_list.append(int(i))

                return [True, val_list]
            except (ValueError):
                return [False, val_list]
        else:
            return [False, []]
    else:
        return [False, []]


def remove_whitespace(s=''):

    _s = ''

    for i in range(len(s)):
        if (s[i] != ' '):
            _s += s[i]

    return _s


def remove_whitespace_from_list(l=[], remove_all_whitespace=False):

    _l = []

    for item in l:

        if (remove_all_whitespace):
            _l.append(remove_whitespace(item))

        else:
            _l.append(item.strip())

    return _l


def clear_screen():

    """
    Clears screen, command is compatible with different OS
    """

    cmd = 'clear'

    os.system(cmd)


def custom_refresh(n1=3, n2=1, print_menu_bars=True):

    clear_screen()
    print_block(n1)

    if (print_menu_bars):
        print(color_menu_bars())
        print_block(n2)


def get_username():

    return os.getlogin()


def run_cmd(cmd=[], verbose=False):

    """
    Executes bash commands on local Linux system
    """

    if (cmd != []):
        process = subprocess.Popen(cmd, shell=True, \
                                   stdout=subprocess.PIPE, \
                                   stderr=subprocess.PIPE)

        stdout,stderr = process.communicate()

        stdout = stdout.decode('ascii').strip()
        stderr = stderr.decode('ascii').strip()

        if (verbose == True):
            print(stdout)

        return stdout, stderr, process.returncode


def check_files(files=[]):

    """
    Iterates over list of input files & verifies if they exist

    Returns: Boolean indicating whether all paths are valid files
    """

    if (files != []):
        for f in files:
            if (os.path.isfile(f)):
                pass
            else:
                #print("File %s doesn't exist." % f)
                return False

        return True


def check_if_prog_exists(p_name=[]):

    """
    Validates whether a list of programs exist

    Returns: Bool, list (str)

             1) Returns True if all of them exist, otherwise False
             2) List of path names to the program (if they exist) otherwise
                it returns the program name which was not found
    """

    if (len(p_name) == 0):
        return False

    l = []

    for p in p_name:
        cmd = 'which %s' % p

        stdout, stderr, rc = run_cmd([cmd])

        if (rc == 1):
            return False, p
        else:
            l.append(stdout)

    return True, ''


#==========================================================================#
#                       Password Generation Functions                      #
#==========================================================================#


def gen_pass(length=10, enableSymbols=True, debug=False):

    """
    Generates a secure password

    Args: 
        length (int): The length of specified password
        enableSymbols (bool): Allow symbols in password (default: True)
        debug (bool): Enable printing of generated password

    Returns: 
        (str) Generated password
    """

    if length <= 0:
        return ""

    seed()

    symbols = "!@#$%^&*(){}[]<>?+-:;"
    num = "0123456789"
    lcase = "abcdefghijklmnopqrstuvwxyz"
    ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    password = ""

    if (enableSymbols):

        for i in range(length+1):
            choice = rand_list([0,5,2,4,3,1])

            if (choice == 0 or choice == 1):
                password = "%s%s" % (password, rand_list(symbols))
            elif (choice == 2 or choice == 3):
                password = "%s%s" % (password, rand_list(num))
            elif (choice == 4):
                password = "%s%s" % (password, rand_list(lcase))
            elif (choice == 5):
                password = "%s%s" % (password, rand_list(ucase))

        password = update_missing_type(password)

    else:

        for i in range(length+1):
            choice = rand_list([3,1,2,0])

            if (choice == 0 or choice == 1):
                password = "%s%s" % (password, rand_list(num))
            elif (choice == 2):
                password = "%s%s" % (password, rand_list(lcase))
            elif (choice == 3):
                password = "%s%s" % (password, rand_list(ucase))

    if (debug):
        print(password)

    return password


def gen_pass_secure(length=10, debug=False, grid=True, enableSymbols=True):

    """
    Generates a grid of 10 passwords of length 10,
        and selects a random column among them

    Args:
        length (int): Length of the generated password
        debug(bool):  Prints all generated passwords
        grid(bool):   Returns a grid of generated password
                        of size length x length

        enableSymbols (bool): Allow symbols in password (default: True)

    Returns:
        (str): Generated password

                or

        int []: An array of generated passwords   
    """

    password_array = []

    for i in range(length):

        password_array.append(gen_pass(length, enableSymbols, debug))

    password = ""

    if (grid):
        return password_array
    else:
        index = randint(0, length)

        for i in range(length):
            password = "%s%s" % (password, password_array[i][index])

        return password


def update_missing_type(pwd=''):

    """
    Take a password string & makes sure that all types
    (alphanumeric + symbols) are present. If not, update
    it accordingly & return the new string.

    Args:       (str)

    Returns:    (str)
    """

    symbols = "!@#$%^&*(){}[]<>?+-:;"
    num = "0123456789"
    lcase = "abcdefghijklmnopqrstuvwxyz"
    ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    output = get_max_missing_type(pwd)

    pwd_list = list(pwd)

    if (output[1] != []):

        c = ''

        for i in output[1]:

            if i == 0:
                c  = "%s" % (rand_list(symbols))
            elif i == 1:
                c  = "%s" % (rand_list(num))
            elif i == 2:
                c  = "%s" % (rand_list(lcase))
            elif i == 3:
                c  = "%s" % (rand_list(ucase))
            
            index = get_type_index(pwd, output[0])

            if (index != None):
                pwd_list[index] = c

        updated_value = update_missing_type(''.join(pwd_list))

        return updated_value

    else:
        return pwd


def get_type_index(s, char_type):

    """
    Returns first occurence of the character set type

    Parameters:
    s = (str)

    char_type:
    0 : if the type is symbol
    1 : if the type is number
    2 : if the type is lower case
    3 : if the type is upper case
    """

    if (char_type not in [0,1,2,3]):
        return None

    symbols = "!@#$%^&*(){}[]<>?+-"
    num = "0123456789"
    lcase = "abcdefghijklmnopqrstuvwxyz"
    ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    s_list = list(s)

    if (char_type == 0):
        for i in range(len(s_list)):
            if s_list[i] in symbols:
                return i
    elif (char_type == 1):
        for i in range(len(s_list)):
            if s_list[i] in num:
                return i
    elif (char_type == 2):
        for i in range(len(s_list)):
            if s_list[i] in lcase:
                return i
    elif (char_type == 3):
        for i in range(len(s_list)):
            if s_list[i] in ucase:
                return i

    return None


def get_max_missing_type(s):

    """
    Checks a str & returns a tuple. First value
    denotes the maximum occurence of that type in the string,
    while the second value (which is a list) denotes if any types
    are missing. If all types are present, returns an empty list
    as second parameter.

    Args:       (str)

    Returns: Tuple with two values (max_type, [missing_type])
             

    0 : if the type is symbol
    1 : if the type is number
    2 : if the type is lower case
    3 : if the type is upper case
    """
    
    symbols = "!@#$%^&*(){}[]<>?+-"
    num = "0123456789"
    lcase = "abcdefghijklmnopqrstuvwxyz"
    ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    s_count = 0
    n_count = 0
    l_count = 0
    u_count = 0

    tmp_str = list(s)

    for i in range(len(tmp_str)):
        if (tmp_str[i] in symbols):
            s_count += 1
        elif (tmp_str[i] in num):
            n_count += 1
        elif (tmp_str[i] in lcase):
            l_count += 1
        elif (tmp_str[i] in ucase):
            u_count += 1

    l = [s_count, n_count, l_count, u_count]

    max_type = l.index(max(l))

    missing_type_list = []

    if (s_count == 0):
        missing_type_list.append(0)

    if (n_count == 0):
        missing_type_list.append(1)

    if (l_count == 0):
        missing_type_list.append(2)

    if (u_count == 0):
        missing_type_list.append(3)

    return (max_type, missing_type_list)


def rand_list(input_list=[]):

    """
    Returns a random element from the input list

    Args:
        input_list (list): The provided list

    Returns:
        object chosen randomly from the list
    """

    if len(input_list) == 0:
        return ""

    index = randint(0, len(input_list)-1)

    return input_list[index]


#===========================================================================#
#                             Dmenu / Search Bar                            #
#===========================================================================#


def run_searchbar(input_list=[]):

    """
    Takes a list of strings as parameter, runs searchbar with
    those choices & returns the index chosen

    Args:       1) Input list of type string
                2) The background color for searchbar

    Returns:    1) Index of item that was chosen from the list
                2) Returns None if nothing was chosen / menu
                   was cancelled.
                3) Returns None if empty list is passed as parameter

    """

    #TODO: Searchbar color setup based on theme

    global config

    # Setting Background / Foreground colors
    # based on the theme that has been set

    _color_background = ''
    _color_foreground = ''

    if (config.get('theme') == 1):
        _color_background = '#1C51A3'
        _color_foreground = '#FFFFFF'
    elif (config.get('theme') == 2):
        _color_background = '#1a552b'
        _color_foreground = '#FFFFFF'
    elif (config.get('theme') == 3):
        _color_background = '#000000'
        _color_foreground = '#FFB737'
    elif (config.get('theme') == 4):
        _color_background = '#015072'
        _color_foreground = '#FFFFFF'
    elif (config.get('theme') == 5):
        _color_background = '#844306'
        _color_foreground = '#FFFFFF'
    elif (config.get('theme') == 6):
        _color_background = '#013951'
        _color_foreground = '#FFB737'
    elif (config.get('theme') == 66):
        _color_background = '#010304'
        _color_foreground = '#0fc6ff'
    else:
        # Setting to default theme 1, if no theme found
        _color_background = '#1C51A3'
        _color_foreground = '#FFFFFF'

    msg = ''

    if (len(input_list) == 0):
        return None

    msg = input_list[0]

    if (len(input_list) > 1):
        for i in range(1, len(input_list)):
            msg = '%s\n%s' % (msg, input_list[i])

    cmd1 = 'echo -e "%s"' % msg

    fn = config.get('searchbar_font_name')
    fs = config.get('searchbar_font_size')

    cmd2 = "dmenu -fn '%s-%s' -l 7 -i -p 'pwmgr (search)' -sb '%s' -sf '%s'" % (fn, fs, _color_background, _color_foreground)
    cmd3 = '%s|%s' % (cmd1, cmd2)

    stdout, stderr, return_code = run_cmd(cmd3)

    if (return_code == 0):
        index = input_list.index(stdout.strip())
        return index
    else:
        return None


def search_bar_show():

    """
    Search using search bar & display selected record

    Args:    N/A

    Returns: N/A
    """

    global enc_db_handler

    summary_list = enc_db_handler.get_summary()

    try:

        index = run_searchbar(summary_list)

        if (index == None):
            sys.exit(1)

    except ValueError:
        sys.exit(1)

    cursor_hide()

    global term_len_h

    header, data = get_record_at_index(index)
    show_index_static(header, data, index)


def search_bar_copy():

    """
    Displays search bar & copies chosen password to clipboard

    Args:    N/A

    Returns: N/A
    """

    global enc_db_handler

    summary_list = enc_db_handler.get_summary()

    index = run_searchbar(summary_list)

    if (index == None):
        sys.exit(1)

    secure_copy_password(index)


#===========================================================================#
#                       Custom Commandline Interface                        #
#===========================================================================#


def menu_generate_password():

    """
    Menu that takes care of user password generation & selection process

    Input:   None

    Returns: Password (str)
    """

    global term_len_h

    term_length_var_h = term_len_h

    color = color_b('yellow')
    rst = color_reset()

    pwd = ''

    length = prompt_int(color + " Enter password length (default - 10): " + rst, 10, 6, 30)

    print_block(1)

    enable_symbols = prompt_yes_no("Enable symbols in password? (Y/n): ", True)

    cursor_hide()

    while (pwd == ''):

        password_list = gen_pass_secure(length, False, True, enable_symbols)

        for password in password_list:

            output = detect_screen_res_change()

            if (output[0]):
                term_length_var_h = output[1]

            custom_refresh(1,0)
            print(color_menu_bars_dynamic(' ', term_length_var_h))
            print(color_menu_bars_dynamic(' ', term_length_var_h))
            print_block(5)

            print(color_symbol_info() + \
                    text_highlight(" Generated password:  "), text_color(password))

            print_block(5)

            menu_text = "(G) Generate password | (S) Select | (Q) Quit"

            print(color_menu_bars_dynamic(' ', term_length_var_h))
            print(color_menu_text(menu_text))
            print(color_menu_bars_dynamic(' ', term_length_var_h))

            while (True):
                char = getch()

                if (char == 'g' or char == 'G'):
                    break
                elif (char == 's' or char == 'S'):
                    pwd = password
                    break
                elif (char == 'q' or char == 'Q'):
                    cursor_show()
                    print_block()
                    sys.exit(1)
                else:
                    pass

            if (pwd != ''):
                break

    cursor_show()

    return pwd


def menu_generate_password_standalone():

    """
    Password generator that helps the user pick a password. 

    Input:   None

    Returns: Password (str)
    """

    global term_len_h

    term_length_var_h = term_len_h

    color = color_b('yellow')
    rst = color_reset()

    print()

    pwd = ''

    length = prompt_int(color + " Enter password length (default - 10): " + rst, 10, 6, 30)

    print_block(1)

    enable_symbols = prompt_yes_no("Enable symbols in password? (Y/n): ", True)

    print_block(1)

    cursor_hide()


    while (pwd == ''):

        password_list = gen_pass_secure(length, False, True, enable_symbols)

        for password in password_list:

            output = detect_screen_res_change()

            if (output[0]):
                term_length_var_h = output[1]

            custom_refresh(1,0)
            print(color_menu_bars_dynamic(' ', term_length_var_h))
            print(color_menu_bars_dynamic(' ', term_length_var_h))
            print_block(5)

            print(color_symbol_info() + \
                    text_highlight(" Generated password:  "), text_color(password))

            print_block(5)

            menu_text = "(G) Generate password | (Q) Quit"

            print(color_menu_bars_dynamic(' ', term_length_var_h))
            print(color_menu_text(menu_text))
            print(color_menu_bars_dynamic(' ', term_length_var_h))

            while (True):

                char = getch()

                if (char == 'g' or char == 'G'):
                    break
                elif (char == 'q' or char == 'Q'):
                    cursor_show()
                    print_block()
                    sys.exit(1)
                else:
                    pass

            if (pwd != ''):
                break

    cursor_show()


def detect_screen_res_change():

    global term_len_h

    try:

        term_length_var_h = os.get_terminal_size()[0]

        if (term_length_var_h != term_len_h):
            term_len_h = term_length_var_h
            clear_screen() 
            return True, term_len_h
        else:
            return False, term_len_h

    except (OSError):
        return False, term_len_h


def get_term_settings():

    return termios.tcgetattr(0)


def unset_term_mode_raw():

    tty.setcbreak(0)


def restore_term_settings(original_attrs=''):

    termios.tcsetattr(0, termios.TCSADRAIN, original_attrs)


def generate_keyfile(file_path='', confirm=True, debug=True):

    cmd = ''

    color = color_b('green')
    rst = color_reset()

    length = 2048

    print_block(1)

    while (True):

        l = prompt_blank("Enter length of keyfile (default - 2048 bits): ")

        if (l == ""):
            break

        try:
            l = int(l)
        except (ValueError):
            print(text_error('An integer value is required'))
            continue

        if (l < 2048):
            print(text_error('Length cannot be less that 2048 bits'))
            continue
        else:
            length = l
            break


    if (file_path == ''):
        keyfile_name = 'keyfile'
        c_dir = '/home/%s/.config/pwmgr/%s' % (os.getlogin(), keyfile_name)

        if (confirm):
            if (os.path.isfile(c_dir)):
                print_block(1)
                confirm_txt = "File '%s' already exists in %s. Overwrite file? (Y/n) " % (keyfile_name, '/'.join(c_dir.split('/')[:-1]))
                r = prompt_yes_no(confirm_txt)
            
                if (not r):
                    print_block(1)
                    sys.exit(0)

        if (debug):
            print_block(1)
            msg = 'Creating keyfile: %s%s%s' % (color, c_dir, rst)
            print(text_debug(msg))

        cmd = "dd if=/dev/urandom of='%s' bs='%s' count=1 iflag=fullblock" % (c_dir, length)

    else:

        if (os.path.isdir(file_path)):
            print(text_error('Need to provide filename of keyfile in path'))
            sys.exit(1)
        elif (len(file_path.split('/')) == 1 or file_path[:2] == './'): 
            # Generate keyfile in current working directory as 
            # user just provided name of key file
            
            keyfile_name = ''

            if (len(file_path.split('/')) == 1):
                keyfile_name = file_path
            else:
                keyfile_name = file_path[2:]

            path = '%s/%s' % (os.getcwd(), keyfile_name)

            if (debug):
                print_block(1)
                msg = 'Creating keyfile: %s%s%s' % (color, path, rst)
                print(text_debug(msg))

            cmd = "dd if=/dev/urandom of='%s' bs='%s' count=1 iflag=fullblock" % (path, length)
        else:

            fn = file_path.split('/')[-1]
            f_path = '/'.join(file_path.split('/')[:-1])
            path = '%s/%s' % (f_path, fn)
            cmd = "dd if=/dev/urandom of='%s' bs='%s' count=1 iflag=fullblock" % (path, length)

            if (confirm):
                if (os.path.isfile(file_path) and fn != ''):
                    print_block(1)
                    confirm_txt = "File '%s' already exists in %s. Overwrite file? (Y/n) " % (fn, file_path)
                    r = prompt_yes_no(confirm_txt)

                    if (not r):
                        print_block(1)
                        sys.exit(0)

            elif (os.path.isdir(f_path) and fn != ''):
                pass

            else:
                err_msg = 'Specified path %s is not valid' % file_path
                print(text_error(err_msg))
                sys.exit(1)

            if (debug):
                print_block(1)
                msg = 'Creating keyfile: %s%s%s' % (color, path, rst)
                print(text_debug(msg))

    #print(cmd)

    run_cmd(cmd)

    print_block(1)
    msg = color_symbol_info() + ' Key file creation successful' 
    print(msg)


def use_keyfile(keyfile_path=''):

    #TODO-2: Validate whether keyfile_path is absolute path to key file

    global enc_db_handler, config, config_file, db_file_path 

    master_key = enc_db_handler.get_key()

    pw = ''

    kf = config.get('keyfile_path')

    value1 = ''
    color = color_b('yellow')
    rst = color_reset()

    print_block(1)

    while (True):

        key = ''

        value1 = getpass(color_symbol_info() + color + " Enter current master password: " + rst)
        value1 = value1.strip()

        if (value1 == ""):
            print(text_error("Field cannot be blank"))
            continue

        if (kf != ''):
            key = enc_db_handler.generate_new_key(value1, False, False, kf)
        else:
            key = enc_db_handler.generate_new_key(value1, False, False)
            
        if (key != master_key):
            print(text_error("Master password is incorrect, try again"))
            continue
        else:
            pw = value1
            break

    try:
        enc_db_handler.use_keyfile(pw, keyfile_path)
    except (KeyFileInvalidException):
        print(text_error("Key file is not valid. Need to have a min size of 2048 bits"))
        print(text_debug("Use -gk to generate a new key file"))
        sys.exit(0)

    config.update({'keyfile_path':keyfile_path})
    write_config(config, config_file)
    enc_db_handler.write_encrypted_database(db_file_path)

    if (keyring_set(enc_db_handler.get_key()) == False):
        print(text_error("use_keyfile(): Unable to store password in keyring"))
        sys.exit(1)


def list_keyfile(brief=True):

    global config

    kf = config.get('keyfile_path')

    print_block(1)

    if (kf == ''):
        print(text_debug('No keyfile is currently being used'))
        print_block(1)

    elif (not check_files([kf])):
        msg = "Keyfile listed in config '%s' is not found" % kf
        print(text_error(msg))
        print_block(1)

    else:
        c_value = color_b('green')
        c_rst = color_reset()

        msg = 'Current keyfile: %s%s%s' % (c_value, kf, c_rst)

        print(text_debug(msg))
        print_block(1)

        kf_data = ''

        with open(kf, 'rb') as fh:
            kf_data = fh.read()
        
        finger_print = base64.urlsafe_b64encode(kf_data).decode('utf-8')
        
        if (brief):
            msg = 'Keyfile fingerprint (base64 encoded, brief): %s%s%s' % \
                    (c_value, finger_print[-50:], c_rst)

            print(text_debug(msg))
        else:
            msg = 'Keyfile fingerprint (base64 encoded, full): %s%s%s' % \
                    (c_value, finger_print, c_rst)

            print(text_debug(msg))

        print_block(1)


def remove_keyfile():

    global enc_db_handler, config, config_file, db_file_path 

    kf = config.get('keyfile_path')

    color = color_b('yellow')
    rst = color_reset()


    if (kf == ''):
        print(text_error('No keyfile found in config'))
        sys.exit(1)

    master_key = enc_db_handler.get_key()
    pw  = ''

    print_block(1)

    while (True):

        key = ''

        value1 = getpass(color_symbol_info() + color + " Enter current master password: " + rst)
        value1 = value1.strip()

        if (value1 == ""):
            print(text_error("Field cannot be blank"))
            continue

        key = enc_db_handler.generate_new_key(value1, False, False, kf)

        if (key != master_key):
            print(text_error("Master password is incorrect, try again"))
            continue
        else:
            pw = value1
            print_block(1)
            break

    enc_db_handler.remove_keyfile(pw)

    config.update({'keyfile_path':''})
    write_config(config, config_file)

    enc_db_handler.write_encrypted_database(db_file_path)

    if (keyring_set(enc_db_handler.get_key()) == False):
        print(text_error("use_keyfile(): Unable to store password in keyring"))
        sys.exit(1)


def update_progress_bar_classic(index=1,index_range=10, left_indent=10, right_indent=5):

    """
    Classic progress bar 

    Args:    1) This represents the amount completed out of the total amount
             2) This represents the total amount
             3) Amount of padding on the left
             4) Amount of padding on the right

    Returns: None
    """

    #TODO: Fix the transition color when it reaches 50%,
    #      should be one digit at a time

    color = color_pair('white_blue')

    bar_length = 20

    total_text = list(' ' * bar_length)

    center = int(len(total_text)/2)

    percentage_remaining = int((index/index_range) * 100)
    percentage_remaining_str = '%3d' % percentage_remaining

    if (index >= index_range-2):
        progress_text = ' '
        total_text[center-2] = '1'
        total_text[center-1] = '0'
        total_text[center] = '0'
        total_text[center+1] = '%'
        remaining_text = ''.join(total_text[:])

        new_text = color_reset() + ' '*left_indent + color + color_b('white') + \
                '[ ' + remaining_text + ' ]' + color_reset() + ' ' *right_indent
    else:

        total_text[center-2] = percentage_remaining_str[0]
        total_text[center-1] = percentage_remaining_str[1]
        total_text[center] = percentage_remaining_str[2]
        total_text[center+1] = '%'

        ratio = float(index/index_range * 1.0)
        progress_amount = int(bar_length * ratio)

        progress_text = ''.join(total_text[:progress_amount])
        remaining_text = ''.join(total_text[progress_amount:])

        if (progress_amount >= (center)):
            new_text = color_reset() + ' '*left_indent + color + color_b('white') + \
                    '[ ' + color_b('white') + progress_text + color_bg('white') + remaining_text + \
                    color_b('white') + ' ]' + color_reset() + ' '*right_indent
        else:
            new_text = color_reset() + ' '*left_indent + color + color_b('white') + \
                    '[ ' + color_b('blue') + progress_text + color_bg('white') + remaining_text + \
                    color_b('white') + ' ]' + color_reset() + ' '*right_indent

    sys.stdout.write('\r')
    sys.stdout.write("%s" % new_text)
    sys.stdout.flush()


#===========================================================================
#                         Password Migration Options                       #
#===========================================================================

def import_from_csv(file_name):

    """
    Imports from csv formatted file into database
    """

    global enc_db_handler, db_file_path

    fh = open(file_name)

    data_list = fh.read().splitlines()

    processed_data = csv.reader(data_list, quotechar='"', delimiter=',', \
            quoting=csv.QUOTE_ALL, skipinitialspace=True)


    csv_list = []

    for item in processed_data:
        csv_list.append(item)

    # Fault checking (minimal)

    r = csv_list[0]

    if (len(r) == 2 or len(r) == 3 or len(r) == 4 or len(r) == 5 or \
            len(r) == 10 or len(r) == 14):

        if (len(r) == 2):
            # Discarding header

            if (r[0].strip() in ['site', 'website', 'address'] and \
                    r[1].strip() in ['password', 'pass', 'pwd']):

                csv_list = csv_list[1:]

            enc_db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 3):

            if (r[0].strip() in ['site', 'website', 'address'] and \
                    r[1].strip() in ['password', 'pass', 'pwd'] and \
                    r[2].strip() in ['username', 'user', 'usr']):

                csv_list = csv_list[1:]

            enc_db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 4):

            if (r[0].strip() in ['site', 'website', 'address'] and \
                    r[1].strip() in ['password', 'pass', 'pwd'] and \
                    r[2].strip() in ['username', 'user', 'usr'] and \
                    r[3].strip() in ['email', 'mail']):

                csv_list = csv_list[1:]

            enc_db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 5):

            if (r[0].strip() in ['site', 'website', 'address'] and \
                    r[1].strip() in ['password', 'pass', 'pwd'] and \
                    r[2].strip() in ['username', 'user', 'usr'] and \
                    r[3].strip() in ['email', 'mail'] and \
                    r[4].strip() in ['notes', 'comment', 'remark']):

                csv_list = csv_list[1:]

            enc_db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 10):

            if (','.join(r) ==
                    'site,pass,last_modified,email,username,group,remark,two_factor,recovery_email,phone_number'):

                csv_list = csv_list[1:]

            enc_db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 14):

            header = 'site,pass,last_modified,email,username,group,remark,two_factor,recovery_email,' + \
                    'phone_number,pw_age,pw_reuse,pw_complexity,security_rating'
            
            if (','.join(r) == header):

                csv_list = csv_list[1:]

            enc_db_handler.convert_csvlist_to_record(csv_list)

        else:

            text_error("Unable to import database from csv file due to unsupported format")
            print_block(1)
            sys.exit(1)

        enc_db_handler.write_encrypted_database(db_file_path)

        print_block(1)
        print(text_debug('%s entries have been imported to database' % len(csv_list)))
        print_block(1)
    else:
        print_block(1)
        print(text_error('Incorrect csv format detected '))
        print(text_debug('Two formats are accepted. Read \'import csv\' section'))
        print_block(1)
        sys.exit(1)


def export_to_csv(file_name, brief=False):

    """
    Exports csv formatted database to the specified file
    """

    global enc_db_handler

    exit_if_database_is_empty()

    if (brief):
        enc_db_handler.export_csv_brief(file_name)
    else:
        enc_db_handler.export_csv(file_name)

    print_block(1)
    print(text_debug('Exported database to file: %s' % file_name))
    print_block(1)


def search_font_name(keyword=''):

    global field_color_fg

    cmd = "fc-list | grep -i '%s' | cut -d':' -f2" % (keyword)

    stdout,stderr,rc = run_cmd(cmd)

    if (stdout == ''):
        print(text_error('Nothing found'))
    else:

        color = color_b('yellow')
        rst   = color_reset()

        font_l = list(set(remove_whitespace_from_list(stdout.split('\n'))))

        font_l.sort()

        count = 1

        print_block(1)

        print(text_debug('The following fonts are installed in system: \n'))

        for f in font_l:

            print("      %s%s)%s %s" % (color, count, rst, f))
            count += 1

        print_block(1)


def read_csv_pwmgr(filename=''):

    """
    Parses a csv formatted file & loads all
        information into database

    Args:    The name of the file

    Returns: True if the operation succeeds
             False if the operation fails
    """

    if (filename == ''):
        return 

    data = []

    try:

        fh = open(filename, 'r')

        r = csv.reader(fh)

        for row in r:
            data.append(row)

    except IOError as e:
        print(e)

    fh.close()

    if (len(data) != 0 and test_if_single_quoted(data[0])):
        data = remove_single_quote_from_list(data)

    return data


def test_if_single_quoted(record=[]):

    item = record[0]

    if (item.startswith("'") and item.endswith("'")):
        return True

    return False


def remove_single_quote_from_list(f=[]):

    _f = []

    for row in f:

        _row = []

        for item in row:

            if (item.startswith("'") and item.endswith("'")):
                _row.append(item[1:-1])
            else:
                _row.append(item)

        _f.append(_row)

    return _f


def write_csv_pwmgr(data=[], filename=''):

    if (len(data) == 0 or filename == ''):
        return

    try:

        with open(filename, 'w+') as fh:
            cw = csv.writer(fh, delimiter=',', quoting=csv.QUOTE_ALL,
                    quotechar='"')

            for r in data:
                cw.writerow(r)

    except IOError as e:
        print(e)


def main():

    global theme, config

    try:
        parse_args()
    except KeyboardInterrupt:
        cursor_show()
        sys.exit(1)


if __name__ == "__main__":
    main()

