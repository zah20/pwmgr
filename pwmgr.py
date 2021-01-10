#!/usr/bin/python3

import password_utils
from database import Record, ManageRecord
from database import IncorrectPasswordException, DatabaseFileNotFoundException,\
        NoKeyFoundException, DatabaseNotEncryptedException, DatabaseEmptyException
from colorama import Fore, Back, Style
import sys, os, platform, subprocess
import keyring, pyperclip, cursor
from getpass import getpass
from getch import getch
from time import sleep


"""
Password Manager 

Copyright © 2021 Zubair Hossain

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


global __title__, __author__, __email__, __version__, __last_updated__, \
        __license__

__title__        =  'Password Manager'
__author__       =  'Zubair Hossain'
__email__        =  'zhossain@protonmail.com'
__version__      =  '1.0.0'
__last_updated__ =  '10/1/2021'
__license__      =  'GPLv3'


global database_handler, app_name, filename, system_username, master_pwd, \
        password_in_keyring, term_length_fixed

database_handler = None
app_name = 'pwmgr'
filename = 'data.bin'
system_username = ''
master_pwd = ''
password_in_keyring=False
term_length_fixed = 75



#===========================================================================
#                Database polling & arugment parsing functions             #
#===========================================================================


def parse_args():

    """
    Parses commandline arguments & executes the desired functions

    """

    global term_length_fixed

    argument_length = len(sys.argv)

    if (argument_length == 1):
        print_help()
        sys.exit(0)
    else:
        term_length_fixed = os.get_terminal_size()[0]

        if (argument_length == 2):
            if (l(sys.argv[1]) == 'add' or l(sys.argv[1]) == '--add' or l(sys.argv[1]) == '-a'):
                check_database()
                add()
                exit(0)
            elif (l(sys.argv[1]) == 'show' or l(sys.argv[1]) == '--show' or l(sys.argv[1]) == '-o'):
                check_database()
                show_summary()
                exit(0)
            elif (l(sys.argv[1]) == 'help' or l(sys.argv[1]) == '--help' or l(sys.argv[1]) == '-h'):
                print_help()
                sys.exit(0)
            else:
                print(text_color_error("The selected option doesn't exist"))
                sys.exit(1)
        elif (argument_length == 3):
            if (l(sys.argv[1]) == 'show' or l(sys.argv[1]) == '--show' or l(sys.argv[1]) == '-o'):

                result = convert_str_to_int(sys.argv[2])

                if (result[0] == False):
                    print(text_color_error("Requires an integer value"))
                    sys.exit(1)

                if (type(result[1]) == list):
                    index_list = result[1]
                    new_list = [i-1 for i in index_list]

                    check_database()
                    
                    result = database_handler.validate_index(new_list)

                    if (result):
                        print_block(1)
                        print(color_menu_bars())
                        print_block(1)
                        show_index_multiple(new_list)
                        sys.exit(0)
                    else:
                        print(text_color_error("Selected indexes are not within range"))
                        sys.exit(1)
                elif (type(result[1]) == int):

                    check_database()

                    if (database_handler.validate_index((result[1]-1))):
                        print_block(1)
                        print(color_menu_bars())
                        print_block(1)
                        show_index((result[1]-1))
                        sys.exit(0)
                    else:
                        print(text_color_error("Selected index is not within range"))
                        sys.exit(1)
                else:
                    print(text_color_error("Requires an integer or comma separated integer values"))
                    sys.exit(1)
            elif (l(sys.argv[1]) == 'edit' or l(sys.argv[1]) == '--edit' or l(sys.argv[1]) == '-e'):

                index = None

                result = convert_str_to_int(sys.argv[2])

                if (result[0]):
                    if (type(result[1]) == list):
                        print(text_color_error("Editing multiple values simultaneously is not supported at the moment"))
                        sys.exit(1)
                    else:
                        index = result[1]
                else:
                    print(text_color_error("Requires an integer value"))
                    sys.exit(1)

                check_database()

                if (database_handler.validate_index((index-1))):
                    edit_index((index-1))
                    sys.exit(0)
                else:
                    print(text_color_error("Selected index is not within range"))
                    sys.exit(1)
            elif (l(sys.argv[1]) == 'search' or l(sys.argv[1]) == '--search' or l(sys.argv[1]) == '-s'):
                check_database()
                keyword = (sys.argv[2]).strip()
                search(keyword)
                sys.exit(0)
            elif (l(sys.argv[1]) == 'copy' or l(sys.argv[1]) == '--copy' or l(sys.argv[1]) == '-c'):

                index = None

                result = convert_str_to_int(sys.argv[2])

                if (result[0] and type(result[1]) == int):
                    index = result[1]
                else:
                    print(text_color_error("Requires an integer value"))
                    sys.exit(1)

                check_database()

                if (database_handler.validate_index((index-1))):
                    copy_to_clipboard_index((index-1))
                    sys.exit(0)
                else:
                    print(text_color_error("Selected index is not within range"))
                    sys.exit(1)
            elif (l(sys.argv[1]) == 'rm' or l(sys.argv[1]) == '--rm' or l(sys.argv[1]) == '-d'):

                index = None

                result = convert_str_to_int(sys.argv[2])

                if (result[0]):
                    index = result[1]
                else:
                    print(text_color_error("Requires an integer value"))
                    sys.exit(1)

                check_database()

                if (type(index) == int):
                    if (database_handler.validate_index((index-1))):
                        delete_index((index-1))
                        sys.exit(0)
                    else:
                        print(text_color_error("Selected index is not within range"))
                        exit(1)
                elif (type(index) == list):
                    new_list = [i-1 for i in index]
                    
                    for i in new_list:
                        if (database_handler.validate_index(i) == False):
                            print(text_color_error("Selected index %s is not within range" % (i+1))) 
                            exit(1)

                    delete_index(new_list)
                    sys.exit(0)
                else:
                    print(text_color_error("Requires an integer value or a comma separated list"))
                    exit(1)
            elif (l(sys.argv[1]) == 'key' or l(sys.argv[1]) == '--key'):

                if (l(sys.argv[2]) == 'show'):
                    check_database()
                    key_show()
                    exit(0)
                elif (l(sys.argv[2]) == 'reset'):
                    check_database()
                    key_reset()
                    exit(0)
                else:
                    print(text_color_error("The selected option doesn't exist"))
                    sys.exit(1)
            elif (l(sys.argv[1]) == 'keyring' or l(sys.argv[1]) == '--keyring'):

                if (l(sys.argv[2]) == 'reset'):
                    keyring_reset()
                    exit(0)
                else:
                    print(text_color_error("The selected option doesn't exist"))
                    sys.exit(1)
            elif (l(sys.argv[1]) == 'import' or l(sys.argv[1]) == '--import'):
                if (l(sys.argv[2]) == 'pass'):
                    check_database()
                    import_from_pass()
                    exit(0)
                else:
                    print(text_color_error("The selected option doesn't exist"))
                    sys.exit(1)
            elif (l(sys.argv[1]) == 'sync' or l(sys.argv[1]) == '--sync' or l(sys.argv[1]) == '-y'):
                
                if (l(sys.argv[2]) == 'enable'):
                    check_database()
                    sync_enable()
                    exit(0)
                elif (l(sys.argv[2]) == 'disable'):
                    check_database()
                    sync_disable()
                    exit(0)
                elif (l(sys.argv[2]) == 'now'):
                    check_database()
                    sync_now()
                    exit(0)
                else:
                    print(text_color_error("The selected option doesn't exist"))
                    exit(1)
            else:
                print(text_color_error("The selected option doesn't exist"))
                sys.exit(1)
        elif (argument_length == 4):
            
            if (l(sys.argv[1]) == 'search' or l(sys.argv[1]) == '--search' or l(sys.argv[1]) == '-s'):

                if (l(sys.argv[2]) == 'group'):
                    check_database()
                    keyword = (sys.argv[3]).strip()
                    search_extended(keyword, 'group')
                    exit(0)
                elif (l(sys.argv[2]) == 'site'):
                    check_database()
                    keyword = (sys.argv[3]).strip()
                    search_extended(keyword, 'site')
                    exit(0)
                elif (l(sys.argv[2]) == 'email'):
                    check_database()
                    keyword = (sys.argv[3]).strip()
                    search_extended(keyword, 'email')
                    exit(0)
                elif (l(sys.argv[2]) == 'username'):
                    check_database()
                    keyword = (sys.argv[3]).strip()
                    search_extended(keyword, 'username')
                    exit(0)
                elif (l(sys.argv[2]) == 'all'):
                    check_database()
                    keyword = (sys.argv[3]).strip()
                    search(keyword)
                    exit(0)
                else:
                    print(text_color_error("The selected option doesn't exist"))
                    sys.exit(1)
            elif (l(sys.argv[1]) == 'sync' or l(sys.argv[1]) == '--sync' or l(sys.argv[1]) == '-y'):

                if (l(sys.argv[2]) == 'set'):
                    if (l(sys.argv[3]) in ['daily', 'weekly', 'monthly']):
                        check_database()
                        sync_set(l(sys.argv[3]))
                        exit(0)
                    else:
                        print(text_color_error("The selected option doesn't exist"))
                        sys.exit(1)
                else:
                    print(text_color_error("The selected option doesn't exist"))
                    sys.exit(1)
            else:
                print(text_color_error("The selected option doesn't exist"))
                sys.exit(1)
        else:
            print(text_color_error("The selected option doesn't exist"))
            sys.exit(1)


def check_database():
    
    global filename, app_name, database_handler, system_username, master_pwd, password_in_keyring

    custom_refresh

    system_username = get_username()
    database_handler = ManageRecord()

    if (os.path.isfile(filename) == False):
        # (No database found)

        print_block(2)

        if (prompt_yes_no("No database exists. Do you want to create a new one? (Y/n): ")):
            custom_refresh()
            master_pwd = prompt_password()
            database_handler.generate_new_key(master_pwd)
            database_handler.write_encrypted_database()
            
            try:
                keyring.set_password(app_name, system_username, master_pwd)
            except (Exception):
                print(text_color_error("check_database(): error#01 Unable to store password in keyring"))
                exit(0)

        else:
            print_block(1)
            print(text_debug("Nothing to do, quitting..."))
            print_block(1)
            print(color_menu_bars())
            print_block(1)
            sys.exit(0)
    else:
        # (Previous database exists)
        # We search for password in keyring, if nothing found we prompt user
        #       for master password & attempt to decrypt it
        # 

        master_pwd = keyring.get_password(app_name, system_username)

        if (master_pwd == None):
            password_in_keyring = False
            print(color_menu_informational("Database found but password store is empty", 0))
            print_block(2)
            master_pwd = prompt_password_once()

        try:
            result = database_handler.load_database(filename, master_pwd)
                
            if (result): # Database decryption succeeded

                if (password_in_keyring == False):
                    try:
                        keyring.set_password(app_name, system_username, master_pwd)
                    except (Exception):
                        print(text_color_error("Unable to store password in keyring"))
        except (IncorrectPasswordException):
                print(text_color_error("Incorrect password! Decryption failed."))
                sys.exit(1)


def key_reset():
    """
    Change the current password that is used for database encryption 

    Note: Needs to be called after database has been loaded in memory using
          the check_database() function
        
    """

    global app_name, database_handler
    custom_refresh()

    new_pwd = prompt_password()
    
    database_handler.change_password(new_pwd)

    system_username = get_username()
    keyring.set_password(app_name, system_username, new_pwd)

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

    global database_handler

    key = database_handler.get_key()
    print(text_debug('Current Key: %s' % key))
    print_block(1)
    print(color_menu_bars())
    print_block(1)


def keyring_reset():
    """
    Remove the current password from the keyring for the current user

    """

    global app_name

    system_username = get_username()
    print_block(1)
    print(color_menu_bars())

    try:
        keyring.delete_password(app_name, system_username)
        print_block(1)
        print(text_debug('Password has been deleted from keyring'))
        print_block(1)
    except keyring.errors.PasswordDeleteError:
        print(text_color_error('No password found in keyring'))

    print(color_menu_bars())
    print_block(1)


def add():
    """
    Adds a record to database
    """
    global database_handler
    
    custom_refresh(3,2)

    site = prompt(" Website name: ")

    pwd = ''

    if (prompt_yes_no("Auto generate new password? (Y/n): ")):
        pwd = menu_generate_password()
    else:
        pwd = prompt_password()

    r = Record(site, pwd)

    print_block(2)

    choice = prompt_yes_no("Do you want to add additional info? (Y/n): ")

    if (choice):
        custom_refresh(3,2)
        print(color_menu_informational("The information below is Optional." + \
                " (Press Enter if you want to skip)   "))

        print_block(3)
        usr = prompt_blank(" Username: ")
        email = prompt_blank(" Email: ")
        group = prompt_blank(" Group: ")
        remark = prompt_blank(" Remark/Notes: ")
        recovery_email = prompt_blank(" Recovery email: ")
        phone = prompt_blank(" Phone number: ")
        two_factor = prompt_yes_no(" Two Factor enabled? (y/N): ", False)

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

        if (database_handler.check_duplicate_entry(r)):
            if (prompt_yes_no(" Duplicate entry found. Do you want to add anyway?  (y/N): ", False)):
                database_handler.add(r)
                print_block(2)
                print(text_debug(" Record has been added successfully!"))
                print_block(2)
                print(color_menu_bars())
            else:
                print_block(2)
                print(text_debug(" Record has been discarded"))
                print_block(2)
                print(color_menu_bars())
        else:
            database_handler.add(r)
            print_block(2)
            print(text_debug(" Record has been added successfully!"))
            print_block(2)
            print(color_menu_bars())
    else:
        database_handler.add(r)
        custom_refresh(3,2)
        print(text_debug(" Record has been added successfully!"))
        print_block(2)
        print(color_menu_bars())

    database_handler.write_encrypted_database()


def show_summary(input_list=None):
    """
    Display a summary of the entries in the database

    """
    global database_handler

    length = database_handler.get_number_of_records()

    data_summary = []

    if (input_list == None):

        if (length == 0):
            print(text_debug("No records found"))
            print_block(1)
            print(color_menu_bars())
            print_block(1)
            return

        for i in range(length):
            r = database_handler.get_index(i)
            data = [(i+1), r.get_website(), r.get_email(), r.get_username(),  r.get_group()]
            data_summary.append(data)
    else:
        data_summary = []

        for i in range(len(input_list)):
            r = database_handler.get_index(input_list[i])
            data = [(input_list[i]+1), r.get_website(), r.get_email(), r.get_username(), r.get_group()]
            data_summary.append(data)
    
    header = ['Site', 'Username', 'Email', 'Group']

    white_space = ' '*3
    white_space2 = ' '*5
    white_space3 = ' '*9
    white_space4 = ' '*4

    # This is for partitioning space & printing out header according to the
    # ratio specified by the second index
    new_header = [['Site', 3], ['Email',2], ['Username',1.5], ['Group', 0.5]]
    
    custom_refresh(print_menu_bars=False)
    print(color_menu_column_header(new_header))
    print_block(2)
    
    for item in data_summary:
        formatted_data = color_menu_column_data(item)
        print(formatted_data)

    print_block(1)
    print(color_menu_bars())
    print_block(1)


def show_index(index=None):

    """
    Display the record at the specified index from database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global database_handler

    if (index == None):
        return

    r = database_handler.get_index(index)

    header = ['Website', 'Password', 'Username', 'Email', 'Group', 'Remark', \
            'Two-factor', 'Recovery-email', 'Phone-number', 'Last-modified']

    data = [r.get_website(), r.get_password(), r.get_username(), \
            r.get_email(), r.get_group(), r.get_remark(), r.get_two_factor(), \
            r.get_recovery_email(), r.get_phone_number(),
            r.get_last_modified()[-1]]

    white_space = ' '*3

    print_block(1)

    for i in range(len(header)):
        category_name = '  %s:' % (header[i])
        category_name = "{0:<20}".format(category_name)
        category_name = text_highlight(category_name)

        if (data[i] == "''"):
            print(category_name)
        else:
            print('%s %s' % (category_name, data[i]))

    print_block(1)
    print(color_menu_bars())
    print_block(1)
    

def show_index_multiple(index_list=None):

    """
    Display the record at the specified index from database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    for i in index_list:
        show_index(i)


def delete_index(index=None):

    """
    Deletes record at the specified index, supports list of indexes
    """

    global database_handler

    if (index == None):
        return
    elif (type(index) == int):
        database_handler.remove_index(index)
        print_block(1)
        print(text_debug(" Record has been deleted."))
        print_block(1)
    elif (type(index) == list):

        show_summary(index)
        print_block(1)

        choice = prompt_yes_no(" The records above will be deleted, continue? (y/N): ", False)

        print_block(2)

        if (choice):
            database_handler.remove_index(index) # This function is aware of lists 
            custom_refresh()
            print(text_debug(" Specified records have been deleted."))
            print_block(1)
            print(color_menu_bars())
            print_block(1)
        else:
            print(text_debug(" No changes have been made to database"))
            print_block(1)


def copy_to_clipboard_index(index=None):

    """
    Copy the specified index from database to clipboard

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global database_handler

    if (index == None):
        return

    r = database_handler.get_index(index)
    pwd = r.get_password()

    pyperclip.copy(pwd)

    
def edit_index(index=None):

    """
    Edit a record at the specified index & update it to database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global database_handler

    if (index == None):
        return

    r = database_handler.get_index(index)

    header = ['Website', 'Password', 'Username', 'Email', 'Group', 'Remark', \
            'Two-factor', 'Recovery-email', 'Phone-number']

    data = [r.get_website(), r.get_password(), r.get_username(), \
            r.get_email(), r.get_group(), r.get_remark(), r.get_two_factor(), \
            r.get_recovery_email(), r.get_phone_number()]

    white_space = ' '*3

    custom_refresh(print_menu_bars=False)
    print(color_menu_informational("    Press (e) to edit | (Enter) to skip | (q) Quit without saving" + ' '*6))
    print_block(3)

    data_changed = False

    for i in range(len(header)):
    
        category_name = '  %s:' % (header[i])
        category_name = "{0:<20}".format(category_name)
        category_name = text_highlight(category_name)
        
        if (data[i] == "''"):
            print(category_name)
        else:
            print('%s %s' % (category_name, data[i]))
        
        while (True):
            char = getch()
        
            if (char == 'e' or char == 'E'):
                if (i == 6):
                    print_block(1)
                    data[i] = prompt_yes_no("Enable Two Factor? (y/N): ", False)
                    data_changed = True
                    print_block(1)
                    break
                else:
                    print_block(1)
                    data[i] = prompt_blank("New value: ")
                    data_changed = True
                    print_block(1)
                    break
            elif (char == '\n'):
                break
            elif (char == 'q' or char == 'Q'):
                print_block(1)
                sys.exit(1)

    if (data_changed):
        r.set_website(data[0])
        r.set_password(data[1])
        r.set_username(data[2])
        r.set_email(data[3])
        r.set_group(data[4])
        r.set_remark(data[5])
        r.set_two_factor(data[6])
        r.set_recovery_email(data[7])
        r.set_phone_number(data[8])
        
        database_handler.update_index(r, index)

    print_block(2)
    print(color_menu_bars())
    print_block(1)
    

def search(keyword=None):

    global database_handler

    if (keyword == None):
        return

    result = database_handler.search_all(keyword)
    
    if (len(result) == 0):
        print_block(1)
        print(text_debug('Nothing found'))
        print_block(1)
    else:
        show_summary(result)


def search_extended(keyword=None, category=''):

    global database_handler

    if (keyword == None or category == ''):
        return

    result = []

    if (category == 'group'):
        result = database_handler.search_group(keyword)
    elif (category == 'site'):
        result = database_handler.search_website(keyword)
    elif (category == 'email'):
        result = database_handler.search_email(keyword)
    elif (category == 'username'):
        result = database_handler.search_username(keyword)

    if (len(result) == 0):
        print_block(1)
        print(text_debug('Nothing found'))
        print_block(1)
    else:
        show_summary(result)



#===========================================================================
#                      User input parsing functions                        #
#===========================================================================


def prompt(question=""):

    value = ""

    while (value == ""):
        value = input(color_symbol_info() + text_highlight(question))

        if (value == ""):
            print(text_color_error(" Field cannot be blank"))

    return value.lower()


def prompt_blank(question=""):

    value = input(color_symbol_info() + ' ' +  text_highlight(question))
    return value


def prompt_int(question="", default=0, min_value=0, max_value=30):

    while (True):
        try:
            tmp_value = input(color_symbol_info() + text_highlight(question))

            if (tmp_value == ''):
                return default

            tmp_value = int(tmp_value)
        except (ValueError):
            print(text_color_error(' Please type an integer'))
            continue

        if (tmp_value < min_value):
            print(text_color_error(' Need minimum length of %d characters' % min_value))
        elif (tmp_value > max_value):
            print(text_color_error(' Maximum length limit of %d characters' % min_value))
        else:
            return tmp_value
        

def prompt_password():
    """
    Used during password generation, prompts for password twice
        in case user mistypes
    """

    value1 = ""
    value2 = ""

    while True:
        value1 = getpass(color_symbol_info() + text_highlight(" Enter new password: "))
        value1 = value1.strip()

        if (value1 == ""):
            print(text_color_error(" Field cannot be blank"))
            continue
        else:
            break

    while True:    
        value2 = getpass(color_symbol_info() + text_highlight(" Retype password: "))
        value2 = value2.strip()
    
        if (value2 == ""):
            print(color_symbol_info() + text_highlight(" Field cannot be blank"))
            continue
        elif (value2 == value1):
            return value1
        else:
            print(text_color_error(" Password don't match, try again"))


def prompt_password_once():

    value = ""

    while True:
        value = getpass(color_symbol_info() + text_highlight(" Enter password: "))
        value = value.strip()

        if (value == ""):
            print(text_color_error(" Field cannot be blank"))
            continue
        else:
            break

    return value


def prompt_yes_no(question="", default=True):
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
            return default
        else:
            print(text_color_error(" Invalid answer.  Please answer 'yes/no'"))


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
            print(text_color_error(" Invalid answer. Please answer 'yes/no' or leave blank"))



#===========================================================================
#                           Printing functions                             #
#===========================================================================


def text_color_error(text=''):
    text = '\n  ' + color_symbol_error() + Fore.LIGHTRED_EX + Back.BLACK + \
            Style.BRIGHT + ' ' + text + Style.RESET_ALL + '\n'     

    return text


def text_color_cyan(text=''):
    text = Fore.BLACK + Back.CYAN + Style.BRIGHT + text + Style.RESET_ALL
    return text


def text_highlight(text=''):
    text = Style.BRIGHT + text + Style.RESET_ALL
    return text


def text_debug(text=''):
    text = (color_symbol_debug() + " " + text_highlight(text))
    return text


def color_menu_bars(text=' '):
    global term_length_fixed

    text = text * term_length_fixed
    text =  Style.NORMAL + Back.CYAN + Fore.BLACK + text + Style.RESET_ALL
    return text


def color_menu_text(text=' '):
    global term_length_fixed

    text_size = len(text)
    remaining_length = int(term_length_fixed - text_size)

    left  = 0
    right = 0

    if (remaining_length%2 == 0): # Even
        left  = int(remaining_length/2)
        right = int(remaining_length/2)
    else:
        left = int(remaining_length/2)
        right = remaining_length - left


    text =  Style.BRIGHT + Back.CYAN + ' '*left + text + ' '*right + Style.RESET_ALL

    return text


def color_menu_informational(text='', left_indent=0):

    indent = ''

    for i in range(left_indent):
        indent = '%s ' % indent

    text =  indent + color_symbol_debug_info() + Style.NORMAL + Back.YELLOW + Fore.BLACK + ' ' + text + Style.RESET_ALL
    return text


def color_menu_column_header(header_list=[], left_indent=7):
    global term_length_fixed

    text  = ' '*(term_length_fixed-left_indent)

    text_list = list(text)

    if (len(header_list) == 0):
        text = Style.BRIGHT + Back.YELLOW + Fore.BLACK + text + Style.RESET_ALL
        return text

    ratio_total = 0

    header_text = ''

    for i in range(len(header_list)):
        ratio_total = ratio_total + header_list[i][1]

    total_length = len(text_list) - left_indent

    master_list = [] 

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

    text = Style.BRIGHT + Back.YELLOW + Fore.BLACK + ' ' * left_indent + ''.join(text_list) + Style.RESET_ALL
        
    return text


def color_menu_column_data(data_list=[], ratio=[3,2,2,1]):
    global term_length_fixed
    
    # Format (data_list)  = '#', 'Site', 'Username', 'Email', 'Group'

    # width of index is fixed at 6 chars, & ratio parameter is used to 
    # allocate space between the remaining fields site .. group

    number_indent = 7

    text  = ' '*(term_length_fixed - number_indent)

    text_list = list(text)

    if (len(data_list) == 0):
        text = ' '*term_length_fixed + Style.RESET_ALL
        return text

    ratio_total = 0

    for i in ratio:
        ratio_total = ratio_total + i


    str_list = list(str(data_list[0]))

    while (len(str_list) < (number_indent-2)):
        str_list.insert(0, ' ')

    str_list.append(')')
    str_list.append(' ')

    mark = 0

    for i in range(1,len(data_list)):
        space_partition = int((len(text_list) * ratio[i-1]) / ratio_total)
        char_list = list(data_list[i])
        right_space = space_partition - len(char_list)

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

    text = Style.BRIGHT + ''.join(str_list) + \
            Style.NORMAL + ''.join(text_list) + Style.RESET_ALL
        
    return text



def color_symbol_info():
    text = '  ' + Fore.CYAN + Style.BRIGHT + '[+]' + Style.RESET_ALL
    return text


def color_symbol_error():
    text = Fore.LIGHTRED_EX + Back.BLACK + Style.BRIGHT + '[-]' + Style.RESET_ALL
    return text


def color_symbol_debug(foreground_color=Fore.CYAN,
        background_color=Back.RESET, style=Style.BRIGHT):

    text = '  ' + foreground_color + background_color + style + '[*]' + Style.RESET_ALL
    return text


def color_symbol_debug_info():

    text = '  ' + color_symbol_debug(foreground_color=Fore.BLACK, background_color=Back.YELLOW, style=Style.NORMAL)
    return text


def print_not_implemented():

    print(text_color_error("Feature not implemented yet"))


def print_block(n=3):
    for i in range(n):
        print()


def print_header():

    global __title, __version__, __last_updated__, __email__

    header = \
    """
    ==========================================================
                                                              
                          %s                         
                                                              
                          (version: %s)                      
                                                              
                      %s
                                                              
                      Last Updated:  %s                       
                                                              
    ==========================================================""" \
            % (__title__,__version__,__email__,__last_updated__)

    print(text_highlight(header))


def print_help():

    print_header()

    print(
    """

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

    """)



#===========================================================================
#                           Utility functions                              #
#===========================================================================


def l(value=''):

    """
    Returns lower case version of input string

    """

    if (value != ''):
        return value.lower()


def parse_comma(value=''):
    if (type(value) == str and value != ''):
        if (',' in value):
            data = value.strip().split(',')
            return data
        else:
            return value

    return []


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


def clear_screen():
    """
    Clears screen, command is compatible with different OS
    """

    cmd = ''

    system_name = platform.system().lower()

    if (system_name == 'linux' or system_name == 'darwin' \
            or system_name == 'posix'):
        cmd = 'clear'
    elif (system_name == 'windows'):
        cmd = 'cls'
    else:
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
    # Executes bash commands on local Linux system

    if (cmd != []):
        process = subprocess.Popen(cmd, shell=True, \
                                   stdout=subprocess.PIPE, \
                                   stderr=subprocess.PIPE)

        stdout,stderr = process.communicate()

        stdout = stdout.decode('ascii').strip()
        stderr = stderr.decode('ascii').strip()

        if (verbose == True):
            print(stdout)

        return stdout,stderr



#===========================================================================
#                         Password Migration Options                       #
#===========================================================================


def get_pass_directory():
    username = get_username()
    get_pass_directory = ''

    system_name = platform.system().lower()

    if (system_name == 'linux' or system_name == 'darwin' \
            or system_name == 'posix'):
        get_pass_directory = '/home/%s/.password-store/' % username
    else:
        raise OSNotSupportedError()

    return get_pass_directory
    

def get_file_list(path=''):

    if (path == ''):
        return

    scan = os.scandir(path)

    dir_list  = []
    file_list = []

    for item in scan:
        if (item.is_dir()):
            dir_list.append('%s/' % item.path)
        elif (item.is_file()):
            file_list.append(['',item.name])
        else:
            pass

    while (len(dir_list) != 0):
        new_list = crawl_directory(dir_list[0])
        dir_list.pop(0)
        file_list = file_list + new_list[1]
        dir_list = dir_list + new_list[0]

    for i in range(len(file_list)):
        file_list[i][1] = file_list[i][1][:-4]
    
    return file_list


def crawl_directory(path=''):

    if (path == ''):
        return

    scan = os.scandir(path)

    dir_list  = []
    file_list = []

    group_name = path.split('/')[-2]

    for item in scan:
        if (item.is_dir()):
            dir_list.append(item.path)
        elif (item.is_file()):

            file_list.append([group_name, item.name])
        else:
            pass

    new_list = [dir_list,file_list]

    return new_list


def parse_pass():

    cursor.hide()

    dir_path = get_pass_directory()

    # file_list format: [groupname, file_name]
    file_list = get_file_list(dir_path)

    # We'll return new_list from this function
    # format: [group_name, site_name, password, last_modified]
    new_list = []

    print_block(2)
    print('\t\t       %s' % 'Importing from Pass')
    print_block(1)

    length = len(file_list)
    #length = 10 # Setting to 10 for testing

    cmd = "stat -c '%y'"

    for i in range(length):

        update_progress_bar_classic(i, length,20,10, 'cyan')

        if (file_list[i][0] == ''):
            stdout,stderr = run_cmd('pass show %s' % file_list[i][1])
            stdout2,stderr2 = run_cmd('%s %s%s.gpg' % (cmd, dir_path, file_list[i][1]))
        else:
            stdout,stderr = run_cmd('pass show %s/%s' % (file_list[i][0],file_list[i][1]))
            stdout2,stderr2 = run_cmd('%s %s%s/%s.gpg' % (cmd, dir_path, file_list[i][0], file_list[i][1]))

        if (stdout == ''):
            pass
        else:
            #data_format = [file_list[i][0], file_list[i][1], stdout.split('\n')[0].strip()]
            data_format = [file_list[i][0], file_list[i][1], stdout.split('\n')[0].strip(), stdout2.split('.')[0].strip()]
            new_list.append(data_format)

    for i in range(len(new_list)):
        if ('Generated_Password_for_' in new_list[i][1]):
            new_list[i][1] = new_list[i][1].split('Generated_Password_for_')[1]

    cursor.show()

    #for item in new_list:
    #    print("Group: %s\tSite: %s\tPass: %s" % (item[0],item[1],item[2]))

    return new_list

    
def import_from_pass():

    """
    Imports all relevant information from pass 
    """

    global database_handler
    
    custom_refresh(3,2)

    custom_list = []
    record_list = []

    if (prompt_yes_no("Do you want to import from pass? (Y/n): ")):
        custom_refresh(3,2)
        custom_list = parse_pass()
    else:
        print(text_color_error("Nothing to do, quitting..."))
        sys.exit(1)

    #for item in custom_list:
    #    print("Group: %s\tSite: %s\tPass: %s" % (item[0],item[1],item[2]))

    if (len(custom_list) != 0):
        for i in range(len(custom_list)):
            if (custom_list[i][1] == '' or custom_list[i][2] == ''):
                pass
            else:

                if (custom_list[i][3] != ''):
                    r = Record(custom_list[i][1], custom_list[i][2], custom_list[i][3])
                else:
                    r = Record(custom_list[i][1], custom_list[i][2])
                
                if (custom_list[i][0] != ''):
                    r.set_group(custom_list[i][0])

                    

                record_list.append(r) 

        #for i in record_list:
        #    database_handler.add(i)

        database_handler.add(record_list)

        database_handler.write_encrypted_database()

        custom_refresh(3,1)
        print(text_debug("(%d) Passwords were successfully imported" % (len(record_list))))
    else:
        print(text_color_error('No passwords were found'))

    print_block(1)
    print(color_menu_bars())
    print_block(1)



#===========================================================================#
#                       Custom Commandline Interface                        #
#===========================================================================#


def menu_generate_password():
    """
    Menu that takes care of user password generation & selection process

    Input:   None

    Returns: Password (str)
    """

    pwd = ''

    length = prompt_int(text_highlight(" Enter password length (default - 10): ") , 10, 6, 30)
    
    enable_symbols = prompt_yes_no("Enable symbols in password? (Y/n): ")
    
    cursor.hide()

    while (pwd == ''):
        password_list = password_utils.gen_pass_secure(length, False, True, enable_symbols)
    
        for password in password_list:
    
            custom_refresh(0,0)
            print(color_menu_bars())
            print(color_menu_bars())
            print_block(5)

            print(color_symbol_info() + \
                    text_highlight(" Generated password: "), text_color_cyan(password))
    
            print_block(5)

            menu_text = "  Press (G) Generate password | (S) Select | (Q) Quit  "
    
            print(color_menu_bars())
            print(color_menu_text(menu_text))
            print(color_menu_bars())

            while (True):
                char = getch()
    
                if (char == 'g' or char == 'G'):
                    break
                elif (char == 's' or char == 'S'):
                    pwd = password
                    break
                elif (char == 'q' or char == 'Q'):
                    cursor.show()
                    print_block()
                    sys.exit(1)
                else:
                    pass
    
            if (pwd != ''):
                break

    cursor.show()

    return pwd


def update_progress_bar_classic(index=1,index_range=10, left_indent=10,
        right_indent=5, color_choice='blue'):
   
    """
    Classic progress bar 

    Args:    1) This represents the amount completed out of the total amount
             2) This represents the total amount
             3) Amount of padding on the left
             4) Amount of padding on the right
             5) Color of the progress bar. Options are 'cyan', 'blue'. 
                (Default: 'blue')

    Returns: N/A
    """
    
    color = None

    if (color_choice == 'blue'):
        color = Back.BLUE
    elif (color_choice == 'cyan'):
        color = Back.CYAN
    else:
        color = Back.BLUE

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

            new_text = Style.NORMAL + ' '*left_indent + color + Fore.BLACK + \
                    '[ ' + remaining_text + ' ]' + Style.RESET_ALL + ' ' *right_indent
    else:

        total_text[center-2] = percentage_remaining_str[0]
        total_text[center-1] = percentage_remaining_str[1]
        total_text[center] = percentage_remaining_str[2]
        total_text[center+1] = '%'

        ratio = float(index/index_range * 1.0)
        progress_amount = int(bar_length * ratio)
        remaining_amount = bar_length - progress_amount

        progress_text = ''.join(total_text[:progress_amount])
        remaining_text = ''.join(total_text[progress_amount:])
        
        new_text = Style.NORMAL + ' '*left_indent + color + Fore.BLACK + \
                '[ ' + progress_text + Back.WHITE + remaining_text + ' ]' + \
                Style.RESET_ALL + ' '*right_indent


    sys.stdout.write('\r')
    sys.stdout.write("%s" % new_text)
    sys.stdout.flush()



#===========================================================================#
#                               Custom Exceptions                           #
#===========================================================================#


class OSNotSupportedException(Exception):
    def __init__(self, msg='Only Linux OS is supported at the moment'):
        super(OSNotSupportedException, self).__init__(msg)


def main():
    parse_args()


if __name__ == "__main__":
    main()
