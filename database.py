#!/usr/bin/python3

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from datetime import datetime as DateTime
from copy import deepcopy
from time import time
import sys, os
import base64
import csv


"""
Database used by Password Manager

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
__version__      =  '1.2.1'
__last_updated__ =  '14/1/2021'
__license__      =  'GPLv3'



class Record():

    def __init__(self, website='', password='', last_modified=''):
        """
        Database Attributes
        ===================

        website* (string)
        password (default: '', string)

        # This variable keeps a history of the number of 
        # times the password field got updated as well as 
        # the date and time. Format: ['dd-mm-yyyy hh:min:ss']
        last_modified (list object, most recent time appended to it) 

        (Optional) group_name (string)
        (Optional) email (default: null, string)
        (Optional) username (default: null, string)
        (Optional) remark (default: null, string)
        (Optional) Two_factor_enabled (default: null, boolean)
        (Optional) Recovery_email: (default: null, string)
        (Optional) Phone number: (default: null, string)
        """
        #if (website == '' or password == ''):
        #    raise Exception("[-] Record parameter cannot be null")

        self.__website = website.lower()
        self.__password = password

        self.__last_modified = []

        if (last_modified == ''):
            self.update_last_modified()
        else:
            self.__last_modified = [last_modified]

        self.__email = ''
        self.__username = ''
        self.__group = ''
        self.__remark = ''
        self.__two_factor = ''
        self.__recovery_email = ''
        self.__phone_number = ''


    def __str__(self):
        s = "Site: %s, Pass: %s, Last Modified: %s" % (\
                self.get_website(), self.get_password(), \
                self.get_last_modified()[-1])

        if (self.__email != ''):
            s = '%s, Email: %s' % (s, self.get_email())

        if (self.__username != ''):
            s = '%s, Username: %s' % (s, self.get_username())

        if (self.__group != ''):
            s = '%s, Group: %s' % (s, self.get_group())

        if (self.__remark != ''):
            s = '%s, Remark: %s' % (s, self.get_remark())

        if (self.__two_factor != ''):
            s = '%s, Two-factor: %s' % (s, self.get_two_factor())

        if (self.__recovery_email != ''):
            s = '%s, Recovery-email: %s' % (s,
                    self.get_recovery_email())

        if (self.__phone_number != ''):
            s = '%s, Phone-number: %s' % (s, self.get_phone_number())

        return s


    def get_summary(self):
        """
        Short summary information about a record.

        Used by: get_record_summary() in Class ManageDatabase()

        Args:    N/A

        Returns: (str)
        """

        s = "%s" % (self.get_website())

        if (self.__username != ''):
            s = '%s, %s' % (s, self.get_username())

        if (self.__email != ''):
            s = '%s, %s' % (s, self.get_email())

        if (self.__group != ''):
            s = '%s, %s' % (s, self.get_group())

        return s


    def format_field_csv(self, data=''):
    
        tmp_data = list(data)
    
        new_list = []
        new_list.append('"')
    
        if '"' in tmp_data:
            for i in range(len(tmp_data)):
    
                if (tmp_data[i] == '"'):
                    new_list.append('"')
                    new_list.append('"')
                else:
                    new_list.append(tmp_data[i])
    
            new_list.append('"')
        else:
            new_list = new_list + tmp_data
            new_list.append('"')
    
        return (''.join(new_list))


    def format_csv(self):
        """
        Convert all data to csv formatted string

        Args:       N/A

        Returns:    (str)
        """

        #==========================================================
        # Headers
        #==========================================================
        # site,pass,last_modified,email,username,group
        # remark,two_factor,recovery_email,phone_number
        #==========================================================

        data = '%s' % self.format_field_csv(self.get_website())
        data = '%s,%s' % (data, self.format_field_csv(self.get_password()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_last_modified()[-1]))
        data = '%s,%s' % (data, self.format_field_csv(self.get_email()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_username()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_group()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_remark()))


        if (self.__two_factor == ''):
            data = '%s,%s' % (data,self.format_field_csv(self.get_two_factor()))
        elif (self.__two_factor == True):
            data = '%s,%s' % (data,self.format_field_csv('enabled'))
        else:
            data = '%s,%s' % (data,self.format_field_csv('disabled'))

        data = '%s,%s' % (data,self.format_field_csv(self.get_recovery_email()))
        data = '%s,%s' % (data,self.format_field_csv(self.get_phone_number()))

        return ''.join(data)


    def update_last_modified(self):
        """
        This function updates 'last_modified' attribute.
        It is called automatically whenever the password field 
        is changed.

        Args:    N/A

        Returns: N/A
        """
        ## Format
        # ['dd-mm-yyyy hh:min']
        
        timestamp = DateTime.today().strftime("%d-%m-%Y %H:%M")
        self.__last_modified.append(timestamp)


    def get_group(self):
        return self.__group

    def get_website(self):
        return self.__website

    def get_password(self):
        return self.__password

    def get_last_modified(self):
        return self.__last_modified

    def get_email(self):
        return self.__email

    def get_username(self):
        return self.__username

    def get_remark(self):
        return self.__remark

    def get_two_factor(self):
        return self.__two_factor

    def get_recovery_email(self):
        return self.__recovery_email

    def get_phone_number(self):
        return self.__phone_number

    def set_group(self, value=""):
        self.__group = value

    def set_website(self, value=""):
        self.__website = value

    def set_password(self, value=""):
        self.__password = value
        self.update_last_modified()

    def set_email(self, value=""):
        self.__email = value

    def set_username(self, value=""):
        self.__username = value

    def set_remark(self, value=""):
        self.__remark = value

    def set_two_factor(self, value=None):
        if (value == True or value == False):
            self.__two_factor = value

    def set_recovery_email(self, value=""):
        self.__recovery_email = value

    def set_phone_number(self, value=""):
        self.__phone_number = value


class ManageRecord():
    def __init__(self):

        """
        This class mantains a list of Record objects and provides
        interfaces to interact with data on a higher level
        """

        self.__record_list = []
        self.__encrypted_data = ''
        self.__encryption_key = ''
        self.__salt = ''
        self.__salt_length = None
        self.__user_password = ''

    
    def print_data(self, item_list=None):

        if (item_list == None):
            print("Number of entries: {}".format(len(self.__record_list)))
            
            for item in self.__record_list:
                print(item)
        else:
            print("Number of entries: {}".format(len(item_list)))
            
            for item in item_list:
                print(item)


    def get_key(self):
        """
        Returns the key that was used for encryption of data

        """

        return self.__encryption_key.decode('utf-8')


    def validate_index(self, index=None, item_list=None):
        """
        Validates index or a list of indexes against the 2nd
        parameter (item_list). If 2nd parameter is not provided,
        then indexes are validated against internal datastructure
        (__record_list).

        Args:    1) An int value or a list of integers 
                 2) The list which will be used to validate indexes
                    (Default: If set to None, will use __record_list)

        Returns: Boolean value indicating whether index/indexes are valid
        
        """

        if (item_list == None):
            item_list = self.__record_list

        if (len(item_list) == 0):
            return False

        if (type(index) == int):
            if (index >= 0 and (index < len(item_list))):
                return True
            else:
                return False
        elif (type(index) == list):
            for i in index:
                if (i < 0 or (i >= len(item_list))):
                    return False
            return True
        else:
            return False


    def get_index(self, index=None):

        """
        Provides the record object at the specified index

        Args:    index (int)
        Returns: (Record)
        
        """
        if (index != None and index >= 0 and index < len(self.__record_list)):
            return self.__record_list[index]
        else:
            return None


    def get_number_of_records(self):
        """
        Returns the number of records in database
        """
        return len(self.__record_list)

        
        """
        Returns the size of data in memory
        """
        return sys.getsizeof(self.format_csv())


    def get_summary(self):
        """
        This is used by the frontend for the search bar.

        Presents a summary of records in database for autocompletion 
        when searching.

        Args:    N/A

        Returns: A list of strings matching record indexes in database
        """

        if (len(self.__record_list) == 0):
            return []

        l = []

        for item in self.__record_list:
            l.append(item.get_summary())

        return l


    def add(self, item):

        """
        Adds a Record object, also supports a list of records
        
        Args:    A single Record or a list of Record
        
        Returns: N/A
        """

        if (type(item) == Record):
            self.__record_list.append(item) 
        elif (type(item) == list):
            for record in item:
                self.__record_list.append(record)

        self.sort()


    def check_duplicate_entry(self, item):

        """
        Searches for duplicate entries & returns boolean value
        indicating whether a duplicate entry exists or not.
        An entry is considered duplicate if the site name along with
        username, email and group match any existing record in database.

        Args:    Record object

        Returns: Boolean
        """

        if (self.search_website(item.get_website())):
            if (self.search_email(item.get_email())):
                return True
            elif (self.search_username(item.get_username())):
                return True

        return False


    def sort(self, custom_list=None):
        self.__sort_by_website(custom_list)


    def __sort_by_website(self, custom_list=None):

        """
        Sorts records by website name in ascending order

        Args:    Accepts a list of records for sorting. 
                 If no parameters are passed, sorts the 
                 inernal list of records

        Returns: If optional parameter was passed returns
                 the sorted list
        """

        if (custom_list == None): # Do in place soting for record in memory,
                                  # only if no other list is provided as argument

            if (len(self.__record_list) == 0):
                return

            while (True):         
                changes = False

                for i in range(len(self.__record_list)):
                    j = i+1

                    if (j < len(self.__record_list)):
                        if (self.__record_list[j].get_website() < self.__record_list[i].get_website()):
                            tmp = self.__record_list[i]
                            self.__record_list[i] = self.__record_list[j]
                            self.__record_list[j] = tmp
                            changes = True

                if (changes == False):
                    break

            return
        else:
            while (True):
                changes = False

                for i in range(len(custom_list)):
                    j = i+1

                    if (j < len(custom_list)):
                        if (custom_list[j].get_website() < custom_list[i].get_website()):
                            tmp = custom_list[i]
                            custom_list[i] = custom_list[j]
                            custom_list[j] = tmp
                            changes = True

                if (changes == False):
                    break

            return custom_list


    def remove_website(self, item):

        """
        Deletes a Record object based on the given website attribute
        
        Args:    Name of website (str)
        
        Returns: N/A
        """

        if (type(item) == str):
            
            index_list = self.search_website(item) 

            if (len(index_list) != 0):
                for i in range(len(index_list)):
                    index = index_list[i]
                    self.__record_list.pop(index)
        else:
            raise TypeError("Parameter needs to be of type string")

    
    def remove_index(self, index):

        """
        Deletes a Record object based on index, support list of indexes
        
        Args:    Index(es) to remove (int) or (list)
        
        Returns: N/A
        """

        if (type(index) == int and len(self.__record_list) != 0):
            if (index < len(self.__record_list) and index >= 0):
                self.__record_list.pop(index)
        elif (type(index) == list and len(self.__record_list) != 0):

            count = 0
            tmp_index = 0
            
            # index represents a list of indexes & item is an index
            #       from that list
            for item in index:
                tmp_index = item - count
                if (tmp_index < len(self.__record_list) and tmp_index >= 0):
                    self.__record_list.pop(tmp_index)
                    count += 1

        else:
            pass
    

    def update_index(self, record_object, index):

        """
        Update record object at the specified index
        
        Args:    1) An object (Record)
                 2) Index at which the record object will be placed (int)
        
        Returns: N/A
        """

        if (type(index) == int and len(self.__record_list) != 0 and \
                type(record_object) == Record):

                self.__record_list[index] = deepcopy(record_object)
                self.sort()
                

    
    def search_website(self, website='', start_index=None, \
            end_index=None, partial_match=True, called_by_search_all=False):

        """
        Search records by website name 
        
        Args:    1) Website to search for (str)
                 2) Starting index of search (int)
                 3) Ending index of search (int)
                 4) Try to search for a partial match (boolean)
                    (Default: False)
        
        Returns: Indexes of matched item from database if it is 
                 found or an empty list if not found.
                 Returns None if the search fails due to invalid 
                 parameters
        """
        
        if (website == '' or len(self.__record_list) == 0):
            return []

        _start_index = 0
        _end_index = len(self.__record_list)

        if (start_index != None and end_index != None):
            _start_index = start_index 
            _end_index = end_index
     
        search_matches = []

        if (partial_match):
            for i in range(_start_index, _end_index):
                if ( website.lower() in \
                        self.__record_list[i].get_website().lower()):
                    search_matches.append(i) 
        else:
            for i in range(_start_index, _end_index):
                if (self.__record_list[i].get_website() == website):
                    search_matches.append(i) 

        if (called_by_search_all): # trying to avoid repetitive sorting
            return search_matches
        else:
            search_matches.sort()
            return search_matches


    def search_group(self, group_name='', partial_match=True, called_by_search_all=False):

        """
        Search records by group name
        
        Args:    Group name to search for (str)
        
        Returns: A list of indexes that have matched.
                 An empty list will be returned if no matches found.
                 None will be returned if the parameters are incorrect.
        """

        if (group_name == ''):
            return []

        search_matches = []

        if (partial_match):
            for i in range(len(self.__record_list)):
                if (group_name.lower() in \
                        self.__record_list[i].get_group().lower()): 
                    search_matches.append(i)
        else:
            for i in range(len(self.__record_list)):
                if (self.__record_list[i].get_group().lower() \
                        == group_name.lower()):
                    search_matches.append(i)

        if (called_by_search_all): # trying to avoid repetitive sorting
            return search_matches
        else:
            search_matches.sort()
            return search_matches

    
    def search_username(self, username='', partial_match=True, called_by_search_all=False):

        """
        Search records by username
        
        Args:    1) Username to search for (str)
                 2) Try to search for a partial match (boolean)
                    (Default: False)
        
        Returns: A list of indexes that matched. 
                 An empty list will be returned if no matches found.
                 None is returned if the parameters are invalid.
        """

        if (username == ''):
            return []

        search_matches = []

        if (partial_match):
            for i in range(len(self.__record_list)):
                if (username.lower() in \
                        self.__record_list[i].get_username().lower()): 
                    search_matches.append(i)
        else:
            for i in range(len(self.__record_list)):
                if (self.__record_list[i].get_username().lower() \
                        == username.lower()):
                    search_matches.append(i)

        if (called_by_search_all): # trying to avoid repetitive sorting
            return search_matches
        else:
            search_matches.sort()
            return search_matches


    def search_email(self, email='', partial_match=True, called_by_search_all=False):

        """
        Search records by email
        
        Args:    1) Email address to search for (str)
                 2) Try to search for a partial match (boolean)
                    (Default: False)
        
        Returns: A list of indexes that matched. 
                 An empty list will be returned if no matches found.
                 None is returned if the parameters are invalid.
        """

        if (email == ''):
            return []

        search_matches = []

        if (partial_match):
            for i in range(len(self.__record_list)):
                if (email.lower() in 
                        self.__record_list[i].get_email().lower()):
                    search_matches.append(i)
        else:
            for i in range(len(self.__record_list)):
                if (self.__record_list[i].get_email().lower() \
                        == email.lower()):
                    search_matches.append(i)

        if (called_by_search_all): # trying to avoid repetitive sorting
            return search_matches
        else:
            search_matches.sort()
            return search_matches

    
    def search_all(self, keyword=''):

        """
        Search records by common attributes such as website name,
            email, username, group. Considers partial matches for
            every category.
        
        Args:    Keyword to search for
        
        Returns: A list of indexes that matched. 
                 An empty list will be returned if no matches found.
                 None is returned if the parameters are invalid.
        """

        if (keyword == ''):
            return []

        r1 = self.search_website(keyword, partial_match=True, called_by_search_all=True)
        r2 = self.search_username(keyword, partial_match=True, called_by_search_all= True)
        r3 = self.search_email(keyword, partial_match=True, called_by_search_all=True)
        r4 = self.search_group(keyword, partial_match=True, called_by_search_all=True)

        search_matches = list(set(r1 + r2 + r3 + r4))

        search_matches.sort()
        
        return search_matches


    def format_csv(self):

        """
        Converts all record entries in database
        into a csv formatted list

        Args:    N/A
        
        Returns: A string list of records
        """

        #==========================================================
        # Headers
        #==========================================================
        # site,pass,last_modified,email,username,group
        # remark,two_factor,recovery_email,phone_number
        #==========================================================

        if (len(self.__record_list) == 0):
            raise DatabaseEmptyException()

        csv_list = []

        header = 'site,pass,last_modified,email,username,group,remark,two_factor,recovery_email,phone_number\n'

        csv_list.append(header)
        
        for i in self.__record_list:
            r = '%s\n' % i.format_csv()
            csv_list.append(r)
            #csv_list.append(i.format_csv())

        return csv_list


    def convert_csvlist_to_record(self, csv_list=[], compatible=False):
        
        """
        Converts all entries in csv formatted list
        to a list of Record objects

        Args:    1) A list of str 
                 2) This field can be set to True if we want to import 
                    only user,pass,username field. This is useful when 
                    importing data from other pw managers & is used only
                    by frontend (bool, default: False)
        
        Returns: N/A

        Remarks: When compatible is set to True & we're importing csv records 
                 to database, we intentionally do not check for duplicates 
                 as we assume that the user knows what they're doing.
                 It is most likely to be used when a new user is 
                 migrating to pwmgr & don't have anything setup yet.
        
        """

        if (len(csv_list) == 0):
            return

        if (compatible):
            for record in csv_list:
                record_object = Record(record[0], record[1])
                record_object.set_username(record[2])
                self.__record_list.append(record_object)
                self.sort()
        else:
            for record in csv_list:
                record_object = Record(record[0], record[1], record[2])
                record_object.set_email(record[3])
                record_object.set_username(record[4])
                record_object.set_group(record[5])
                record_object.set_remark(record[6])
                record_object.set_two_factor(record[7])
                record_object.set_recovery_email(record[8])
                record_object.set_phone_number(record[9])

                self.__record_list.append(record_object)

            
    def export_csv(self, filename='data.csv'):
        
        """
        Writes all entries in database into 
        the specified file in csv format

        Args:    The name of the file
        
        Returns: True if the operation succeeds
                 False if the operation fails
        """

        if (type(filename) != str):
            raise TypeError("Filename needs to be a string")
            
        try:
            f = open(filename, 'w')
        
            formatted_list = self.format_csv()

            header = 'site,pass,last_modified,email,username,group,remark,two_factor,recovery_email,phone_number\n'

            f.write(header)

            for i in range(len(self.__record_list)):

                r = self.__record_list[i]

                data = '%s\n' % (r.format_csv())

                f.write(data)

        except (IOError):
            return False

        f.close()

        return True


    def read_csv(self, filename='data.csv'):
        
        """
        Parses a csv formatted file & loads all 
            information into database

        Args:    The name of the file
        
        Returns: True if the operation succeeds
                 False if the operation fails
        """

        if (type(filename) != str):
            raise TypeError("Filename needs to be a string")
            
        data = []

        try:
            f = open(filename, 'r')
            r = reader(f)

            for row in r:
                data.append(row)
            
        except (BaseException):
            return False
        finally:
            f.close()

        self.convert_csvlist_to_record(data)

        return True


    def read_csv_in_memory(self, data=''):
        
        """
        Parses a csv formatted string & loads all 
            information into database

        Args:    (str)
        
        Returns: True if the operation succeeds
                 False if the operation fails
        """

        if (type(data) != str):
            raise TypeError("read_csv_in_memory(): Data needs to be string")
            
        data_list = data.splitlines()

        record_list = csv.reader(data_list, quotechar='"', delimiter=',', \
                quoting=csv.QUOTE_ALL, skipinitialspace=True)

        tmp = []

        for item in record_list:
            tmp.append(item)

        return tmp


    def convert_int_to_hex(self, val=None, decimal_places=4):
        """
        Converts int to hex without regular 0x part

        Args:      1) Integer value (int)
                   2) The number of decimal places 

        Returns:   (str)

        Exception: ValueError() if the input parameter is 
                   not of type int
        """
        if (type(val) == int):
            s = str(hex(val))[2:].zfill(decimal_places)
            return s
        else:
            raise ValueError('Expected integer value')
    

    def convert_hex_to_int(self, val=None):
        """
        Converts hex from integer

        Args:      Hexadecimal value (str)

        Returns:   (int)

        Exception: ValueError() if the input parameter is 
                   not of type str
        """
    
        if (type(val) == str):
            i = int(val, 16)
            return i
        else:
            raise ValueError('Expected str in hex / base 16 format')


    def generate_new_key(self, password='', generate_salt=True):

        """
        Uses a combination of salt and input password to 
        generate a new key. Both the salt and encryption
        keys are automatically updated internally when
        they are generated. 

        In situations for example when loading the file,
        the salt is already present so the second parameter 
        can be set to false in order to generate new key 
        from user password.

        Args:       The password to use to derive the key

        Returns:    N/A

        Exceptions: N/A
        """

        if (password == ''):
            print("generate_new_key(): Requires a password to generate new key")
            return

        # Generating new salt, if one doesn't already exist
        if (generate_salt):
            # Aiming for 32 bit (salt + password)
            self.__salt_length = 32-len(password)
            self.__salt = os.urandom(self.__salt_length)

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), \
                length=32, salt=self.__salt, iterations=100000)

        key = base64.urlsafe_b64encode(\
                kdf.derive(bytes(password, 'utf-8')))

        self.__encryption_key = key
        
        #print("Key: %s\tSalt: %s" % (key, self.__salt))


    def change_password(self, new_password=''):
        """
        Generates new salt and derives a new key based on the 
        new password. Re-encrypts database with new key.

        Args:    The new password to use to encrypt the database
        
        Returns: Boolean value indicating success / failure
        """

        self.__user_password = new_password
        self.generate_new_key(new_password, True)


    def __encrypt_database_in_memory(self):

        """
        Encrypts database with key and updates internal variable 
        (self.__encryption_key) which stores an encrypted
        byte string representation of database

        Args:      N/A
        
        Returns:   N/A

        Exception: N/A
        """

        data = self.format_csv()

        # We don't include index 0, cos we want to discard csv header from
        # encrypted database
        record_string = '%s' % (data[1])
        
        if (len(data) > 2):
            for record in data[2:]: 
                record_string = '%s%s' % (record_string, record) 

        data_bytes = bytes(record_string, 'utf-8')

        fernet_handler = Fernet(self.__encryption_key)
        encrypted_data = fernet_handler.encrypt(data_bytes)

        self.__encrypted_data = encrypted_data


    def write_encrypted_database(self, filename='data.bin', export=False, export_filename='backup.bin'):

        """
        Responsible for encryption of database

        Args:       1) The name of the regular encryted file. (Default: 'data.bin')
                    2) Boolean value indicating whether we should process it as
                       a regular or a different file format (used in cloud syncing with
                       integrity checks & builtint configs). (Default: False)
                       - If it is False, we just write updated data to regular
                         database
                       - If it is True, we call create a separate file that 
                         can be used in cloud sync.

                    3) The name of the exported file. (Default: 'backup.bin')

        Returns:    Boolean value indicating whether the operation succeeded or not.

        Exceptions: NoKeyFoundException() if a new key hasn't been generated

        """

        if (self.__encryption_key == '' or self.__salt == ''):
            # This exception like won't occur as frontend will make sure that
            # the key has been initialized first before calling this functions, 
            # but it is kept as a safety measure in case this library 
            # is used by other programs
            raise NoKeyFoundException('Need to initialize key first, call ' + \
                    'generate_new_key() function')

        if (len(self.__record_list) != 0):

            data_length = ''

            self.__encrypt_database_in_memory()
            data_length = '%s' % (self.convert_int_to_hex(len(self.__encrypted_data),4))
            file_type = '00'

            if (export): # Writing file that will be used for cloud sync
                         # TODO(1): This part will be completed later after
                         # rest of the database has a stable code base
                         # & has been tested thoroughly
                file_type = '01'
            else: # Writing regular file

                try:
                    salt_length_hex = '%s' % (self.convert_int_to_hex(self.__salt_length, 2))
                    file_handler = open(filename, 'wb')
                    file_handler.write(bytes(file_type, 'utf-8'))
                    file_handler.write(bytes(salt_length_hex, 'utf-8'))
                    file_handler.write(bytes(data_length, 'utf-8'))
                    file_handler.write(self.__salt)
                    file_handler.write(self.__encrypted_data)
                    file_handler.close()
                    return True
                except IOError as e:
                    print("write_encrypted_database(): error#01 occured while writing database")
                    return False

        else: # When records are empty & we are just writing salt with no database
              # We also assume that we don't allow exporting to backup format 
              # with an empty database

            try:
                file_type = '00'
                salt_length_hex = '%s' % (self.convert_int_to_hex(self.__salt_length, 2))
                data_length = '0000'

                file_handler = open(filename, 'wb')

                file_handler.write(bytes(str(file_type), 'utf-8'))
                file_handler.write(bytes(str(salt_length_hex), 'utf-8'))
                file_handler.write(bytes(str(data_length), 'utf-8'))
                file_handler.write(self.__salt)
                file_handler.close() 
                return True
            except IOError as e:
                print("write_encrypted_database(): error#02 occured while writing database")
                return False


    def load_database(self, filename='data.bin', password=''):
        
        """
        Attempts to load database from current working directory

        Args: Specify the database name (Default: 'data.bin')

        Returns: Boolean value indicating success / failure

        Exception: 1) IncorrectPasswordException() if password
                      for decrypting data is not correct
                   2) DatabaseFileNotFoundException() if the
                      database file doesn't exist & load_database()
                      function is called.
                      
        """

        if (password == ''):
            print("load_database(): Requires a password to decrypt database")
            return

        if (os.path.isfile(filename) == False): 
            # The exception below will not occur as frontend verifies path &
            # handles errors accordingly if database is not present.
            # It is kept as a safety measure in case used by other programs
            raise DatabaseFileNotFoundException("load_database(): File: %s does't exist" % filename)

        try:
            fh = open(filename, 'rb')

            file_type = (fh.read(2)).decode('utf-8')

            # Salt length specified in first 2 bytes of file
            self.__salt_length = self.convert_hex_to_int((fh.read(2)).decode('utf-8'))
        except IOError as e:
            print("load_database(): error#01 occured while reading database")

        if (file_type == '00'):
            try:
                data_length = self.convert_hex_to_int((fh.read(4)).decode('utf-8'))

                self.__salt = fh.read(self.__salt_length)
            except IOError as e:
                print("load_database(): error#02 occured while reading database")

            self.generate_new_key(password, False)

            if (data_length == 0): 
            # The condition means empty database but there's salt
            # & key that can be generated. We assume that user might
            # want to add new records using existing key so we load old
            # key & return

                return True
            else:
                try:
                    self.__encrypted_data = fh.read()
                except IOError as e:
                    print("load_database(): error#03 occured while reading database")
        else: # TODO(3) Add logic for filetype '01' with cloud sync features
            pass


        fernet_handler = Fernet(self.__encryption_key)

        try:
           decrypted = (fernet_handler.decrypt(self.__encrypted_data)).decode('utf-8')
        except InvalidToken as e:  # This means password was incorrect 
            raise IncorrectPasswordException()

        self.__password = password

        data_list = self.read_csv_in_memory(decrypted)

        self.convert_csvlist_to_record(data_list)

        return True



#===========================================================================
#                   Custom Exception Handling Classes                      #
#===========================================================================


class DatabaseEmptyException(Exception):
    def __init__(self, msg='No record exists'):
        super(DatabaseEmptyException, self).__init__(msg)


class DatabaseNotEncryptedException(Exception):
    def __init__(self, msg='Need to call __encrypt_database_in_memory() first'):
        super(DatabaseNotEncryptedException, self).__init__(msg)


class NoKeyFoundException(Exception):
    def __init__(self, msg="Key doesn't exist"):
        super(NoKeyFoundException, self).__init__(msg)


class DatabaseFileNotFoundException(Exception):
    def __init__(self, msg="data.bin file doesn't exist in current directory"):
        super(DatabaseFileNotFoundException, self).__init__(msg)


class IncorrectPasswordException(Exception):
    def __init__(self, msg="Decryption of database failed as password is incorrect"):
        super(IncorrectPasswordException, self).__init__(msg)

