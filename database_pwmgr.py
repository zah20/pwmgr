#!/usr/bin/python3
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from datetime import datetime as DateTime
from hashlib import sha256
from time import time
import sys, os
import base64
import csv


"""
Database used by Password Manager

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
__version__      =  '1.9.0'
__last_updated__ =  '01/23/2023'
__license__      =  'GPLv3'


class Record():

    """
    TODO: Version 2.0
         1) Switch to pycrypto encryption library
         2) Replace PBKDF2 with Scrypt function
         3) Upgrade pw audit metrics 
    """

    def __init__(self, website='', password='', last_modified=''):

        """

        --audit attributes:

            pw_age (default: null, str) Determines if a pw change is required
                (values: null = unset, 'n' = not needed, 'o' = optional, 'r' = required)

            pw_reuse (default: null, str) Checks whether pw has been reused in another record
                (values: null = unset, '1' = pw reused in another record, '0' = pw not reused  )

            pw_complexity (default: null, str) Determines the pw strength
                (values: null = unset, 'u' = unsuitable, 'w' = weak, 'a' = average, 'g' = good, 'e' = excellent)

            security_rating (default: null, str) Rates overall security of a record based on the 3 pw attributes defined above
                (values: null = unset, range '0'-'15')

                ratings: 

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

        self.__website = website.lower()
        self.__password = password

        if (last_modified == ''):
            self.update_last_modified()
        else:
            self.__last_modified = last_modified

        self.__email = ''
        self.__username = ''
        self.__group = ''
        self.__remark = ''
        self.__two_factor = ''
        self.__recovery_email = ''
        self.__phone_number = ''
        self.__pw_age = ''
        self.__pw_reuse = ''
        self.__pw_complexity = ''
        self.__security_rating = ''


    def __str__(self):

        s = "Site: %s, Pass: %s, Last Modified: %s" % (\
                self.get_website(), self.get_password(), \
                self.get_last_modified())

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
            s = '%s, Recovery-email: %s' % (s, self.get_recovery_email())

        if (self.__phone_number != ''):
            s = '%s, Phone-number: %s' % (s, self.get_phone_number())

        s = '%s, pw_age: %s' % (s, self.get_pw_age())
        s = '%s, pw_reuse: %s' % (s, self.get_pw_reuse())
        s = '%s, pw_complexity: %s' % (s, self.get_pw_complexity())
        s = '%s, security_rating: %s' % (s, self.get_security_rating())

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
        """
        Makes our data compatible with double quote enclosed csv format
        """
    
        tmp_data = list(data)
    
        new_list = []
        new_list.append('"')
    
        # Since we use double quoted csv format,
        # if there's any double quote present, it
        # needs to be replaced wit 2 double quote
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
        # pw_age,pw_reuse,pw_complexity,security_rating
        #==========================================================

        data = '%s' % self.format_field_csv(self.get_website())
        data = '%s,%s' % (data, self.format_field_csv(self.get_password()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_last_modified()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_email()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_username()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_group()))
        data = '%s,%s' % (data, self.format_field_csv(self.get_remark()))

        # Internally two factor is stored as '0' or '1' or '' (if not set)
        # We store it in its original form by directry accessing the variable,
        # but when called by pwmgr frontend using get_two_factor(), we modify
        # it's value to be more readable
        data = '%s,%s' % (data,self.format_field_csv(self.__two_factor))

        data = '%s,%s' % (data,self.format_field_csv(self.get_recovery_email()))
        data = '%s,%s' % (data,self.format_field_csv(self.get_phone_number()))

        data = '%s,%s' % (data,self.format_field_csv(self.get_pw_age()))
        data = '%s,%s' % (data,self.format_field_csv(self.get_pw_reuse()))
        data = '%s,%s' % (data,self.format_field_csv(self.get_pw_complexity()))
        data = '%s,%s' % (data,self.format_field_csv(self.get_security_rating()))

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
        # 'dd-mm-yyyy hh:min'
        
        self.__last_modified = DateTime.today().strftime("%d-%m-%Y %H:%M")


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
        if (self.__two_factor == ''):
            return 'Not enabled'
        elif (self.__two_factor == '1'):
            return 'Enabled'
        elif (self.__two_factor == '0'):
            return 'Disabled'

    def get_recovery_email(self):
        return self.__recovery_email

    def get_phone_number(self):
        return self.__phone_number

    def get_pw_age(self):
        return self.__pw_age

    def get_pw_reuse(self):
        return self.__pw_reuse

    def get_pw_complexity(self):
        return self.__pw_complexity

    def get_security_rating(self):
        return self.__security_rating

    def set_group(self, value=""):
        self.__group = value

    def set_website(self, value=""):
        self.__website = value

    def set_password(self, value="", update_lm=False):
        self.__password = value

        if (update_lm):
            self.update_last_modified()

    def set_email(self, value=""):
        self.__email = value

    def set_username(self, value=""):
        self.__username = value

    def set_remark(self, value=""):
        self.__remark = value

    def set_two_factor(self, value=''):
        if (type(value) == bool):
            if (value):
                self.__two_factor = '1'
            else:
                self.__two_factor = '0'
        elif (value in ['', '0', '1']):
            self.__two_factor = value

    def set_recovery_email(self, value=""):
        self.__recovery_email = value

    def set_phone_number(self, value=""):
        self.__phone_number = value

    def set_pw_age(self, value=""):
        self.__pw_age = value

    def set_pw_reuse(self, value=""):
        self.__pw_reuse = value

    def set_pw_complexity(self, value=""):
        self.__pw_complexity = value

    def set_security_rating(self, value=""):
        self.__security_rating = value


class ManageRecord():

    def __init__(self):

        """
        This class mantains a list of Record objects and provides
        interfaces to interact with data on a higher level
        """

        self.__salt_length = 32
        self.__record_list = []
        self.__hash_length = 64 # SHA-256
        self.__salt_1 = ''
        self.__encrypted_data = ''
        self.__encryption_key_1 = ''
        self.__encryption_key_2 = ''
        self.__master_password = ''
        self.__salt_2 = ''

        self.__symbols = "!@#$%^&*(){}[]<>?+-"
        self.__ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.__num = "0123456789"
        self.__lcase = "abcdefghijklmnopqrstuvwxyz"


    def print_data(self):

        print(len(self.__record_list))
        
        for item in self.__record_list:
            print(item)


    def get_key(self):

        """
        Returns the key that was used for encryption of data

        """

        return self.__encryption_key_1.decode('utf-8')


    def get_key_2(self):

        """
        Returns the key that was used for encryption of data

        """

        return self.__encryption_key_2.decode('utf-8')

    def get_master_password(self):

        """
        Returns the master password if its available.

        It is only available if user loads the database without stored key

        """

        return self.__master_password


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


    def get_index(self, index):

        """
        Provides the record object at the specified index

        Args:    index (int)
        Returns: (Record)
        
        """

        r = self.__record_list[index]
        r.set_password(self.get_pw_of_index(index))

        return r


    def get_pw_of_index(self, index, enc_key=''):

        """
        Decrypted pw of given index
        """
        
        pw = self.__record_list[index].get_password()

        fernet_handler = ''

        if (enc_key == ''):
            fernet_handler = Fernet(self.__encryption_key_2)
        else:
            fernet_handler = Fernet(enc_key)

        pw = bytes(pw, 'utf-8')

        try:
            pw = fernet_handler.decrypt(pw).decode('utf-8')
        except InvalidToken:
            raise IncorrectPasswordException('Unable to decrypt pw, encryption key is incorrect')

        return pw


    def get_number_of_records(self):

        """
        Returns the number of records in database
        """
        return len(self.__record_list)


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

            _pw = self.__encrypt_pw(item.get_password())
            _item = item
            _item.set_password(_pw)

            self.__record_list.append(_item) 

        elif (type(item) == list):

            for record in item:

                _pw = self.__encrypt_pw(record.get_password())
                _record = record
                _record.set_password(_pw)

                self.__record_list.append(_record) 

        self.sort()


    def check_duplicate_entry(self, item):

        """
        Searches for duplicate entries & returns boolean value
        indicating whether a duplicate entry exists or not.
        An entry is considered duplicate if the site name along with
        username / email match any existing record in database.

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

        if (custom_list == None): # Do in place sorting for record in memory,
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


    def __sort_by_last_modified(self, custom_list=None):

        """
        Sorts records by most recent to least

        Args:    Accepts a list of records for sorting. 
                 If no parameters are passed, sorts the 
                 inernal list of records

        Returns: If optional parameter was passed returns
                 the sorted list
        """

        if (custom_list == None or len(custom_list) == 0):
            return []

        l_mod = [] 

        for i in range(len(custom_list)):
            l_mod.append([custom_list[i],i])

        while (True):
            changes = False
        
            for i in range(len(l_mod)):
                j = i+1
        
                if (j < len(l_mod)):
                    j_last = l_mod[j][0].get_last_modified().split(' ')
                    j_date = j_last[0].split('-')
                    j_time = j_last[1].split(':')
        
                    j_day = int(j_date[0])
                    j_month = int(j_date[1])
                    j_year = int(j_date[2])
                    j_hr = int(j_time[0])
                    j_min = int(j_time[1])

                    #print('%s/%s/%s %s:%s' % (j_year, j_month, j_day, j_hr, j_min))
        
                    j_dt_obj = DateTime(j_year, j_month, j_day, j_hr, j_min)
        
                    i_last = l_mod[i][0].get_last_modified().split(' ')
                    i_date = i_last[0].split('-')
                    i_time = i_last[1].split(':')
        
                    i_day = int(i_date[0])
                    i_month = int(i_date[1])
                    i_year = int(i_date[2])
                    i_hr = int(i_time[0])
                    i_min = int(i_time[1])
        
                    #print('%s/%s/%s %s:%s' % (i_year, i_month, i_day, i_hr, i_min))

                    i_dt_obj = DateTime(i_year, i_month, i_day, i_hr, i_min)
        

                    if (i_dt_obj < j_dt_obj):
                        tmp = l_mod[i]
                        l_mod[i] = l_mod[j]
                        l_mod[j] = tmp
                        changes = True
        
            if (changes == False):
                break

        return l_mod


    def get_records_last_modified(self):

        """
        Returns a list of records from database, sorted in 
        the order of most recently modified 

        Args:    N/A

        Returns: A list of records sorted in the order of 
                 most recently modified along with their
                 appropriate index in the database
                 e.g [[r1,2], [r2,3], [r3,7],..]

        Note: This function is just used to sort & display internal
              records in read only mode, we keep our default sorting 
              (sort by website) & our database intact.
        """

        return self.__sort_by_last_modified(self.__record_list)


    def remove_index(self, index):

        """
        Deletes a Record object based on index, also supports a list of indexes
        
        Args:    Index(es) to remove (int) or (list)
        
        Returns: N/A
        """

        if (type(index) == int):
            self.__record_list.pop(index)
        elif (type(index) == list):

            tmp_records = []

            for i in index:
                r = self.__record_list[i]
                tmp_records.append(r)

            for record in tmp_records:
                for i in range(0, len(self.__record_list)):
                    if (record == self.__record_list[i]):
                        self.__record_list.pop(i)
                        break
    

    def update_index(self, record_object, index):

        """
        Update record object at the specified index
        
        Args:    1) An object (Record)
                 2) Index at which the record object will be placed (int)
        
        Returns: N/A
        """

        _record = record_object
        _pw = self.__encrypt_pw(record_object.get_password())
        _record.set_password(_pw)

        self.__record_list[index] = _record

        self.sort()
                

    def search_website(self, website='', partial_match=True, called_by_search_all=False):

        """
        Search records by website name 
        
        Args:    1) Website to search for (str)
                 2) Try to search for a partial match (boolean)
                    (Default: False)
                 3) Used internally by search_all() function (boolean)
        
        Returns: Indexes of matched item from database if it is 
                 found or an empty list if not found.
        """
        
        if (website == '' or len(self.__record_list) == 0):
            return []

        _end_index = len(self.__record_list)

        search_matches = []

        if (partial_match):
            for i in range(0, _end_index):
                if ( website.lower() in \
                        self.__record_list[i].get_website().lower()):
                    search_matches.append(i) 
        else:
            for i in range(0, _end_index):
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
        # remark,two_factor,recovery_email,phone_number,
        # pw_age,pw_reuse,pw_complexity
        #==========================================================

        if (len(self.__record_list) == 0):
            raise DatabaseEmptyException()

        csv_list = []

        header = 'site,pass,last_modified,email,username,group,remark,two_factor,' + \
                'recovery_email,phone_number,pw_age,pw_reuse,pw_complexity,security_rating\n'

        csv_list.append(header)
        
        for i in self.__record_list:
            r = '%s\n' % i.format_csv()
            csv_list.append(r)
            #csv_list.append(i.format_csv())

        return csv_list


    def convert_csvlist_to_record(self, csv_list=[], \
            import_brief=False, used_by_load_database=False):
            
        
        """
        Converts all entries in csv formatted list
        to a list of Record objects

        Args:    1) A list of str 
                 2) This field can be set to True if we want to import 
                    only site,pass,username field. This is useful when 
                    importing data from other pw managers & is used only
                    by frontend (bool, default: False)
        
        Returns: N/A

        Remarks: We intentionally do not check for duplicates 
                 as we assume that the user knows what they're doing.
                 It is most likely to be used when a new user is 
                 migrating to pwmgr & don't have anything setup yet.
        
        """

        #TODO: Test this code

        if (len(csv_list) == 0):
            return

        r_l = len(csv_list[0])

        if (import_brief):

            for record in csv_list:

                pw = ''

                if (not used_by_load_database):
                    pw = self.__encrypt_pw(record[1])
                else:
                    pw = record[1]

                record_object = Record(record[0], pw)
                record_object.set_username(record[2])
                self.__record_list.append(record_object)
                self.sort()

        elif (r_l == 10):

            for record in csv_list:

                pw = ''

                if (not used_by_load_database):
                    pw = self.__encrypt_pw(record[1])
                else:
                    pw = record[1]

                record_object = Record(record[0], pw, record[2])
                record_object.set_email(record[3])
                record_object.set_username(record[4])
                record_object.set_group(record[5])
                record_object.set_remark(record[6])
                record_object.set_two_factor(record[7])
                record_object.set_recovery_email(record[8])
                record_object.set_phone_number(record[9])
                self.__record_list.append(record_object)

        elif (r_l == 14):

            for record in csv_list:

                pw = ''

                if (not used_by_load_database):
                    pw = self.__encrypt_pw(record[1])
                else:
                    pw = record[1]

                record_object = Record(record[0], pw, record[2])
                record_object.set_email(record[3])
                record_object.set_username(record[4])
                record_object.set_group(record[5])
                record_object.set_remark(record[6])
                record_object.set_two_factor(record[7])
                record_object.set_recovery_email(record[8])
                record_object.set_phone_number(record[9])
                record_object.set_pw_age(record[10])
                record_object.set_pw_reuse(record[11])
                record_object.set_pw_complexity(record[12])
                record_object.set_security_rating(record[13])
                self.__record_list.append(record_object)

        else:
            raise UnsupportedFileFormatException('[!] The database format is not supported. ' + \
                    'Please try exporting database with (--export csv) and importing (--import csv) on a newer version of pwmgr')

            
    def export_csv(self, filename='data.csv'):
        
        """
        Writes all entries in database into 
        the specified file in csv format

        Args:    The name of the file
        
        Returns: True if the operation succeeds
                 False if the operation fails
        """

        header = 'site,pass,last_modified,email,username,group,remark,two_factor,recovery_email,phone_number,pw_age,pw_reuse,pw_complexity,security_rating\n'

        try:
            with open(filename, 'w') as f:

                f.write(header)

                for i in range(len(self.__record_list)):

                    # r = self.__record_list[i]
                    r = self.get_index(i)

                    data = '%s\n' % (r.format_csv())

                    f.write(data)

        except (IOError):
            return False

        return True


    def export_csv_brief(self, filename='data.csv'):
        
        """
        Only 'site,pass,username' fields are exported to csv format

        Args:    The name of the file
        
        Returns: True if the operation succeeds
                 False if the operation fails
        """

        header = 'site,pass,username\n'

        try:
            with open(filename, 'w') as f:

                f.write(header)

                for i in range(len(self.__record_list)):

                    # r = self.__record_list[i]

                    r = self.get_index(i)

                    s = r.format_field_csv(r.get_website())
                    p = r.format_field_csv(r.get_password())
                    u = r.format_field_csv(r.get_username())

                    data = '%s,%s,%s\n' % (s,p,u)

                    f.write(data)

        except (IOError):
            return False

        return True


    def read_csv(self, filename='data.csv'):
        
        """
        Parses a csv formatted file & loads all 
            information into database

        Args:    The name of the file
        
        Returns: True if the operation succeeds
                 False if the operation fails
        """

        data = []

        try:
            with open(filename, 'r') as f:
                r = reader(f)
        except (IOError, BaseException):
            return False

        for row in r:
            data.append(row)
            
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


    def generate_new_key(self, password='', generate_salt=True,
            update_enc_key=True, path_to_keyfile=''):

        """
        Uses a combination of salt and input password to 
        generate a new key. Both the salt and encryption
        keys are automatically updated internally when
        they are generated if the 3rd parameter is True.

        In situations for example when loading the file,
        the salt is already present so the 2nd parameter 
        can be set to false in order to generate new key 
        from user password.

        Args:       1) The password to use to derive the key (str)
                    2) Whether to generate a new salt (bool)
                    3) Whether to update_enc_key or just return the new key (bool)
                    4) Path to key file, if you want to use combine it with
                       master password to strengthen key. (Default: null)

        Returns:    The generated key if 3rd parameter is True, otherwise
                    updates internal master key 

        Exceptions: N/A
        """

        if (password == ''):
            print("generate_new_key(): Requires a password to generate new key")
            return

        # Generating new salt, if one doesn't already exist
        if (generate_salt):
            # Used for database encryption
            self.__salt_1 = os.urandom(self.__salt_length) 

        key = ''

        if (path_to_keyfile == ''):

            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), \
                    length=32, salt=self.__salt_1, iterations=1000000)

            key = base64.urlsafe_b64encode(\
                    kdf.derive(bytes(password, 'utf-8')))

            #print("Key: %s\tSalt: %s" % (key, self.__salt_1))
        else:

            kf_data = ''

            with open(path_to_keyfile, 'rb') as fh:
                kf_data = fh.read()

            if (len(kf_data) < 2048):
                raise KeyFileInvalidException()

            kf_data = kf_data + bytes(password, 'utf-8')

            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), \
                    length=32, salt=self.__salt_1, iterations=1000000)

            key = base64.urlsafe_b64encode(kdf.derive(kf_data))

        if (update_enc_key):
            self.__encryption_key_1 = key
            self.generate_new_key_2()
        else:
            return key.decode('utf-8')
        

    def change_password(self, new_password=''):

        """
        Generates new salt and derives a new key based on the 
        new password. Re-encrypts database with new key.

        Args:    The new password to use to encrypt the database
        
        Returns: Boolean value indicating success / failure
        """

        old_key_2 = self.__encryption_key_2

        self.__master_password = new_password
        self.generate_new_key(new_password, True)

        self.generate_new_key_2()
        new_key_2 = self.__encryption_key_2

        self.__migrate_all_pw_from_old_to_new_key(old_key_2, new_key_2)


    def use_keyfile(self, pw, path_to_keyfile=''):

        old_key_2 = self.__encryption_key_2

        self.__master_password = pw
        self.generate_new_key(pw, True, True, path_to_keyfile)

        self.generate_new_key_2()
        new_key_2 = self.__encryption_key_2

        self.__migrate_all_pw_from_old_to_new_key(old_key_2, new_key_2)


    def remove_keyfile(self, pw):

        old_key_2 = self.__encryption_key_2

        self.__master_password = pw
        self.generate_new_key(pw, True, True, '')
    
        self.generate_new_key_2()
        new_key_2 = self.__encryption_key_2

        self.__migrate_all_pw_from_old_to_new_key(old_key_2, new_key_2)


    def generate_hash(self, input_str):
        
        """
        Returns a sha256 hash digest value of the input string

        Args:       A byte encoded string

        Returns:    (str)
        """
    
        if (type(input_str) != bytes):
            raise TypeError('generate_hash(): first parameter needs to be of type bytes')
    
        s = sha256(input_str)
    
        hash_value = s.hexdigest()
    
        return hash_value


    def __encrypt_pw(self, pw, enc_key=''):

        """
        Encrypts the input pw & return it in str form
        
        As it will be in memory & used by db for various str operations, 
        we convert it to a str instead of byte form. That way it also complies 
        with the rules of existing interface
        """

        fernet_handler = ''

        if (enc_key == ''):
            fernet_handler = Fernet(self.__encryption_key_2)
        else:
            fernet_handler = Fernet(enc_key)

        _pw = bytes(pw, 'utf-8')
        _pw = fernet_handler.encrypt(_pw).decode('utf-8')

        return _pw


    def __pre_encrypt_records(self):

        """
        This function ensures that pw field of records are always kept in an
        encrypted state even when database is loaded in memory. This is done
        to minimise risk of dataleak through memory related attacks.

        * To get the decrypted form of pw for each record, the interface
          get_pw_record() needs to be called with the appropriate index

        Args:      N/A
        
        Returns:   N/A

        Exception: N/A
        """

        if (self.__encryption_key_1 == ''):
            raise NoKeyFoundException('__pre_encrypt_records(): ' + \
                    'Key needs to be generated first (encryption_key_1 ' + \
                    'not found)')
        elif (len(self.__record_list) == 0):
            return

        if (self.__encryption_key_2 == ''):
            self.generate_new_key_2()

        fernet_handler = Fernet(self.__encryption_key_2)

        for i in range(0, len(self.__record_list)):

            r = self.__record_list[i]
            pw = bytes(r.get_password(), 'utf-8')
            pw = fernet_handler.encrypt(pw).decode('utf-8')
            r.set_password(pw)
            self.__record_list[i] = r


    def generate_new_key_2(self, key='', update_enc_key=True):

        if (self.__salt_2 == ''):
            self.__salt_2 = os.urandom(self.__salt_length) 

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), \
                length=32, salt=self.__salt_2, iterations=1000000)

        _key = ''

        if (key == ''):
            _key = self.__encryption_key_1
        else:
            _key = key

        if (type(_key) != bytes):
            _key = bytes(_key, 'utf-8')

        if (update_enc_key):
            self.__encryption_key_2 = base64.urlsafe_b64encode(kdf.derive(_key))
        else:
            return base64.urlsafe_b64encode(kdf.derive(_key))


    def __migrate_all_pw_from_old_to_new_key(self, old_key='', new_key=''):

        if (old_key == '' or new_key == ''):
            raise InvalidParameterException('migrate_all_pw_from_old_to_new_key():' + \
                ' encryption keys cannot be empty')

        for i in range(len(self.__record_list)):

            pw = self.get_pw_of_index(i, old_key)

            self.__record_list[i].set_password(self.__encrypt_pw(pw, new_key))


    def __encrypt_database_in_memory(self):

        """
        Encrypts database with key and updates internal variable 
        (self.__encryption_key_1) which stores an encrypted
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

        fernet_handler = Fernet(self.__encryption_key_1)
        encrypted_data = fernet_handler.encrypt(data_bytes)

        self.__encrypted_data = encrypted_data


    def write_encrypted_database(self, filename='data.bin'):

        """
        Responsible for encryption of database

        Args:       The name of the regular encryted file. (Default: 'data.bin')

        Returns:    Boolean value indicating whether the operation succeeded or not.

        Exceptions: 1) NoKeyFoundException() if a new key hasn't been generated
                    2) SaltNotGeneratedException() if by mistake one of the salt
                       (used for pre-encryption of password field) was not generated
                    3) IOError(): If an error occured while reading/writing file

        """

        if (self.__encryption_key_1 == '' or self.__salt_1 == '' or \
                self.__encryption_key_2 == '' or self.__salt_2 == ''):
            # This exception like won't occur as frontend will make sure that
            # the key has been initialized first before calling this function, 
            # but it is kept as a safety measure in case this library 
            # is used by other programs or for testing
            raise NoKeyFoundException('Need to initialize key first, ' + \
                    'call generate_new_key() function')

        if (len(self.__record_list) != 0):

            #---------------------------------------#
            #          Writing regular file         #
            #---------------------------------------#
            # 03 | hash | salt-1 | salt-2 | data    #
            #---------------------------------------#

            file_type = '03'

            self.__encrypt_database_in_memory()

            encrypted_hash = self.generate_hash((bytes(file_type, 'utf-8') + \
                    self.__salt_1 + self.__salt_2 + self.__encrypted_data))

            try:
                with open(filename, 'wb') as file_handler:
                    file_handler.write(bytes(file_type, 'utf-8'))
                    file_handler.write(bytes(encrypted_hash, 'utf-8'))
                    file_handler.write(self.__salt_1)
                    file_handler.write(self.__salt_2)
                    file_handler.write(self.__encrypted_data)
                    return True
            except IOError:
                print("write_encrypted_database(): error#03 occured while writing database")
                return False

        else: 

            #---------------------------------------------#
            #   Writing hash & salt with empty database   #
            #---------------------------------------------#
            # 04 | hash | salt-1 | salt-2                 #
            #---------------------------------------------#

            file_type = '04' 

            encrypted_hash = self.generate_hash((bytes(file_type, 'utf-8') + \
                    self.__salt_1 + self.__salt_2))

            try:
                with open(filename, 'wb') as file_handler:
                    file_handler.write(bytes(str(file_type), 'utf-8'))
                    file_handler.write(bytes(encrypted_hash, 'utf-8'))
                    file_handler.write(self.__salt_1)
                    file_handler.write(self.__salt_2)
                    return True
            except IOError:
                print("write_encrypted_database(): error#04 occured while writing database")
                return False


    def load_database(self, filename='data.bin', password='',
            override_integrity_check=False, path_to_keyfile=''):
        
        """
        Attempts to load database from specified path (filename)

        Args: Specify path to the database 

        Returns: Boolean value indicating success / failure

        Exceptions:

            1) InvalidParameterException() if any of
                the input parameters are missing or invalid
            2) DatabaseFileNotFoundException() if the
               database file doesn't exist & load_database()
               function is called.
            3) IOError() if an error occurs while reading file
            4) IncorrectPasswordException() if password
               for decrypting data is not correct
            5) UnsupportedFileFormatException() if an older or 
               unsupported format was detected
            6) IntegrityCheckFailedException() if the calculated
               hash of the encrypted data doesn't match with
               the one stored
            7) PWDecryptionFailedException() if decryption 
               of encrypted password (stored in memory)
               failed due to incorrect key
                      
        """

        ## Debug
        #st1 = time()

        ## Some of the parameter checks are not required as it is handled
        ## by frontend, but its still placed in here as a safety measure 
        ## in case this library is used by other programs.

        if (password == ''):
            raise InvalidParameterException("load_database(): key parameter cannot be empty")

        if (os.path.isfile(filename) == False): 
            raise DatabaseFileNotFoundException("load_database(): File: %s does't exist" % filename)

        file_type = ''

        try:
            fh = open(filename, 'rb')

            file_type = fh.read(2)

        except IOError:
            fh.close()
            raise IOError("load_database(): error#01 occured while reading database")

        msg = "\nUnsupported file format detected!\n\n" + \
                "1) Run '--export csv-brief data.csv' on older version of pwmgr < 2.0\n" + \
                "2) Backup & remove ~/.config/pwmgr/data.bin\n" + \
                "3) Run '--import data.csv' on latest version of pwmgr >= 2.0\n"

        if (file_type.decode('utf-8') == '01'):
            raise UnsupportedFileFormatException(msg)

        elif (file_type.decode('utf-8') == '02'):
            raise UnsupportedFileFormatException(msg)

        elif (file_type.decode('utf-8') == '03'):

            #---------------------------------------#
            # File with data                        #
            #---------------------------------------#
            # 03 | hash | salt-1 | salt-2 | data    #
            #---------------------------------------#

            try:
                loaded_hash = fh.read(self.__hash_length)
                self.__salt_1 = fh.read(self.__salt_length)
                self.__salt_2 = fh.read(self.__salt_length)
                self.__encrypted_data = fh.read()
                fh.close()
            except IOError:
                fh.close()
                raise IOError("load_database(): error#02 occured while reading database")

            generated_hash = self.generate_hash((file_type + self.__salt_1 + self.__salt_2 + self.__encrypted_data))

            if (loaded_hash.decode('utf-8') != generated_hash):

                if (override_integrity_check):
                    pass
                else:
                    raise IntegrityCheckFailedException()

            self.generate_new_key(password, False, True, path_to_keyfile)

            fernet_handler = Fernet(self.__encryption_key_1)

            try:
                decrypted = (fernet_handler.decrypt(self.__encrypted_data)).decode('utf-8')
            except InvalidToken:
                raise IncorrectPasswordException()

            ## Debug
            #st4 = time()
            #print("decrypted data(), time taken: %.3fs" % (st4-st3))

            self.__master_password = password

            data_list = self.read_csv_in_memory(decrypted)

            ## Debug
            #st5 = time()
            #print("read_csv_in_memory(), time taken: %.3fs" % (st5-st4))

            self.convert_csvlist_to_record(data_list, False, True)

            ## Debug
            #st6 = time()
            #print("convert_csvlist_to_record(), time taken: %.3fs" % (st6-st5))
            #print("Total time taken: %.3fs" % (st6-st1))

            ## Checking whether we can decrypt pw field
            if (len(self.__record_list) != 0):
                try:
                    self.get_pw_of_index(0)
                except (IncorrectPasswordException):
                    raise PWDecryptionFailedException()

            return True

        elif (file_type.decode('utf-8') == '04'):

            #---------------------------------------#
            # Empty database                        #
            #---------------------------------------#
            # 04 | hash | salt-1 | salt-2           #
            #---------------------------------------#

            try:
                loaded_hash = fh.read(self.__hash_length)
                self.__salt_1 = fh.read(self.__salt_length)
                self.__salt_2 = fh.read(self.__salt_length)
                fh.close()
            except IOError:
                fh.close()
                raise IOError("load_database(): error#03 occured while reading database")
            
            generated_hash = self.generate_hash((file_type + self.__salt_1 + self.__salt_2))

            if (loaded_hash.decode('utf-8') != generated_hash):

                if (override_integrity_check):
                    pass
                else:
                    raise IntegrityCheckFailedException()

            self.generate_new_key(password, False, True, path_to_keyfile)

            return True

        else:

            try:
                fh.close()
            except IOError:
                pass
            
            raise UnsupportedFileFormatException()


    def load_database_key(self, filename='data.bin', key='', override_integrity_check=False):
        
        """
        Attempts to load database from specified path (filename) using key

        Args: Specify path to the database 

        Returns: Boolean value indicating success / failure

        Exceptions:

            1) InvalidParameterException() if any of
                the input parameters are missing or invalid
            2) DatabaseFileNotFoundException() if the
               database file doesn't exist & load_database()
               function is called.
            3) IOError() if an error occurs while reading file
            4) IncorrectPasswordException() if password
               for decrypting data is not correct
            5) UnsupportedFileFormatException() if an older or 
               unsupported format was detected
            6) IntegrityCheckFailedException() if the calculated
               hash of the encrypted data doesn't match with
               the one stored
            7) PWDecryptionFailedException() if decryption 
               of encrypted password (stored in memory)
               failed due to incorrect key
                      
        """

        ## Some of the parameter checks are not required as it is handled
        ## by frontend, but its still placed in here as a safety measure 
        ## in case this library is used by other programs.

        ## Debug
        #st1 = time()

        if (key == ''):
            raise InvalidParameterException("load_database_key(): key parameter cannot be empty")
        else:
            self.__encryption_key_1 = key

        if (os.path.isfile(filename) == False): 
            raise DatabaseFileNotFoundException("load_database_key(): File: %s does't exist" % filename)

        try:
            fh = open(filename, 'rb')

            file_type = fh.read(2)

        except IOError:
            fh.close()
            raise IOError("load_database_key(): error#01 occured while reading database")

        msg = "\nUnsupported file format detected!\n\n" + \
                "1) Run '--export csv-brief data.csv' on older version of pwmgr < 2.0\n" + \
                "2) Backup & remove ~/.config/pwmgr/data.bin\n" + \
                "3) Run '--import data.csv' on latest version of pwmgr >= 2.0\n"

        if (file_type.decode('utf-8') == '01'):
            raise UnsupportedFileFormatException(msg)

        elif (file_type.decode('utf-8') == '02'):
            raise UnsupportedFileFormatException(msg)

        elif (file_type.decode('utf-8') == '03'):

            #---------------------------------------#
            # Regular file with data                #
            #---------------------------------------#
            # 03 | hash | salt-1 | salt-2 | data    #
            #---------------------------------------#

            try:
                loaded_hash = fh.read(self.__hash_length)
                self.__salt_1 = fh.read(self.__salt_length)
                self.__salt_2 = fh.read(self.__salt_length)
                self.__encrypted_data = fh.read()
                fh.close()

            except IOError:
                fh.close()
                raise IOError("load_database_key(): error#02 occured while reading database")

            generated_hash = self.generate_hash((file_type + self.__salt_1 + self.__salt_2 + self.__encrypted_data))

            if (loaded_hash.decode('utf-8') != generated_hash):

                if (override_integrity_check):
                    pass
                else:
                    raise IntegrityCheckFailedException()

            self.generate_new_key_2()

            fernet_handler = Fernet(self.__encryption_key_1)

            try:
                decrypted = (fernet_handler.decrypt(self.__encrypted_data)).decode('utf-8')
            except InvalidToken:
                raise IncorrectKeyException()

            ## Debug
            #st3 = time()
            #print("decrypted data, time taken: %.3fs" % (st3-st2))

            data_list = self.read_csv_in_memory(decrypted)

            ## Debug
            #st4 = time()
            #print("read_csv_in_memory(), time taken: %.3fs" % (st4-st3))

            self.convert_csvlist_to_record(data_list, False, True)

            if (len(self.__record_list) != 0):
                try:
                    self.get_pw_of_index(0)
                except (IncorrectPasswordException):
                    raise PWDecryptionFailedException()

            ## Debug
            #st5 = time()
            #print("convert_csvlist_to_record(), time taken: %.3fs" % (st5-st4))
            #print("Total time taken: %.3fs" % (st5-st1))

            return True

        elif (file_type.decode('utf-8') == '04'):

            #---------------------------------------#
            # Empty database                        #
            #---------------------------------------#
            # 04 | hash | salt-1 | salt-2           #
            #---------------------------------------#

            try:
                loaded_hash = fh.read(self.__hash_length)
                self.__salt_1 = fh.read(self.__salt_length)
                self.__salt_2 = fh.read(self.__salt_length)
                fh.close()
            except IOError:
                fh.close()
                raise IOError("load_database_key(): error#03 occured while reading database")
            
            generated_hash = self.generate_hash(file_type + self.__salt_1 + self.__salt_2)

            if (loaded_hash.decode('utf-8') != generated_hash):

                if (override_integrity_check):
                    pass
                else:
                    raise IntegrityCheckFailedException()

            self.generate_new_key_2()

            return True

        else:

            try:
                fh.close()
            except IOError:
                pass
            
            raise UnsupportedFileFormatException()



    #===========================================================================
    #                       Password Auditing Functions                        #
    #===========================================================================

    # [x] Tested
    def audit_security(self):

        self.audit_record_pw_age()
        self.audit_record_pw_reuse()
        self.audit_record_pw_complexity()
        self.rate_overall_security()


    # [x] Tested
    def sort_security_rating(self, sort_ascending=True):

        """
        Sorts records by security ratings in ascending or descending order based 
        on the paramter that has been set. Need to call audit_security() first before 
        calling this function.

        Ratings: 

        (14-15) : Outstanding
        (12-13) : Good
        (10-11) : Average
        (7-9)   : Poor
        (0-6)   : Critical
        
        Returns:  List of record indexes sorted in (ascending/descending order) 
                  based on overall security rating

        """

        if (len(self.__record_list) == 0):
            return []

        sorted_indexes = []

        # Removing unavailable ratings
        for i in range(0, len(self.__record_list)):

            if (self.__record_list[i].get_security_rating() != ''):
                sorted_indexes.append(i)

        if (sort_ascending):

            while (True):

                index_moved = False

                for i in range(0, len(sorted_indexes)-1):

                    rt1 = int(self.__record_list[sorted_indexes[i]].get_security_rating())
                    rt2 = int(self.__record_list[sorted_indexes[i+1]].get_security_rating())
 
                    if (rt1 > rt2):
                        tmp_index = sorted_indexes[i+1]
                        sorted_indexes[i+1] = sorted_indexes[i]
                        sorted_indexes[i] = tmp_index
                        index_moved = True

                if (not index_moved):
                    break
        else:

            while (True):

                index_moved = False

                for i in range(0, len(sorted_indexes)-1):
                    rt1 = int(self.__record_list[sorted_indexes[i]].get_security_rating())
                    rt2 = int(self.__record_list[sorted_indexes[i+1]].get_security_rating())
 
                    if (rt1 < rt2):
                        tmp_index = sorted_indexes[i+1]
                        sorted_indexes[i+1] = sorted_indexes[i]
                        sorted_indexes[i] = tmp_index
                        index_moved = True

                if (not index_moved):
                    break

        return sorted_indexes
        

    # [x] Tested, Initial testing done. More testing needed
    def rate_overall_security(self):

        """
        Rates overall security posture of all records in database

            Ratings: 

            pw_age (3):          'n' =  3, 'o' =  2, 'r' = -1
            pw_reuse (6):        '0' =  6, '1' =  0
            pw_complexity (6):   'e' =  6, 'g' =  4, 'a' = 2, 'w' = -2, 'u' = -4
            ___________________________________________________________________________
            Total score (15):    max = 15, min = 0 (negative values are set to 0)

        """

        if (len(self.__record_list) == 0):
            return []

        for i in range(len(self.__record_list)):

            r = self.__record_list[i]

            rating_age = 0
            rating_reuse = 0
            rating_complexity = 0
            rating_total = 0

            pw_age = r.get_pw_age()

            if (pw_age == 'n'):
                rating_age = 3
            elif (pw_age == 'o'):
                rating_age = 2
            elif (pw_age == 'r'):
                rating_age = -1
            else: # Skipping rating if there's errors with last_modified attribute
                continue

            pw_reuse = r.get_pw_reuse()

            if (pw_reuse == '0'):
                rating_reuse = 6
            elif (pw_age == '1'):
                rating_reuse = 0

            #pw_complexity (6):   'e' =  6, 'g' =  4, 'a' = 2, 'w' = -2, 'u' = -4

            pw_complexity = r.get_pw_complexity()

            if (pw_complexity == 'e'):
                rating_complexity = 6
            elif (pw_complexity == 'g'):
                rating_complexity = 4
            elif (pw_complexity == 'a'):
                rating_complexity = 2
            elif (pw_complexity == 'w'):
                rating_complexity = -2
            elif (pw_complexity == 'u'):
                rating_complexity = -4

            rating_total = rating_age + rating_reuse + rating_complexity

            if (rating_total < 0):
                rating_total = 0

            rating_str = '%d' % (rating_total)

            self.__record_list[i].set_security_rating(rating_str)


    # [x] Tested
    def audit_record_pw_age(self):

        """
        Audits records to check if they exceed the desired password age,
            & stores audit information within each record

        Returns: 5 lists 
                 
                 1) List of record indexes whose last modified value
                    is blank / not updated.
                    (This could be because after importing from another 
                    password manager datebase, the user didn't change 
                    the password.)

                 2) List of record indexes whose last modified value
                    is probably incorrect as it points to somewhere 
                    in the future

                 3) List of record indexes whose password age 
                    is < 6 months & don't need to be changed

                 4) List of record indexes whose password age
                    is >= 6 months to < 1 year old. 

                 5) List of record indexes whose password age
                    is >= 1 year and the user would be recommended
                    to change it.

        """

        lm_not_updated = []
        lm_err = []
        pw_reset_not_needed = []
        pw_reset_optional = []
        pw_reset_recommended = []

        dt_now = DateTime.today()

        days_this_year = 365
        half_year = 181

        if (self.is_year_leap_year(dt_now.year)):
            days_this_year = 366

        for i in range(len(self.__record_list)):

            lm = self.__record_list[i].get_last_modified()

            if (lm == ''):
                lm_not_updated.append(i)
                continue

            date = lm.split(' ')[0]
            time = lm.split(' ')[1]

            day = int(date.split('-')[0])
            month = int(date.split('-')[1])
            yr = int(date.split('-')[2])

            hr = int(time.split(':')[0])
            min = int(time.split(':')[1])

            dt_past = DateTime(yr, month, day, hr, min)

            if (dt_past > dt_now):
                lm_err.append(i)
                continue

            num_days = (dt_now-dt_past).days

            if (num_days < half_year):
                pw_reset_not_needed.append(i)
            elif (num_days < days_this_year):
                pw_reset_optional.append(i)
            else:
                pw_reset_recommended.append(i)

        for i in pw_reset_not_needed:
            self.__record_list[i].set_pw_age('n')
        
        for i in pw_reset_optional:
            self.__record_list[i].set_pw_age('o')

        for i in pw_reset_recommended:
            self.__record_list[i].set_pw_age('r')

        return lm_not_updated, lm_err, \
                pw_reset_not_needed, pw_reset_optional, \
                pw_reset_recommended


    def is_year_leap_year(self, y=0):

        if (y <= 0):
            return False

        if (y % 4 != 0):
            return False
        else:

            if (y % 100 != 0):
                return True
            else:

                if (y % 400 == 0):
                    return True
                
                return False


    # [x] Tested
    def audit_record_pw_reuse(self):

        """
        Audits records to see if any of them reuse the same password 
            & stores audit information within each record
    
        Returns: List of indexes that reuse the same password

        """

        rec_len = len(self.__record_list)

        if (rec_len == 0):
            return []
        elif (rec_len == 1):
            self.__record_list[0].set_pw_reuse('0')

        reuse_pass_recs = []

        for i in range(0, rec_len):
            
            if (i in reuse_pass_recs):
                continue

            _pw1 = self.__record_list[i].get_password()

            match = False

            for j in range(0, rec_len):
                if (i==0 or j==i or j in reuse_pass_recs):
                    continue

                _pw2 = self.__record_list[j].get_password()

                if (_pw1 == _pw2):
                    match = True
                    reuse_pass_recs.append(j)

            if (match and i not in reuse_pass_recs):
                reuse_pass_recs.append(i)

        for index in range(0, rec_len):

            if (index not in reuse_pass_recs):
                self.__record_list[index].set_pw_reuse('0')
            else:
                self.__record_list[index].set_pw_reuse('1')

        return reuse_pass_recs


    # [x] Tested
    def audit_record_pw_complexity(self):

        """
        Audits password complexity of the all records & stores audit information
    
        Returns: None
        """

        if (len(self.__record_list) == 0):
            return

        for i in range(len(self.__record_list)):
            # pw = self.__record_list[i].get_password()

            pw = self.get_pw_of_index(i)
            result = self.audit_pw_complexity(pw)

            if (result == 'u'):
                self.__record_list[i].set_pw_complexity('u')
            elif (result == 'w'):
                self.__record_list[i].set_pw_complexity('w')
            elif (result == 'a'):
                self.__record_list[i].set_pw_complexity('a')
            elif (result == 'g'):
                self.__record_list[i].set_pw_complexity('g')
            elif (result == 'e'):
                self.__record_list[i].set_pw_complexity('e')


    # [x] Tested
    def audit_pw_complexity(self, pw=''):

        """
        Rates password complexity of the input password.
    
        Rating level: 
    
            4 character classes (upper, lower, symbols, digits)
    
            Rating: u,w,a,g,e where u=unsuitable, w=weak, a=avg, g=good, e=excellent
    
                    Unsuitable: Covers only 1 class
    
                    Weak: Covers 2 classes
    
                    Average: 
                        1) Covers 3 classes
                        2) Length >= 8 characters otherwise downgraded to weak rating
                           if only (1) is met
    
                    Good:
                        1) Covers all 4 classes
                        2) Length >= 10 characters, otherwise downgraded to average rating 
                           if only (1,2) are met
    
                    Excellent: 
                        1) Covers all 4 classes
                        2) No character belonging to any character class is repeated consecutively
                           e.g: '9W@0KZ9<[#TrS' -> not valid
                                '9W@0kZ9<[#TrS' -> valid
                        3) Length >= 15 characters, otherwise downgraded to good rating 
                           if only (1,2) are met
    
        """
    
        rating = ''
    
        pw_len = len(pw)
    
        n_chr_classes = self.check_num_chr_classes(pw)
    
        if (n_chr_classes == 1):
            return 'u'
        elif (n_chr_classes == 2):
            return 'w'
        elif (n_chr_classes == 3): 
            if (pw_len < 8):
                return 'w'
            else:
                return 'a'
        elif (n_chr_classes == 4):
            if (pw_len < 10):
                return 'a'
            else:
                if (pw_len < 15 or self.check_consecutive_class_chr_repeat(pw)):
                    return 'g'
                else:
                    return 'e'
    
    
    def check_num_chr_classes(self, pw=''):
    
        """
        Returns the number of character classes that are present in a password  
       
        """

        _pw = list(pw)
    
        count_l = 0
        count_s = 0
        count_u = 0
        count_n = 0
    
        for i in range(len(_pw)):
    
            if (_pw[i] in self.__lcase):
                count_l += 1
            elif (_pw[i] in self.__symbols):
                count_s += 1
            elif (_pw[i] in self.__ucase):
                count_u += 1
            elif (_pw[i] in self.__num):
                count_n += 1
            
        count_total = 0
    
        if (count_l != 0):
            count_total += 1
    
        if (count_s != 0):
            count_total += 1
    
        if (count_u != 0):
            count_total += 1

        if (count_n != 0):
            count_total += 1
    
    
        return count_total
    
    
    def check_consecutive_class_chr_repeat(self, pw=''):
    
        """
        Check whether characters belonging to the same class are repeated 
        consecutively in a password
    
        e.g: 'asdfghijkl' -> invalid
             'aSdFgHiJkL' -> valid
    
        Returns: Boolean
    
                 True if found
                 False if not found
        """
    
        if (len(pw) <= 1):
            return False
    
        _pw = list(pw)
    
        chr_p = self.get_chr_class(_pw[0])
    
        for i in range(1, len(pw)):
    
            c = self.get_chr_class(pw[i]) 
    
            if (c == 'l' and chr_p == 'l'):
                return True
            elif (c == 's' and chr_p == 's'):
                return True
            elif (c == 'u' and chr_p == 'u'):
                return True
            elif (c == 'n' and chr_p == 'n'):
                return True
            else:
                chr_p = c
    
        return False
        
    
    def get_chr_class(self, c=''):
    
        """
        Returns the character class of the input character
    
        'l' = lowercase alphabet
        's' = symbols
        'u' = uppercase alphabet
        'n' = numeric
        """
    
        if (len(c) != 1):
            return 
    
        if (c in self.__lcase):
            return 'l'
        elif (c in self.__symbols):
            return 's'
        elif (c in self.__ucase):
            return 'u'
        elif (c in self.__num):
            return 'n'


#===========================================================================
#                   Custom Exception Handling Classes                      #
#===========================================================================

class DatabaseEmptyException(Exception):
    def __init__(self, msg="No record exists"):
        super(DatabaseEmptyException, self).__init__(msg)

class DatabaseFileNotFoundException(Exception):
    def __init__(self, msg="Database file not found"):
        super(DatabaseFileNotFoundException, self).__init__(msg)

class IncorrectKeyException(Exception):
    def __init__(self, msg="Decryption of database failed due to incorrect key"):
        super(IncorrectKeyException, self).__init__(msg)

class IncorrectPasswordException(Exception):
    def __init__(self, msg="Decryption of database failed as password is incorrect"):
        super(IncorrectPasswordException, self).__init__(msg)

class IntegrityCheckFailedException(Exception):
    def __init__(self, msg="Database file potentially corrupted"):
        super(IntegrityCheckFailedException, self).__init__(msg)

class InvalidParameterException(Exception):
    def __init__(self, msg="The input parameter is not valid"):
        super(InvalidParameterException, self).__init__(msg)

class KeyFileInvalidException(Exception):
    def __init__(self, msg="Keyfile is invalid, need to use a minimum of 2048 bit key"):
        super(KeyFileInvalidException, self).__init__(msg)

class NoKeyFoundException(Exception):
    def __init__(self, msg="Key doesn't exist"):
        super(NoKeyFoundException, self).__init__(msg)

class PWDecryptionFailedException(Exception):
    def __init__(self, msg="Decryption of password stored in memory failed due to incorrect key"):
        super(PWDecryptionFailedException, self).__init__(msg)

class SaltNotGeneratedException(Exception):
    def __init__(self, msg="Salt needs to be generated first"):
        super(SaltNotGeneratedException, self).__init__(msg)

class UnsupportedFileFormatException(Exception):
    def __init__(self, msg="Unsupported file format detected"):
        super(UnsupportedFileFormatException, self).__init__(msg)

