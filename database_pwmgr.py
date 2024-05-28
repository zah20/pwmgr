#!/usr/bin/python3
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from hashlib import sha256
import subprocess, ctypes
import sys, os, csv
import base64, math


global __app, __author, __last_updated__, __current_revision__

__app__              = 'Database @PWMGR'
__author__           = 'Zubair Hossain'
__last_updated__     = '07/24/2024'
__current_revision__ = '3.0.1'


"""
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃             Code Index             ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

       Record Class                   47
       ManageRecord                  358

       Database Encryption Mgmt      377
       Database RW                   661
       Database Password Auditing    919
       Database Miscellaneous       1436
       Database Export              1937

       Utility                      2177
       Security Functions           2374
"""


class Record():

    def __init__(self, website='', password='', last_modified=''):

        """
                                Audit Attributes

        pw_age (default: null, str) Determines if a pw change is required

        pw_reuse (default: null, str) Checks whether pw has been reused in another record
            (values: null=unset, '1'=pw reused in another record, '0'=pw not reused)

        pw_complexity (default: null, str) Determines the pw strength

        security_rating (default: null, str) Rates overall security of a record 
            (values: null = unset, range '0'-'15')

        """

        self.__website = website.lower()
        self.__password = password

        if (last_modified == ''):

            self.update_last_modified()

        else:

            reset_date    = False

            test_date_obj = None

            try:
                test_date_obj = datetime.strptime(last_modified, "%d-%m-%Y %H:%M")

                if (test_date_obj >= datetime.now()):
                    reset_date = True

            except (ValueError):
                reset_date = True

            if (reset_date):
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

        s = "Site: %s, Pass: %s, Last Modified: %s" % (self.get_website(), \
                self.get_password_encrypted(), self.get_last_modified())

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
        data = '%s,%s' % (data, self.format_field_csv(self.get_password_encrypted()))
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

        self.__last_modified = datetime.today().strftime("%d-%m-%Y %H:%M")


    def get_group(self):
        return self.__group

    def get_website(self):
        return self.__website

    def get_password_encrypted(self):
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

        if (self.__two_factor == '1'):
            return 'Enabled'
        else:
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

        self.__salt_length       = 32
        self.__record_list       = []
        self.__hash_length       = 64 # SHA-256

        self.__master_password   = ''

        self.__encryption_key_1  = ''
        self.__encryption_key_2  = ''
        self.__salt_1            = ''
        self.__salt_2            = ''

        self.__symbols           = "[!@#$%&,./<;()|:^{}]?-_*'+=>"
        self.__ucase             = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.__num               = "0123456789"
        self.__lcase             = "abcdefghijklmnopqrstuvwxyz"


    '''
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃   Database Encryption Management                                   ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    '''

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


    def get_pw_of_index(self, index, enc_key=''):

        """
        Plain text pw of given index

        * enc_key is not required unless we're migrating database 
          from old key to a new key
        """

        fernet_handler = ''

        if (enc_key == ''):
            fernet_handler = Fernet(self.__encryption_key_2)
        else:
            fernet_handler = Fernet(enc_key)

        try:
            return fernet_handler.decrypt(bytes(self.__record_list[index].get_password_encrypted(), \
                    'utf-8')).decode('utf-8')

        except (InvalidToken, UnicodeDecodeError):
            raise IncorrectPasswordException('Unable to decrypt pw, database possibly corrupted')


    def get_pw_of_index_with_sec_mem(self, index, enc_key=''):

        """
        Returns an object of AllocateSecureMemory() function, 
               which can wipe off sensitive information after operation
        """

        fernet_handler = ''

        if (enc_key == ''):
            fernet_handler = Fernet(self.__encryption_key_2)
        else:
            fernet_handler = Fernet(enc_key)

        try:
            return AllocateSecureMemory(fernet_handler.decrypt(bytes( \
                    self.__record_list[index].get_password_encrypted(), 'utf-8')).decode('utf-8'))

        except (InvalidToken, UnicodeDecodeError):
            raise IncorrectPasswordException('Unable to decrypt pw, database possibly corrupted')


    def generate_new_key(self, \
            password='', generate_salt=True,
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

        Exceptions: FileNotFoundError
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

        else:

            if (not os.path.isfile(path_to_keyfile)):
                raise FileNotFoundError('generate_new_key(): keyfile not found')

            kf_data = ''

            output = keyfile_load(path_to_keyfile)

            if (not output[0] or len(output[1]) < 1000):
                raise KeyFileInvalidException()
            else:
                kf_data = bytes(output[1], 'utf-8')

            kf_data = kf_data + bytes(password, 'utf-8')

            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), \
                    length=32, salt=self.__salt_1, iterations=1000000)

            key = base64.urlsafe_b64encode(kdf.derive(kf_data))

        if (update_enc_key):
            self.__encryption_key_1 = key
            self.__generate_new_key_2()
        else:
            return key.decode('utf-8')


    def __generate_new_key_2(self):

        if (self.__encryption_key_1 == ''):
            raise InvalidParameterException('__generate_new_key_2(): ' + \
                                            'key 1 needs to be generated first, ' + \
                                            'call the generate_new_key() function')
        if (self.__salt_2 == ''):
            self.__salt_2 = os.urandom(self.__salt_length)

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), \
                length=32, salt=self.__salt_2, iterations=1000000)

        _key = self.__encryption_key_1

        self.__encryption_key_2 = base64.urlsafe_b64encode(kdf.derive(_key))


    def change_password(self, new_password=''):

        """
        Generates new salt and derives a new key based on the 
        new password. Re-encrypts database with new key.

        Args:    The new password to use to encrypt the database

        Returns: Boolean value indicating success / failure
        """

        old_key_2 = self.__encryption_key_2

        self.__master_password = new_password
        self.generate_new_key(new_password, generate_salt=True, update_enc_key=True)

        self.__migrate_all_pw_from_old_to_new_key(old_key_2, self.__encryption_key_2)


    def use_keyfile(self, pw, path_to_keyfile=''):

        old_key_2 = self.__encryption_key_2

        self.__master_password = pw
        self.generate_new_key(pw, True, True, path_to_keyfile)

        self.__migrate_all_pw_from_old_to_new_key(old_key_2, self.__encryption_key_2)


    def remove_keyfile(self, pw):

        old_key_2 = self.__encryption_key_2

        self.__master_password = pw
        self.generate_new_key(pw, True, True, '')

        self.__migrate_all_pw_from_old_to_new_key(old_key_2, self.__encryption_key_2)


    def generate_hash(self, input_str):

        """
        Returns a sha256 hash digest value of the input string

        Args:       A byte encoded string

        Returns:    (str)
        """

        if (not (type(input_str) == bytes or type(input_str) == str)):
            raise TypeError('generate_hash(): first parameter needs to be of type bytes or str')

        if (type(input_str) == str):
            return sha256(bytes(input_str, 'utf-8')).hexdigest()
        else:
            return sha256(input_str).hexdigest()


    def __migrate_all_pw_from_old_to_new_key(self, old_key='', new_key=''):

        if (old_key == '' or new_key == ''):
            raise InvalidParameterException('migrate_all_pw_from_old_to_new_key():' + \
                ' encryption keys cannot be empty')

        for i in range(len(self.__record_list)):

            pw = self.get_pw_of_index(i, old_key)

            self.__record_list[i].set_password(self.__encrypt_pw(pw, new_key))


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

        return fernet_handler.encrypt(bytes(pw, 'utf-8')).decode()


    def __encrypt_database_in_memory(self):

        """
        Encrypts the entire database

        Used by: write_encrypted_database()
        """

        data = self.format_csv(include_header=False)

        output_str = ''

        for item in data: 
            output_str += item 

        fernet_handler = Fernet(self.__encryption_key_1)

        return fernet_handler.encrypt(bytes(output_str, 'utf-8'))


    '''
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃   Database Read / Write                                            ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    '''

    def write_encrypted_database(self, filename='data.enc'):

        """
        Responsible for encryption of database

        Args:       The name of the regular encryted file. (Default: 'data.enc')

        Returns:    Boolean value indicating whether the operation succeeded or not.

        Exceptions:

         1) NoKeyFoundException if a new key hasn't been generated
         2) IOError If an error occured while reading/writing file

        Notes:

              06/19/2024:

                  * Original file format had 'PWMGR' flag, which was used to identify the file format, 
                         but down the line it got hacked & removed, that has now been fixed.
        """

        if (self.__encryption_key_1 == '' or self.__salt_1 == '' or \
                self.__encryption_key_2 == '' or self.__salt_2 == ''):

            # This exception like won't occur as frontend will make sure that
            # the key has been initialized first before calling this function, 
            # but it is kept as a safety measure in case this library 
            # is used by other programs or for testing
            raise NoKeyFoundException('Need to initialize key first, ' + \
                    'call generate_new_key() function')

        #-----------------------------------------------#  #-----------------------------------------------# 
        # File without data                             #  # File with data                                #
        #-----------------------------------------------#  #-----------------------------------------------#
        # PWMGR | 00 | hash | salt-1 | salt-2           #  # PWMGR | 01 | hash | salt-1 | salt-2 | data    #
        #-----------------------------------------------#  #-----------------------------------------------#

        format_name    = 'PWMGR'
        format_version = ''

        file_hash      = ''

        if (len(self.__record_list) == 0):

            format_version = '00'
            file_hash = self.generate_hash(bytes(format_name, 'utf-8') + \
                                           bytes(format_version, 'utf-8') + \
                                                 self.__salt_1 + \
                                                 self.__salt_2)
        else:

            format_version = '01'

            data           =  self.__encrypt_database_in_memory()

            file_hash = self.generate_hash(bytes(format_name, 'utf-8') + \
                                           bytes(format_version, 'utf-8') + \
                                                 self.__salt_1 + \
                                                 self.__salt_2 + \
                                                 data)
        try:

            with open(filename, 'wb') as fh:
                fh.write(bytes(format_name, 'utf-8'))
                fh.write(bytes(format_version, 'utf-8'))
                fh.write(bytes(file_hash, 'utf-8'))
                fh.write(self.__salt_1)
                fh.write(self.__salt_2)

                if (format_version == '01'):
                    fh.write(data)

        except IOError:
            print("write_encrypted_database(): error#1 occured while writing database")
            return False

        return True


    def load_database(self, filename='data.enc', password='', \
                            override_integrity_check=False,   \
                            path_to_keyfile='',               \
                            load_key_from_keyring=False,      \
                            enc_key=''):

        """

        Attempts to load database from specified path (filename)

        Args: Specify path to the database

        Returns: Boolean value indicating success / failure

        Exceptions:

         1) UnsupportedFileFormatException    File format is not supported

         2) IntegrityCheckFailedException     Calculated hash is incorrect

         3) IncorrectPasswordException        Data decryption failed

         4) InvalidParameterException         Input parameters are incorrect

         5) DataCorruptedException            Decoding of unicode characters failed

        """

        ## Some of the parameter checks are not required as it is handled
        ## by frontend, but its still placed in here as a safety measure 
        ## in case this library is used by other programs.

        if (password == '' and load_key_from_keyring == False):
            raise InvalidParameterException("load_database(): Password parameter cannot be empty")
        elif (load_key_from_keyring == True and enc_key == ''):
            raise InvalidParameterException("load_database(): Encryption key cannot be empty")
        elif (not os.path.isfile(filename)):
            raise InvalidParameterException("load_database(): Database file '%s' does not exist" % filename)

        fh = open(filename, 'rb')

        format_name          = 'PWMGR'
        format_name_bytes    = ''

        format_version       = ''
        format_version_bytes = ''

        try:
            # 'PWMGR'
            format_name_bytes = fh.read(5)

            # '00' / '01'
            format_version_bytes = fh.read(2)

        except IOError:
            fh.close()
            raise DataCorruptedException("load_database(): IO error occured " + \
                                         "while reading database (error#1)")

        if (format_name_bytes == '' or format_version_bytes == ''):
            raise UnsupportedFileFormatException("load_database(): Format is not recognized (error#2)")

        output1 = decode_unicode_str_safely(format_name_bytes)
        output2 = decode_unicode_str_safely(format_version_bytes)

        if (not (output1[0] and output1[1] == format_name)):
            fh.close()
            raise UnsupportedFileFormatException("load_database(): Format is not recognized (error#3)")


        if (output2[0] and output2[1] in ['00','01'] ):

            format_version = output2[1]

        else:

            fh.close()
            raise UnsupportedFileFormatException("load_database(): Format is not recognized (error#4)")

        loaded_hash = ''

        try:
            loaded_hash   = fh.read(self.__hash_length)
            self.__salt_1 = fh.read(self.__salt_length)
            self.__salt_2 = fh.read(self.__salt_length)
        except IOError:
            fh.close()
            raise DataCorruptedException("load_database(): IO error occured " + \
                                         "while reading database (error#5)")

        if (loaded_hash == '' or self.__salt_1 == '' or self.__salt_2 == ''):
            fh.close()
            raise UnsupportedFileFormatException("load_database(): Format is not recognized (error#6)")


        #-----------------------------------------------#  #-----------------------------------------------# 
        # File with data                                #  # File without data                             #
        #-----------------------------------------------#  #-----------------------------------------------#
        # PWMGR | 01 | hash | salt-1 | salt-2 | data    #  # PWMGR | 00 | hash | salt-1 | salt-2           #
        #-----------------------------------------------#  #-----------------------------------------------#

        data = ''

        if (format_version == '01'):

            try:
                data = fh.read()
                fh.close()
            except IOError:
                fh.close()
                raise DataCorruptedException("load_database(): IO error occured " + \
                                             "while reading database (error#7)")

            if (data == ''):
                raise UnsupportedFileFormatException("load_database(): Format is not recognized (error#8)")

        if (not override_integrity_check):

            generated_hash = ''

            if (format_version == '01'):
                generated_hash = self.generate_hash(format_name_bytes + format_version_bytes + \
                                                    self.__salt_1 + self.__salt_2 + data)
            else:
                generated_hash = self.generate_hash(format_name_bytes + format_version_bytes + \
                                                    self.__salt_1 + self.__salt_2)

            if (loaded_hash != bytes(generated_hash, 'utf-8')):
                raise IntegrityCheckFailedException('load_database(): Hash mismatch detected (error#9)')

        if (load_key_from_keyring):
            self.__encryption_key_1 = enc_key
            self.__generate_new_key_2()
        else:
            self.generate_new_key(password=password, generate_salt=False, \
                                     update_enc_key=True, path_to_keyfile=path_to_keyfile)

        if (format_version == '01'):

            fernet_handler = Fernet(self.__encryption_key_1)

            try:
                decrypted = fernet_handler.decrypt(data)
            except InvalidToken:
                raise IncorrectPasswordException("load_database(): Password is incorrect (error#10)")

            output = decode_unicode_str_safely(decrypted)

            if (output[0]):
                decrypted = output[1]
            else:
                raise DataCorruptedException("load_database(): IO error occured " + \
                                                 "while reading database (error#11)")

            if (not load_key_from_keyring):
                self.__master_password = password

            self.convert_csvlist_to_record(self.read_csv_in_memory(decrypted), True)

        return True


    '''
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃   Database Password Auditing                                       ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    '''

    def audit_security(self):

        ## Combining pw_reuse & pw_complexity otherwise we'd run into memory enc errors
        ##      due to the way this enc library functions

        self.audit_pw_age_all()
        self.audit_pw_reuse_and_cmp_all()
        self.rate_overall_security()


    # [x] Tested
    def sort_security_rating(self):

        """
        Sorts records by security ratings in ascending or descending order based 
        on the paramter that has been set. Need to call audit_security() first before 
        calling this function.

         Ratings: 

            (15) Superb
            (14) Excellent
         (12-13) Good
         (10-11) Average
           (7-9) Weak
           (0-6) Critical

        Returns:  List of record indexes sorted in (ascending/descending order) 
                  based on overall security rating

        """

        if (len(self.__record_list) == 0):
            return []

        sorted_indexes = []

        ## TODO: index,rating list needs to be sorted using optimized sorting method

        # Removing unavailable ratings
        for i in range(0, len(self.__record_list)):
            if (self.__record_list[i].get_security_rating() != ''):
                sorted_indexes.append(i)


        while (True):

            index_moved = False

            for i in range(0, len(sorted_indexes)-1):

                try:
                    rt1 = int(self.__record_list[sorted_indexes[i]].get_security_rating())
                    rt2 = int(self.__record_list[sorted_indexes[i+1]].get_security_rating())
                except ValueError:
                    continue

                if (rt1 > rt2):
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

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                                             Ratings
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

         pw_complexity (6)  's' =  6, 'e' =  5, 'g' =  2, 'a' =  0, 'w' = -3, 'u' = -6
         pw_age        (3)  'n' =  3, 'o' =  1, 'r' = -3, 't' = -5, 'h' = -6
         pw_reuse      (6)  '0' =  6, '1' =  0

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         Total score (15)   max = 15, min = 0 (negative values are set to 0)
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

            (15) Superb
            (14) Excellent
         (12-13) Good
         (10-11) Average
           (7-9) Weak
           (0-6) Critical

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

            # pw_age (3)  'n' =  3, 'o' =  1, 'r' = -3, 't' = -5, 'h' = -6
            if (pw_age == 'n'):
                rating_age = 3
            elif (pw_age == 'o'):
                rating_age = 1
            elif (pw_age == 'r'):
                rating_age = -3
            elif (pw_age == 't'):
                rating_age = -5
            elif (pw_age == 'h'):
                rating_age = -6
            else: # Skipping rating if there's errors with last_modified attribute
                continue

            pw_reuse = r.get_pw_reuse()

            # pw_reuse (6)  '0' =  6, '1' = 0
            if (pw_reuse == '0'):
                rating_reuse = 6
            elif (pw_age == '1'):
                rating_reuse = 0

            # pw_complexity (6)  's' =  6, 'e' =  5, 'g' =  2, 'a' =  0, 'w' = -3, 'u' = -6
            pw_complexity = r.get_pw_complexity()

            if (pw_complexity == 's'):
                rating_complexity = 6
            elif (pw_complexity == 'e'):
                rating_complexity = 5
            elif (pw_complexity == 'g'):
                rating_complexity = 2
            elif (pw_complexity == 'a'):
                rating_complexity = 0
            elif (pw_complexity == 'w'):
                rating_complexity = -3
            elif (pw_complexity == 'u'):
                rating_complexity = -6

            rating_total = rating_age + rating_reuse + rating_complexity

            if (rating_total < 0):
                rating_total = 0

            rating_str = '%d' % (rating_total)

            self.__record_list[i].set_security_rating(rating_str)


    # [x] Tested
    def audit_pw_age_all(self):

        """
        Audits records to check if they exceed the desired password age,
            & stores audit information within each record

        Returns: 7 lists

                 Not audited / Error / No Password age information ('e')
                 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                 1) List of record indexes whose last modified value
                    is blank / not updated.
                    (This could be because after importing from another 
                    password manager datebase)

                 2) List of record indexes whose last modified value
                    is probably incorrect as it points to somewhere 
                    in the future


                 Audited attributes ('n', 'o', 'r', 't', 'h')
                 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                 3) Password age is < 6 months & don't need to be changed ('n')

                 4) Password age is >= 6 months to < 1 year old ('o')

                 5) Password age is >= 1 year and < 1.5 years.
                    The user would be recommended to change it ('r')

                 6) Password age is 1.5-2 years, change is urgently required ('t')

                 7) Password age is > 2 years, password change is critical
                    for overall security ('h')
        """

        lm_not_updated         =     []
        lm_err                 =     []
        pw_reset_not_needed    =     []
        pw_reset_optional      =     []
        pw_reset_recommended   =     []
        pw_reset_urgent        =     []
        pw_reset_critical      =     []

        for i in range(len(self.__record_list)):

            lm = self.__record_list[i].get_last_modified()

            if (lm == ''):
                lm_not_updated.append(i)
                continue
            else:
                result = self.audit_pw_age_single_record(i)

                if (result == 'e'):
                    lm_err.append(i)
                elif (result == 'n'):
                    pw_reset_not_needed.append(i)
                elif (result == 'o'):
                    pw_reset_optional.append(i)
                elif (result == 'r'):
                    pw_reset_recommended.append(i)
                elif (result == 't'):
                    pw_reset_urgent.append(i)
                elif (result == 'h'):
                    pw_reset_critical.append(i)

        return lm_not_updated, lm_err, pw_reset_not_needed, \
                     pw_reset_optional, pw_reset_recommended, \
                     pw_reset_urgent, pw_reset_critical


    def audit_pw_age_single_record(self, chosen_index=-1):

        """
        Audits records to check if they exceed the desired password age,
            & stores audit information within each record

        * If there's any errors, for example last modified is missing,
            (which probably won't happen) pw_age attribute is set to 'e'

        Returns: A char in the range as show in the chart below

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           pw_age (3) 'n' =  3, 'o' =  1, 'r' = -2, 't' = -4, 's' = -6, 'e' = n/a
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                                   n =          #days < 0.5 yr
                                   o = 0.5 yr < #days < 1 yr
                                   r =   1 yr < #days < 1.5 yr
                                   t = 1.5 yr < #days < 2 yr
                                   h =   2 yr < #days
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """

        if (chosen_index == -1):
            raise InvalidParameterException('audit_pw_age_single_record(): Index parameter cannot be empty')

        day_today = datetime.today()

        days_this_year = 365
        half_year = 180

        if (self.is_year_leap_year(day_today.year)):
            days_this_year = 366

        # 1 < 1yr+ < 1.5
        days_1_yr_plus = days_this_year + 180

        days_2_yr = (days_this_year * 2)

        lm = self.__record_list[chosen_index].get_last_modified()

        if (lm == ''):
            self.__record_list[i].set_pw_age('e')
            return

        date = lm.split(' ')[0]
        time = lm.split(' ')[1]

        day = int(date.split('-')[0])
        month = int(date.split('-')[1])
        yr = int(date.split('-')[2])

        hr = int(time.split(':')[0])
        minute = int(time.split(':')[1])

        days_of_past = datetime(yr, month, day, hr, minute)

        '''
            n =          #days < 0.5 yr
            o = 0.5 yr < #days < 1 yr
            r =   1 yr < #days < 1.5 yr
            t = 1.5 yr < #days < 2 yr
            h =   2 yr < #days
        '''

        if (days_of_past > day_today):

            ## 'e' metric is used for errors, usually we won't get this
            self.__record_list[chosen_index].set_pw_age('e')
            return 'e'

        num_days = (day_today-days_of_past).days

        if (num_days < half_year):
            self.__record_list[chosen_index].set_pw_age('n')
            return 'n'
        elif (num_days < days_this_year):
            self.__record_list[chosen_index].set_pw_age('o')
            return 'o'
        elif (num_days < days_1_yr_plus):
            self.__record_list[chosen_index].set_pw_age('r')
            return 'r'
        elif (num_days < days_2_yr):
            self.__record_list[chosen_index].set_pw_age('t')
            return 't'
        else:
            self.__record_list[chosen_index].set_pw_age('h')
            return 'h'


    def is_year_leap_year(self, y=0):

        if (y <= 0):
            return False

        if (y % 4 != 0):
            return False

        else:

            if (y % 100 != 0):
                return True
            elif (y % 400 == 0):
                return True
            else:
                return False


    # [x] Tested
    def audit_pw_reuse_and_cmp_all(self):

        """
        Audits records to see if any of them reuse the same password & the pw complexity

        Returns: None
        """

        rec_len = len(self.__record_list)

        ## PW Reuse Calculations
        if (rec_len == 0):
            return

        reuse_pw_indexes_l = []

        pw_list = []

        for i in range(rec_len):
            pw_list.append(self.get_pw_of_index(i))

        for i in range(0, rec_len):

            if (i in reuse_pw_indexes_l):
                continue

            pw1 = pw_list[i]

            match = False

            for j in range(0, rec_len):

                if (j==i or j in reuse_pw_indexes_l):
                    continue

                pw2 = pw_list[j]

                if (pw1 == pw2):
                    match = True
                    reuse_pw_indexes_l.append(j)

            if (match):
                reuse_pw_indexes_l.append(i)

        reuse_pw_indexes_l = list(set(reuse_pw_indexes_l))

        for i in range(0, rec_len):

            if (i not in reuse_pw_indexes_l):
                self.__record_list[i].set_pw_reuse('0')
            else:
                self.__record_list[i].set_pw_reuse('1')

        ## PW Complexity calculations
        for i in range(0, rec_len):
            self.__record_list[i].set_pw_complexity(self.audit_pw_complexity(pw_list[i]))


    # [x] Tested
    def audit_pw_complexity(self, pw=''):

        """
                             * Rates password complexity of the input password


                                             Rating Metrics:

                             4 character classes (upper, lower, symbols, digits)

              u,w,a,g,e,s where u=unsuitable, w=weak, a=avg, g=good, e=excellent, s=superb


                Unsuitable        Typically length is less than 8 characters


                Weak              This is the recommendation from the 90's which
                                  consists of minimum of 8 characters and mix of
                                  character classes


                Average           This is what is recommended by most password managers


                Good              PW length in the range of 12-14, with a mix of 3 or more classes


                Excellent         This ensures that there's a high probability
                                  that your password will not be part of a wordlist
                                  found in the wild


                Superb            This makes bruteforce style attacks unfeasible
                                  using modern gpu clusters. This is as close to having
                                  full cracking immunity as you can get
        """

        ##                         pw_len, n chr classes, rating

        pw_complexity_rating_l =   {( 8, 1) : 'u', ( 8, 2) : 'u', ( 8, 3) : 'u', ( 8, 4) : 'w', \
                                    ( 9, 1) : 'u', ( 9, 2) : 'u', ( 9, 3) : 'u', ( 9, 4) : 'w', \
                                    (10, 1) : 'u', (10, 2) : 'u', (10, 3) : 'u', (10, 4) : 'w', \
                                    (11, 1) : 'u', (11, 2) : 'w', (11, 3) : 'w', (11, 4) : 'a', \
                                    (12, 1) : 'w', (12, 2) : 'w', (12, 3) : 'a', (12, 4) : 'g', \
                                    (13, 1) : 'w', (13, 2) : 'a', (13, 3) : 'a', (13, 4) : 'g', \
                                    (14, 1) : 'w', (14, 2) : 'a', (14, 3) : 'g', (14, 4) : 'g', \
                                    (15, 1) : 'a', (15, 2) : 'g', (15, 3) : 'g', (15, 4) : 'e', \
                                    (16, 1) : 'a', (16, 2) : 'g', (16, 3) : 'g', (16, 4) : 'e', \
                                    (17, 1) : 'g', (17, 2) : 'g', (17, 3) : 'g', (17, 4) : 'e', \
                                    (18, 1) : 'g', (18, 2) : 'g', (18, 3) : 'e', (18, 4) : 'e', \
                                    (19, 1) : 'g', (19, 2) : 'g', (19, 3) : 'e', (19, 4) : 'e', \
                                    (20, 1) : 'g', (20, 2) : 'g', (20, 3) : 'e', (20, 4) : 'e', \
                                    (21, 1) : 'g', (21, 2) : 'e', (21, 3) : 'e', (21, 4) : 's', \
                                    (22, 1) : 'g', (22, 2) : 'e', (22, 3) : 'e', (22, 4) : 's', \
                                    (23, 1) : 'g', (23, 2) : 'e', (23, 3) : 'e', (23, 4) : 's', \
                                    (24, 1) : 'e', (24, 2) : 'e', (24, 3) : 's', (24, 4) : 's', \
                                    (25, 1) : 'e', (25, 2) : 'e', (25, 3) : 's', (25, 4) : 's', \
                                    (26, 1) : 'e', (26, 2) : 'e', (26, 3) : 's', (26, 4) : 's', \
                                    (27, 1) : 'e', (27, 2) : 's', (27, 3) : 's', (27, 4) : 's', \
                                    (28, 1) : 'e', (28, 2) : 's', (28, 3) : 's', (28, 4) : 's', \
                                    (29, 1) : 'e', (29, 2) : 's', (29, 3) : 's', (29, 4) : 's', \
                                    (30, 1) : 's', (30, 2) : 's', (30, 3) : 's', (30, 4) : 's'}


        pw_len = len(pw)

        n_chr_classes = self.check_num_char_classes(pw)


        if (pw_len < 8):

            return 'u'

        elif (pw_len > 30):

            return 's'

        else:

            return pw_complexity_rating_l.get((pw_len, n_chr_classes))            


    def check_num_char_classes(self, pw=''):

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



    '''
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃   Database Miscellaneous                                           ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    '''

    def validate_index(self, index=None):

        """
        Validates whether index or a list of indexes represents
         record indices in database

        Args:    An int value or a list of integers 
                             OR
                 The list which will be used to validate indexes

        Returns: Boolean value indicating whether index/indexes are valid

        Exception: TypeError is raised if there's a data type mismatch

        """

        if (type(index) == int):
            if (index >= 0 and (index < len(self.__record_list))):
                return True
            else:
                return False

        elif (type(index) == list):

            for i in index:
                if (not (i >= 0 or (i < len(self.__record_list)))):
                    return False

            return True

        else:
            raise TypeError('validate_index(): Needs to be of type int or list')


    def get_number_of_records(self):

        """
        Returns the number of records in database
        """
        return len(self.__record_list)


    def get_record_at_index_with_enc_pw(self, index):

        """
        Provides the record object at the specified index with enc pw

        Args:    index (int)
        Returns: (Record)

        """

        return self.__record_list[index]


    def get_summary(self):

        """
        This is used by the frontend for the search bar.

        Presents a summary of records in database for autocompletion 
        when searching.

        Uses:    get_summary() method in Class @Record()
        Used by: search_bar_show() in @pwmgr

        Args:    N/A

        Returns: A list of strings matching record indexes in database
        """

        if (len(self.__record_list) == 0):
            return []

        l = []

        for i in range(len(self.__record_list)):
            l.append(self.__record_list[i].get_summary())

        return l


    def print_data(self):

        print('Number of records: %d' %len(self.__record_list))

        for i in range(len(self.__record_list)):
            print(self.__record_list[i])


    def add(self, item):

        """
        Adds a Record object, also supports a list of records
        
        Args:    A single Record or a list of Record
        
        Returns: N/A
        """

        if (type(item) == Record):

            _item = item
            _item.set_password(self.__encrypt_pw(item.get_password_encrypted()))

            self.__record_list.append(_item) 

        elif (type(item) == list):

            for record in item:

                _record = record
                _record.set_password(self.__encrypt_pw(record.get_password_encrypted()))

                self.__record_list.append(_record) 

        self.sort()


    def check_duplicate_entry(self, site):

        """
        Searches for duplicate entries & returns boolean value
        indicating whether a duplicate entry exists or not.
        An entry is considered duplicate if the site name along with
        username / email match any existing record in database.

        Args:    Record object

        Returns: Boolean
        """
        result = self.search_website(site, partial_match=False)

        if (len(result) != 0):
            return True
        else:
            return False


    def sort(self):

        self.__sort_by_website()


    def __sort_by_website(self):

        self.__record_list.sort(key=lambda x : x.get_website())


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
        
                    j_dt_obj = datetime(j_year, j_month, j_day, j_hr, j_min)
        
                    i_last = l_mod[i][0].get_last_modified().split(' ')
                    i_date = i_last[0].split('-')
                    i_time = i_last[1].split(':')
        
                    i_day = int(i_date[0])
                    i_month = int(i_date[1])
                    i_year = int(i_date[2])
                    i_hr = int(i_time[0])
                    i_min = int(i_time[1])
        
                    #print('%s/%s/%s %s:%s' % (i_year, i_month, i_day, i_hr, i_min))

                    i_dt_obj = datetime(i_year, i_month, i_day, i_hr, i_min)
        

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
        _pw = self.__encrypt_pw(record_object.get_password_encrypted())
        _record.set_password(_pw)

        self.__record_list[index] = _record

        self.sort()
                

    def update_index_with_sec_mem(self, record_obj, index, sec_mem_handler):

        """
        Update record object at the specified index
        
        Args:    1) An object (Record)
                 2) Index at which the record object will be placed (int)
                 3) Sec mem handler instance which can be used to obtain
                      password for the record
        
        Returns: N/A
        """

        _record = record_obj
        _pw = self.__encrypt_pw(sec_mem_handler.get_str())
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
                if (website.lower() in \
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


    '''
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃   Database Export                                                  ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    '''

    def format_csv(self, include_header=True):

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
            return []

        csv_list = []

        if (include_header):
            header = 'site,pass,last_modified,email,username,group,remark,two_factor,' + \
                    'recovery_email,phone_number,pw_age,pw_reuse,pw_complexity,security_rating\n'
            csv_list.append(header)

        for item in self.__record_list:
            csv_list.append('%s\n' % item.format_csv())

        return csv_list


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


    def convert_csvlist_to_record(self, csv_list=[], used_by_load_database=False):

        """
        Converts all entries in csv formatted list
        to a list of Record objects

        Args:    1) A list of str list
                 2) Boolean value whether this function is called
                    by the database internally (skips certain operations)

        Returns: True if operation succeeds or
                  raises UnsupportedFileFormatException if it fails

        Remarks: We intentionally do not check for duplicates
                 as we assume that the user knows what they're doing.

                 * Called by frontend when user is importing a new csv database

        """

        if (len(csv_list) == 0):
            return

        r_l = len(csv_list[0])

        if (r_l not in [2,3,4,5,10,14]):
            raise UnsupportedFileFormatException('[!] The database format is not supported')


        if (r_l == 2):

            for record in csv_list:

                pw = ''

                if (not used_by_load_database):
                    pw = self.__encrypt_pw(record[1])
                else:
                    pw = record[1]

                record_object = Record(record[0], pw)
                self.__record_list.append(record_object)

        elif (r_l == 3):

            for record in csv_list:

                pw = ''

                if (not used_by_load_database):
                    pw = self.__encrypt_pw(record[1])
                else:
                    pw = record[1]

                record_object = Record(record[0], pw)
                record_object.set_username(record[2])
                self.__record_list.append(record_object)

        elif (r_l == 4):

            for record in csv_list:

                pw = ''

                if (not used_by_load_database):
                    pw = self.__encrypt_pw(record[1])
                else:
                    pw = record[1]

                record_object = Record(record[0], pw)
                record_object.set_username(record[2])
                record_object.set_email(record[3])
                self.__record_list.append(record_object)

        elif (r_l == 5):

            for record in csv_list:

                pw = ''

                if (not used_by_load_database):
                    pw = self.__encrypt_pw(record[1])
                else:
                    pw = record[1]

                record_object = Record(record[0], pw)
                record_object.set_username(record[2])
                record_object.set_email(record[3])
                record_object.set_remark(record[4])
                self.__record_list.append(record_object)

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


        self.sort()
        return True


    ## Optimize code
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

                    r = self.__record_list[i]
                    r.set_password(self.get_pw_of_index(i))

                    data = '%s\n' % (r.format_csv())

                    f.write(data)

        except (IOError):
            return False

        return True


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Utility                                                          ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def run_cmd(cmd=[], verbose=False):

    """
    Executes bash commands on local Linux system
    """

    if (cmd != []):
        process = subprocess.Popen(cmd, shell=True, \
                                   stdout=subprocess.PIPE, \
                                   stderr=subprocess.PIPE)

        stdout,stderr = process.communicate()

        stdout = stdout.decode('utf-8').strip()
        stderr = stderr.decode('utf-8').strip()

        if (verbose == True):
            print(stdout)

        return stdout, stderr, process.returncode


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
                return [False, -1]
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


def decode_unicode_str_safely(input_str=''):

    if (type(input_str) != bytes):
        msg = 'decode_unicode_str_safely(): data type needs to be bytes'
        return InvalidParameterException(msg)

    try:
        return (True, input_str.decode('utf-8'))
    except UnicodeDecodeError:
        return (False, '')


def get_libc_path():

    """
    Returns: success/failure (bool), path (str)
    """
    stdout, _, rc = run_cmd('locate libc.so')

    if (rc == 0):
        path_l = stdout.splitlines()

        for path in path_l:

            if (not ('libc.so' in path and os.path.isfile(path))):
                continue

            base_name = path.split('/')[-1]

            lib_version = base_name.split('.')[-1]
            conversion_status = convert_str_to_int(lib_version)

            if (conversion_status[0]):

                stdout, _, rc = run_cmd('file %s | cut -d":" -f2' % path)

                if (rc == 0 and \
                    stdout.strip().startswith('ELF') and \
                    'shared object' in stdout.lower()):

                    return (True, path)

    return (False, '')


def keyfile_load(fp=''):

    if (not os.path.isfile(fp)):
        return (False, '')

    data_l = []

    with open(fp, 'r') as fh:

        line = fh.readline()

        while (line != ''):
            data_l.append(line)
            line = fh.readline()

    if (len(data_l) == 0):
        return (False, '')
    else:
        return (True, ''.join([data.strip() for data in data_l]))


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Security Related Functions for PWMGR >= 2.3                        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

class AllocateSecureMemory():

    """
    Function that calls c-api at lower level to allocate & securely wipe memory

        * At this time only string data types are supported
    """

    def __init__(self, value=''):

        if (type(value) != str):
            msg = 'AllocateSecureMemory(): Only str data types are currently supported' 
            raise TypeError(msg)

        self.__prealloc_percent = 1.3
        self.__data_size_physical = 0
        self.__data_size_virtual  = 0

        if (len(value) == 0):
            self.__data_size_physical = 10
            self.__data_size_virtual  = 0
        elif (len(value) <= 7):
            self.__data_size_physical = 10
            self.__data_size_virtual  = len(value)
        else:
            self.__data_size_physical = math.ceil(len(value) * self.__prealloc_percent)
            self.__data_size_virtual  = len(value)

        ## Memory allocation
        try:
            self.__data = (ctypes.c_char * self.__data_size_physical)()
        except Exception:
            raise MemoryAllocationFailedException('AllocateSecureMemory(): Insufficient memory')

        ## Copying strings
        for i in range(self.__data_size_virtual):
            self.__data[i] = bytes(value[i], 'utf-8')


    def get_virtual_size(self):
        return self.__data_size_virtual


    def get_physical_size(self):
        return self.__data_size_physical


    def get_str(self):
        """
        Use this function only if you're directly providing it as input to
        encryption / decryption functions, otherwise data may not get wiped.  
        """
        return self.__data.value.decode()


    def print_str(self):

        for i in range(self.__data_size_virtual):
            sys.stdout.write('%s' % self.__data[i].decode())


    def clear_str(self):

        self.wipe_memory()


    def is_empty(self):

        if (self.__data_size_virtual == 0):
            return True
        else:
            return False


    def lstrip(self):

        """
        Removes white space at the beginning of a str
        """

        start_index = 0

        for i in range(self.__data_size_virtual):

            if (self.__data[i].decode() == ' '):
                start_index += 1
            else:
                break

        current_index = 0

        for i in range(start_index, self.__data_size_virtual):
            self.__data[current_index] = self.__data[i]
            current_index += 1

        for i in range(current_index, self.__data_size_virtual):
            self.__data[i] = bytes('\x00', 'utf-8')

        self.__data_size_virtual = self.__data_size_virtual - start_index


    def has_space(self):
        """
        This fn is used by the frontend to check if password str has space in it
        """

        result = False

        for i in range(self.__data_size_virtual):

            if (self.__data[i].decode() == ' '):
                return True

        return result


    def add_str_start(self, value=""):
        
        free_space = self.__data_size_physical - self.__data_size_virtual

        if (free_space < len(value)):
            new_physical_size = math.ceil((self.__data_size_physical + len(value)) * self.__prealloc_percent)
            new_virtual_size = len(value) + self.__data_size_virtual

            try:
                new_memory =  (ctypes.c_char * new_physical_size)() 
            except Exception:
                raise MemoryAllocationFailedException('AllocateSecureMemory(): Insufficient memory')

            current_index = 0

            for i in range(0, len(value)):
                new_memory[i] = bytes(value[i], 'utf-8')
                current_index += 1

            for i in range(0, self.__data_size_virtual):
                new_memory[current_index] = self.__data[i]
                current_index += 1

            self.wipe_memory()

            self.__data = new_memory
            self.__data_size_virtual = new_virtual_size
            self.__data_size_physical = new_physical_size

        else:

            # raise Exception("add_str_start(): Functionality yet to be implemented")
            
            data_index = self.__data_size_virtual - 1
            end_index = self.__data_size_virtual + len(value) - 1

            while (data_index >= 0):

                self.__data[end_index] = self.__data[data_index]
                end_index -= 1
                data_index -= 1

            for i in range(len(value)):
                self.__data[i] = bytes(value[i], 'utf-8')

            self.__data_size_virtual = self.__data_size_virtual + len(value)


    def add_str_end(self, value=""):

        free_space = self.__data_size_physical - self.__data_size_virtual

        if (free_space >= len(value)):

            start_index = self.__data_size_virtual

            for i in range(0, len(value)):
                self.__data[start_index+i] = bytes(value[i], 'utf-8')

            self.__data_size_virtual = start_index + len(value)

        else:

            new_physical_size = math.ceil((self.__data_size_physical + len(value)) * self.__prealloc_percent)
            new_virtual_size = len(value) + self.__data_size_virtual

            try:
                new_memory =  (ctypes.c_char * new_physical_size)() 
            except Exception:
                raise MemoryAllocationFailedException('AllocateSecureMemory(): Insufficient memory')

            current_index = 0

            for i in range(0, self.__data_size_virtual):
                new_memory[current_index] = self.__data[i]
                current_index += 1

            for i in range(0, len(value)):
                new_memory[current_index] = bytes(value[i], 'utf-8')
                current_index += 1

            self.wipe_memory()

            self.__data = new_memory
            self.__data_size_virtual = new_virtual_size
            self.__data_size_physical = new_physical_size


    def wipe_memory(self):

        for i in range(self.__data_size_virtual):
            self.__data[i] = bytes('\x00', 'utf-8')

        self.__data_size_virtual = 0


    def copy_to_clipboard(self):

        output = get_libc_path() 

        if (output[0] == False):
            raise SecureClipboardCopyFailedException()

        try:
            ## Typical path: 
            ##  '/lib/libc.so.6', 
            ##  '/usr/lib/x86_64-linux-gnu/libc.so.6'

            c_lib = ctypes.CDLL(output[1])

            self.add_str_start("echo '")
            self.add_str_end("' | /usr/bin/xclip -selection clipboard")
            shell_cmd = c_lib.system
            shell_cmd(self.__data)
            self.wipe_memory()

        except OSError:
            raise SecureClipboardCopyFailedException()
        except Exception:
            msg =  'Unknown error occured, while using secure clipboard copy function'
            raise SecureClipboardCopyFailedException(msg)


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

class DataCorruptedException(Exception):
    def __init__(self, msg="Unable to decode unicode chars, " + \
                            "database file is corrupted"):
        super(DataCorruptedException, self).__init__(msg)

class KeyFileInvalidException(Exception):
    def __init__(self, msg="Keyfile is invalid, need to use a minimum of 1000 byte key"):
        super(KeyFileInvalidException, self).__init__(msg)

class NoKeyFoundException(Exception):
    def __init__(self, msg="Key doesn't exist"):
        super(NoKeyFoundException, self).__init__(msg)

class UnsupportedFileFormatException(Exception):
    def __init__(self, msg="Unsupported file format detected"):
        super(UnsupportedFileFormatException, self).__init__(msg)

class MemoryAllocationFailedException(Exception):
    def __init__(self, msg='Unable to acquire sufficient memory'):
        super(MemoryAllocationFailedException, self).__init__(msg)

class SecureClipboardCopyFailedException(Exception):
    def __init__(self, msg='Unable to copy data using secure method'):
        super(SecureClipboardCopyFailedException, self).__init__(msg)


