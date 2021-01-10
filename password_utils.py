#!/usr/bin/python3

from random import seed, randint


"""
Utility functions used by Password Manager

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

    symbols = "!@#$%^&*(){}[]<>?+-"
    num = "0123456789"
    lcase = "abcdefghijklmnopqrstuvwxyz"
    ucase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


    password = ""

    if (enableSymbols):
        for i in range(length+1):
            choice = rand_list([0,1,2,3])

            if (choice == 0):
                password = "%s%s" % (password, rand_list(symbols))
            elif (choice == 1):
                password = "%s%s" % (password, rand_list(num))
            elif (choice == 2):
                password = "%s%s" % (password, rand_list(lcase))
            elif (choice == 3):
                password = "%s%s" % (password, rand_list(ucase))
    else:
        for i in range(length+1):
            choice = rand_list([0,1,2])

            if (choice == 0):
                password = "%s%s" % (password, rand_list(num))
            elif (choice == 1):
                password = "%s%s" % (password, rand_list(lcase))
            elif (choice == 2):
                password = "%s%s" % (password, rand_list(ucase))

    if (debug):
        print(password)

    return password
        

def gen_pass_secure(length=10, debug=False, grid=False,
        enableSymbols=True):
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

    if length < 10:
        return -1


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


