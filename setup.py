#!/usr/bin/python3

from time import sleep
from hashlib import sha256
import math, os, sys, subprocess, random
from threading import Thread
from getch import getch

global app_name, dist_pkg_l_ubuntu, dist_pkg_l_arch, \
       pip_pkg_l, installation_files

'''
    Auto Installer script for apps,
    supports distro based packages & 
    third party python libraries
'''

__title__        =  'Password Manager'
__author__       =  'Zubair Hossain'
__email__        =  'zhossain@protonmail.com'
__version__      =  '3.0.0'
__last_updated__ =  '07/17/2024'
__license__      =  'GPLv3'


app_name           = 'PWMGR'
dist_pkg_l_ubuntu  = 'git dmenu xclip wxpython-tools keyutils python3-pip libc6 fonts-fantasque-sans'
dist_pkg_l_arch    = 'git dmenu xclip python-wxpython keyutils python-pip glibc ttf-fantasque-sans-mono'

pip_pkg_l          = 'getch fernet'

installation_files = ['pwmgr.py', 'wipe_pwmgr.py', 'database_pwmgr.py']

'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                           Utility Functions                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

class ProgressBarTimerBased():

    def __init__(self, avg_wait_time=10, left_indent=25):

        self.__count_current = 0

        self.__count_total = avg_wait_time

        self.__end_progress = False

        self.__wait_schedule = []

        self.__allocate_wait_schedule()

        self.__thread_obj = None

        self.__left_indent = left_indent


    def start(self):

        try:
            cursor_hide()
            self.__thread_obj = Thread(target=self.__threaded_fn)
            self.__thread_obj.start()
        except KeyboardInterrupt:
            cursor_show()
            clear_screen()
            raise KeyboardInterrupt('ProgressBarTimerBased(): Task has been interrupted by user')


    def end(self):

        self.__end_progress = True
        self.__thread_obj.join()
        cursor_show()


    def __print(self):

        self.__update_progress_bar_classic(self.__count_current, \
                                           self.__count_total, \
                                           self.__left_indent)


    def __threaded_fn(self):

        cursor_hide()

        while (len(self.__wait_schedule) > 0 and not self.__end_progress):

            self.__print()
            amount = self.__wait_schedule.pop(0)
            sleep(amount)
            self.__increment_count(amount)

        while (True):

            if (self.__end_progress):
                self.__count_current = self.__count_total
                self.__print()
                sleep(1)
                return
            else:
                sleep(0.01)


    def __allocate_wait_schedule(self):

        random.seed()

        total_time = self.__count_total
        num_long_waits = random.randint(2,6)
        long_wait_time = float(total_time * 0.70)
        short_wait_time = float(total_time * 0.30)

        wait_schedule = []
        long_wait_schedule = []
        short_wait_schedule = []

        long_wait_time_available = long_wait_time

        for i in range(num_long_waits):

            if (long_wait_time_available <= 0):
                break

            wait_time = self.__get_random_number(1, long_wait_time, long_wait_time * 0.6)
            long_wait_schedule.append(wait_time)
            long_wait_time_available = long_wait_time_available - wait_time

        short_wait_time_available = short_wait_time

        while (short_wait_time_available > 0):

            wait_time = self.__get_random_number(0.1, 5, 2.5)
            short_wait_schedule.append(wait_time)
            short_wait_time_available = short_wait_time_available - wait_time

        wait_schedule = short_wait_schedule

        long_wait_schedule.sort(reverse=True)
        # __print(long_wait_schedule)

        ## Inserting longer wait times at the end and beginning
        time = long_wait_schedule.pop(0)
        # __print(time)
        index = self.__get_index_by_percent(0, (len(wait_schedule)-1), 0.80)
        # __print(index)
        wait_schedule.insert(index, time)
        # __print(wait_schedule)

        time = long_wait_schedule.pop(0)
        # __print(time)
        index = self.__get_index_by_percent(0, (len(wait_schedule)-1), 0.2)
        # __print(index)
        wait_schedule.insert(index, time)
        # __print(wait_schedule)

        wait_schedule_mid_index_st = self.__get_index_by_percent(0, (len(wait_schedule)-1), 0.25)
        wait_schedule_mid_index_end = self.__get_index_by_percent(0, (len(wait_schedule)-1), 0.65)

        while (len(long_wait_schedule) > 0):

            wait_schedule.insert(random.randint(wait_schedule_mid_index_st, wait_schedule_mid_index_end), \
                                         long_wait_schedule.pop(0))

        self.__wait_schedule = wait_schedule
        # __print(self.__wait_schedule)


    def __get_random_number(self, st_range=0, end_range=4, limit=2):

        value = 0

        while (True):

            value = random.random() * end_range

            if (value < st_range):
                return value+st_range
            elif (value <= limit):
                return value


    def __get_index_by_percent(self, index_start=0, index_end=10, amount=0.2):

        return math.floor((index_end - index_start) * amount)


    def __increment_count(self, count):

        if (self.__count_current >= self.__count_total):
            self.__count_current = self.__count_total
        else:
            self.__count_current += count


    def __update_progress_bar_classic(self, index=1, \
                                      index_range=10, \
                                      left_indent=25):

        """
        Classic progress bar

        Args:    1) This represents the amount completed out of the total amount
                 2) This represents the total amount
                 3) Amount of padding on the left
                 4) Amount of padding on the right

        Returns: None
        """

        color_black_orange = '\x1B[1;38;5;0m\x1B[1;48;5;214m' 
        color_white        = '\x1B[1;38;5;15m'
        color_black        = '\x1B[1;38;5;0m' 
        color_bg_black     = '\x1B[1;48;5;0m' 
        color_yellow       = '\x1B[1;38;5;220m' 
        color_rst          = color_reset()

        bar_length = 20

        total_text = list(' ' * bar_length)

        center = int(len(total_text)/2)

        percentage_remaining = (index/index_range) * 100
        percentage_remaining = int(percentage_remaining)
        percentage_remaining_str = '%3d' % percentage_remaining

        if (index >= index_range-2):
           progress_text = ' '
           total_text[center-2] = '1'
           total_text[center-1] = '0'
           total_text[center] = '0'
           total_text[center+1] = '%'
           remaining_text = ''.join(total_text[:])

           new_text = color_rst + ' ' * left_indent + color_black_orange + color_black + \
                   '[ ' + remaining_text + ' ]' + color_rst
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

                new_text = color_rst + ' ' * left_indent + color_black_orange + color_black + \
                        '[ ' + color_black + progress_text + color_bg_black + remaining_text + \
                        color_white + ' ]' + color_rst
            else:

                new_text = color_rst + ' ' * left_indent + color_black_orange + color_black + \
                        '[ ' + color_white + progress_text + color_bg_black + remaining_text + \
                        color_yellow + ' ]' + color_rst

        sys.stdout.write('\r')
        sys.stdout.write("%s" % new_text)
        sys.stdout.flush()


def prompt(question="", allow_blank_response=False, \
           quit_if_keyboard_interrupt=True, field_color_fg=''):

    rst = color_reset()

    value = ""

    _q = question

    if (not _q.strip().endswith('?')):
        pass
    else:
        _q += ':'

    if (not _q.endswith(' ')):
        _q += ' '

    _q = field_color_fg + question + rst

    try:

        while (True):

            value = input(color_symbol_prompt() + ' ' + _q)

            if (not allow_blank_response and value == ""):
                print(text_error("Field cannot be blank\n"))
            else:
                break

    except KeyboardInterrupt:

        if (quit_if_keyboard_interrupt):
            clear_screen()
            sys.exit()
        else:
            raise KeyboardInterrupt('prompt(): keyboard interrupt requested')

    return value


def prompt_yes_no_instant(question="", default=True, \
                          quit_if_keyboard_interrupt=True):
    """
    Asks yes/no & returns a boolean value.
    """

    q =  color_symbol_info() + ' ' + '\x1B[1;38;5;221m' + question + color_reset() 
        
    choice = ''

    try:

        while (True):

            sys.stdout.write(q)
            sys.stdout.flush()

            choice = getch()

            print()

            if (choice == '\n'):
                return default
            elif (choice == 'y'):
                return True
            elif (choice == 'n'):
                return False
            else:
                print(text_error("Invalid answer.  Please type 'y/n'") + '\n')

    except KeyboardInterrupt:

        if (quit_if_keyboard_interrupt):
            clear_screen()
            sys.exit()

        else:
            msg = 'prompt_yes_no_instant(): keyboard interrupt requested'
            raise KeyboardInterrupt(msg)


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                          Printing Functions                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def text_error(text=''):
    text = '\n%s %s%s%s' % (color_symbol_error(), \
                            '\x1B[1;38;5;249m', \
                            text, color_reset())
    return text


def text_info(text=''):

    text = '\n%s %s%s%s' % (color_symbol_info(), \
                            '\x1B[1;38;5;249m', \
                            text, color_reset())
    return text


def text_debug(text=''):

    text = color_symbol_debug() + " " + bold() + text + color_reset()
    return text


def color_symbol_debug():

    text = '  ' + color_b('yellow') + '[*]' + color_reset()
    return text

def color_symbol_prompt():
    text = '  ' + '\x1B[1;38;5;51m' + '[>]' + color_reset()
    return text


def color_symbol_info():

    text = '%s*%s' % ('\x1B[1;38;5;214m', color_reset())

    text = '  %s[%s%s]%s' % ('\x1B[1;38;5;11m', \
                               text, \
                             '\x1B[1;38;5;11m', \
                               color_reset())
    return text


def color_symbol_error():

    text = '%s-%s' % ('\x1B[1;38;5;198m', color_reset())

    text = '  %s[%s%s]%s' % ('\x1B[1;38;5;160m', \
                               text, \
                             '\x1B[1;38;5;160m', \
                               color_reset())
    return text


def bold():

    return "\x1B[1m"


def text_highlight(text=''):

    return bold() + text + color_reset()


def color_reset():
    """
    Reset bg & fg colors
    """
    return "\x1B[0m"


def color_b(c=''):

    """
    Bold colors
    """

    if (c == 'white'):
        return '\x1B[1;38;5;15m'
    elif (c == 'blue'):
        return '\x1B[1;38;5;27m'
    elif (c == 'cyan'):
        return '\x1B[1;38;5;51m'
    elif (c == 'yellow'):
        return '\x1B[1;38;5;221m'
    elif (c == 'orange'):
        return '\x1B[1;38;5;214m'
    elif (c == 'red'):
        return '\x1B[1;38;5;196m'
    elif (c == 'green'):
        return '\x1B[1;38;5;118m'
    elif (c == 'black'):
        return '\x1B[1;38;5;232m'
    else:
        return ""


def clear_screen():

    """
    Clears screen, command is compatible with different OS
    """
    os.system('clear')


def cursor_show():

    print("\x1b[?25h")


def cursor_hide():

    print("\x1b[?25l")


def print_header():
    color_rst    = color_reset()
    color_cyan   = '\x1B[1;38;5;87m' 
    print('''
                  %sPWMGR Installation%s''' % (color_cyan, color_rst))
            
def decode_unicode_str_safely(input_str=''):

    if (type(input_str) != bytes):
        msg = 'decode_unicode_str_safely(): data type needs to be bytes' 
        return InvalidParameterException(msg)

    try:
        return (True, input_str.decode('ascii'))
    except UnicodeDecodeError:
        return (False, '')


def display_row(field_list=[], data_list=[], \
                header_width=20, indent=6, \
                term_len_h=100,  field_color_fg=''):

    if (len(data_list) == 0 or len(field_list) == 0):
        return
    elif (len(data_list) != len(field_list)):
        raise FieldMismatchException('display_row(): The field & data list needs to be of same size')

    if (term_len_h < 50):
        print(text_error('Terminal size too small to display data'))
        sys.exit(1)

    max_length = 0

    for i in range(len(data_list)):
        if (len(data_list[i]) > max_length):
            max_length = len(data_list[i])

    indent_text = ' ' * indent

    for i in range(len(data_list)):

        h_list = list(' ' * header_width)

        # text_list is the remaining data + space after header field
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

            text = field_color_fg + indent_text + \
                    text_highlight(''.join(h_list)) + color_reset() + ''.join(text_list[0]) + \
                    color_reset()

            print(text)

            blank_header = h_list  

            for crab in range(len(blank_header)):

                blank_header[crab] = ' '

            blank_header = ''.join(blank_header)

            for line in text_list[1:]:

                text = field_color_fg + indent_text + \
                        blank_header + color_reset() + ''.join(line) + \
                        color_reset()
        
                print(text)

        else:

            for k in range(len(d_list_char)):
                text_l_obj[k] = d_list_char[k]
        
            text = field_color_fg + indent_text + \
                    text_highlight(''.join(h_list)) + color_reset() + ''.join(text_l_obj) + \
                    color_reset()
        
            print(text)


def print_file_list(fl=[]):

    # Printing file list
    color_orange = '\x1B[1;38;5;214m'
    color_rst    = color_reset()

    line_width_max = 53

    final_text = ''
    current_line = ''

    line_added = False

    for f in fl:

        if (len(current_line) > line_width_max):
            final_text = final_text + current_line + '\n\n'
            current_line = '\t'
            line_added = True
        else:
            line_added = False
            current_line += ' %s' % (f)

    if (not line_added):
        final_text += ' %s' % (current_line)

    print('\t' + color_orange + final_text + color_rst + '\n')

            
def print_help():

    color_rst    = color_reset()
    color_green  = '\x1B[1;38;5;118m'
    color_orange = '\x1B[1;38;5;214m'

    color_white  = '\x1B[1;38;5;249m'
    color_yellow = '\x1B[1;38;5;229m'

    print_header()

    print ('''                  
           %sUsage: ./%s%s %sinstall %s[ %subuntu %s| %sarch%s ]%s

                  ./%s%s %suninstall %s

           %s* If your distribution is unsupported or you're running into issues,
             feel free to check out the manual installation section of the guide%s
           ''' % ( color_white, color_green, sys.argv[0], \
                  color_orange, color_white, \
                  color_yellow, color_white, color_yellow, color_white, color_rst, \
                  color_green, sys.argv[0], color_orange, color_rst, \
                  color_white,  color_rst))


def print_cmd_not_found():

    color_white  = '\x1B[1;38;5;249m' 
    color_orange = '\x1B[1;38;5;214m'
    color_rst    = color_reset()


    print(text_error("Option not found. Trying using " + \
                     color_orange + "help " + \
                     color_white  + "/"     + \
                     color_orange + " +h "   + \
                     color_white  + "for more info\n"  + color_rst))
    sys.exit(1)


def print_install_success():

    print(text_info('\x1B[1;38;5;249m' + \
          'Congratulations, your %s installation is now complete!' % app_name) + '\n')


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


def check_if_user_can_sudo():

    cmd = 'sudo id'
    stdout, stderr, rc = run_cmd(cmd)

    if (rc == 0):
        return True
    else:
        return False


def load_hashes_from_file(fp=''):

    formatted_data = []

    if (os.path.isfile(fp)):

        data = []

        with open(fp, 'r') as fh:
            try:
                data = fh.read().strip().splitlines()
            except IOError:
                pass

        for i in range(len(data)):

            item = data[i].split()

            if (len(item) == 2):
                formatted_data.append([item[0], item[1]])

    return formatted_data


def validate_integrity_of_code(fp=''):

    data = load_hashes_from_file(fp)

    if (len(data) == 0):

        print(text_debug('No hash database found'))

        if (not prompt_yes_no_instant('Do you wish to continue? (Y/n)    ', \
                               quit_if_keyboard_interrupt=True)):
            print()
            sys.exit(0)
    else:

        f_not_found      = []

        failed_fn        = []
        failed_hash      = []

        passed_fn        = []
        passed_hash      = []

        # print(data)
        for item in data:

            if (not os.path.isfile(item[1])):
                f_not_found.append(item[1])
                continue

            f_data = ''

            with open(item[1], 'r') as fh:
                f_data = fh.read()

            try:
                output = bytes(f_data, 'utf-8') 

                item_hash = sha256(output).hexdigest()

                if (item_hash != item[0]):
                    failed_fn.append(item[1])
                    failed_hash.append(item[0])
                else:
                    passed_fn.append(item[1])
                    passed_hash.append(item[0])

            except UnicodeEncodeError:
                f_hash_error(item[1])
                continue

        if (len(f_not_found) != 0):
            print(text_error('The following files are listed in database, but do not exist') + '\n')
            print_file_list(f_not_found)
            
            if (not prompt_yes_no_instant('Do you wish to continue? (Y/n)    ', \
                                             quit_if_keyboard_interrupt=True)):
                print()
                cursor_show()
                sys.exit(0)

        try:
            term_len_h, term_len_v = os.get_terminal_size()
        except (OSError):
            term_len_h = 75
            term_len_v = 75

        if (len(failed_fn) != 0):
            print(text_error('The following files have hash mismatches: ') + '\n')

            display_row(failed_fn, failed_hash, \
                        term_len_h=term_len_h, \
                        indent=10, \
                        field_color_fg='\x1B[1;38;5;36m')

            print(text_info('Please make sure you have correct version of the files')) 
            cursor_show()
            sys.exit(1)

        else:
            passed_amount = '%s(%d/%d)%s' % ('\x1B[1;38;5;118m',   \
                                             len(passed_fn), len(passed_fn), \
                                             color_reset())

            print(text_info('Passed hash verfication check ') + passed_amount)

        
class FieldMismatchException(Exception):
    def __init__(self, msg="The field & data list needs to be of same size"):
        super(FieldMismatchException, self).__init__(msg)


def main():

    global app_name, dist_pkg_l_ubuntu, dist_pkg_l_arch, \
           pip_pkg_l, installation_files

    arg_len = len(sys.argv) 

    if (arg_len == 2 or arg_len == 1):

        if (arg_len == 1 or sys.argv[1] in ['help', '+h']):
            print_help()

        elif (arg_len == 2 and sys.argv[1] == 'uninstall'):

            for f in installation_files:

                _f = '/usr/bin/%s' % f

                if (os.path.isfile(_f)):
                    cmd = 'sudo rm %s' % _f
                    stdout, stderr, rc = run_cmd(cmd)

            print(text_info('\x1B[1;38;5;249m' + \
                  '%s has been removed from the system' % app_name) + '\n')
        elif (arg_len == 2 and sys.argv[1] == 'install'):
            print(text_info('Need to specify the Linux distribution') + '\n')
            sys.exit(0)
        else:
            print_cmd_not_found()

    elif (arg_len == 3 and sys.argv[1] == 'install'): ## Installation logic

        if (not (sys.argv[2] == 'ubuntu' or sys.argv[2] == 'arch')):
            print(text_error('Your Linux distribution is not currently supported'))
            print(text_info('Please checkout the installation section of the guide') + '\n')
            sys.exit(0)

        dist = sys.argv[2]
        color_orange = '\x1B[1;38;5;214m'
        color_rst    = color_reset()

        cursor_hide()
        clear_screen()

        print(text_info('Validating integrity of code files, please wait..'))
        sleep(1)
        validate_integrity_of_code('code_hashes.txt')

        if (not (len(dist_pkg_l_ubuntu) == 0 or len(dist_pkg_l_arch) == 0)):

            dist_pkg_l = []

            cmd1 = ''

            if (sys.argv[2] == 'ubuntu'):
                cmd1 = 'sudo apt-get install -y '
                cmd1 += dist_pkg_l_ubuntu
                dist_pkg_l = dist_pkg_l_ubuntu.split()
            else:
                cmd1 = 'sudo pacman -S --noconfirm '
                cmd1 += dist_pkg_l_arch
                dist_pkg_l = dist_pkg_l_arch.split()

            # Printing system package info
            if (len(dist_pkg_l) > 6):

                print(text_info('The following system packages will be installed: \n'))
                number_of_lines = math.ceil(len(dist_pkg_l)/6)

                current_pkg_index = 0
                num_pkg_per_line  = 6

                for i in range(number_of_lines):

                    if (i == number_of_lines-1):
                        print('\t' + color_orange + \
                              ' '.join(dist_pkg_l[current_pkg_index:]) + \
                              color_rst + '\n\n')
                        break

                    else:

                        print('\t' + color_orange + \
                              ' '.join(dist_pkg_l[current_pkg_index:current_pkg_index+6]) + \
                              color_rst + '\n')
                    
                        current_pkg_index += 6

            else:
                print(text_info('The following system packages will be installed: \n'))
                print('\t\t' + color_orange + dist_pkg_l_ubuntu + color_rst + '\n\n')

            if (not prompt_yes_no_instant('Do you wish to continue? (Y/n)    ', \
                                   quit_if_keyboard_interrupt=True)):
                print()
                cursor_show()
                sys.exit(0)

            clear_screen()
            print('\n\n')
            pb1 = ProgressBarTimerBased(120)

            try:
                pb1.start()
                stdout, stderr, rc = run_cmd(cmd1)
                pb1.end()
            except KeyboardInterrupt:
                clear_screen()
                sys.exit(1)

            clear_screen()

            # Package not found in distro
            if (rc != 0):

                err_msg = ''

                if (dist == 'ubuntu'):

                    if (stderr.startswith('E:')):
                        err_msg = stderr[3:]
                    else:
                        err_msg = stderr

                elif (dist == 'arch'): # TODO: arch linux logic
                    err_msg = stderr

                print(text_error(err_msg))
                print(text_info('Please checkout the installation section of the guide ')) 
                print('\x1B[1;38;5;249m' + '\t& try to install the packages manually\n' + color_reset())
                cursor_show()
                sys.exit(1)
                
        if (len(pip_pkg_l) != 0):

            clear_screen()

            _pip_pkg_l = pip_pkg_l.split()

            # Printing pip pkg info
            if (len(_pip_pkg_l) > 6):

                print(text_info('The following python packages will be installed: \n'))
                number_of_lines = math.ceil(len(_pip_pkg_l)/6)

                current_pkg_index = 0
                num_pkg_per_line  = 6

                for i in range(number_of_lines):

                    if (i == number_of_lines-1):
                        print('\t' + color_orange + \
                              ' '.join(_pip_pkg_l[current_pkg_index:]) + \
                              color_rst + '\n\n')
                        break

                    else:

                        print('\t' + color_orange + \
                              ' '.join(_pip_pkg_l[current_pkg_index:current_pkg_index+6]) + \
                              color_rst + '\n')
                    
                        current_pkg_index += 6
            else:
                print(text_info('The following python packages will be installed: \n'))
                print('\t' + color_orange + pip_pkg_l + color_rst + '\n\n')

            if (prompt_yes_no_instant('Do you wish to continue? (Y/n)    ', \
                               quit_if_keyboard_interrupt=True) == False):
                print()
                cursor_show()
                sys.exit(0)

            clear_screen()
            print('\n\n')

            pb2 = ProgressBarTimerBased(120)

            cmd2  = 'pip3 install --user --break-system-packages '
            cmd2 += pip_pkg_l

            try:
                pb2.start()
                stdout, stderr, rc = run_cmd(cmd2)
                pb2.end()
            except KeyboardInterrupt:
                cursor_show()
                clear_screen()
                sys.exit(1)

            clear_screen()

            # Package not found in pip
            if (rc != 0):
                print(text_error('Unable to install packages through pip'))
                print(text_info('Try installing manually by running the following command: \n')) 
                print('\t\x1B[1;38;5;214m' + cmd2 + color_reset() + '\n')
                sys.exit(1)

        # Copying pwmgr files to /usr directory

        err_file_cp = False

        for f in installation_files:

            if (os.path.isfile(f)):
                cmd = 'sudo cp %s /usr/bin/' % f
                stdout, stderr, rc = run_cmd(cmd)

                if (rc != 0):
                    err_file_cp = True

        if (err_file_cp == True):

            print(text_error('Unable to copy %s files to system' % app_name))

            print(text_info('You can enable sudo to run without requiring a password\n' + \
                  '\tby adding this line to the file: ' + \
                  '\x1B[1;38;5;87m' + '/etc/sudoers' + color_reset() + '\n'))
            
            sudo_config = '%s ALL=(ALL) NOPASSWD: ALL' % (os.getlogin())
            print('\t\x1B[1;38;5;118m' + sudo_config + color_reset())

            print(text_info('Please make sure you have sudo priviledges' + \
                    ' before running the commands\n'))

            for f in installation_files:
                cmd = 'sudo cp %s /usr/bin/' % f
                print('\t\x1B[1;38;5;214m' + cmd + color_reset() + '\n')
        else:
            print_install_success()

    else:
        print_cmd_not_found()


if __name__ == "__main__":
    main()
