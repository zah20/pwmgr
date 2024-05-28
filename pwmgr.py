#!/usr/bin/python3
from        time import sleep
from        getch import getch
from        hashlib import sha256
from        getpass import getpass
from        database_pwmgr import ManageRecord,\
                 Record, AllocateSecureMemory
import    csv, math, os
import    subprocess
import    random
import    base64  
import    sys
from  database_pwmgr import \
     SecureClipboardCopyFailedException,InvalidParameterException,\
   IncorrectPasswordException,IntegrityCheckFailedException,IncorrectKeyException,\
 UnsupportedFileFormatException,NoKeyFoundException,DataCorruptedException


global __app, __author, __updated__, __current_revision__

__app__              = 'Password Manager'
__author__           = 'Zubair Hossain'
__last_updated__     = '07/24/2024'
__current_revision__ = '3.0.1'


#$$$$━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$
global term_len_h,term_len_v,config_file,db_file_path,\
  config,term_bar_color,app_name,file_name,db_handler, \
 theme_number,theme,field_color_fg,password_in_keyring#/
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━/
#////////////////////////
theme='';theme_number=1 
file_name= 'db.enc'
app_name = 'pwmgr'
db_handler= True
config = {}
config_file=''
db_file_path=''
field_color_fg=''
term_bar_color=''


global lcase,\
char_set_complete,\
symbol,ucase,number
symbol= "<!$%?+@*^&#>"
ucase=  "AMBYNZCODPEQFRGSHTIUJVKWLX"
lcase=   "ambynzcodpeqfrgshtiujvkwlx"
number= "0123456789"
char_set_complete=\
symbol+lcase+\
ucase+\
number 


term_len_v = 30;
term_len_h = 70;
password_in_keyring = False


'''
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃             Code Index              ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

                    Core

      Argument Parsing                137
      Configuration                   641
      Essential Functions            1101


                  Security

      Clipboard Functions            1771
      Secure Printing Functions      1871
      Advanced Printing Functions    2570
      Keyfile & Keyring Functions    2845


                Uncategorized

      Utility Functions              3385
      Search Bar                     3605
      Database RW                    3761


                     IO

      File IO Functions              4047
      Import / Export Functions      4185
      Gui Functions                  4414
      Help Text                      4501
      Terminal & Printing Functions  4755
      User Input & Related           5061
      Password Generator Functions   5591

'''


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Argument Parsing Functions                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def parse_args():

    """
    Parses commandline arguments & executes the desired functions

    """

    global term_len_h, config, \
           theme_number, theme, field_color_fg, term_bar_color

    argument_length = len(sys.argv)

    if (argument_length == 1):

        print_help()
        sys.exit(0)

    else:

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

        initialize_resolution(init=True)

        initialize_theme(init=True)

        if (argument_length == 2):

            if (sys.argv[1] == 'add'):

                check_database()
                add()
                sys.exit(0)

            elif (sys.argv[1] == 'audit'):

                if (term_len_h < 110):
                    print(text_error('Screen size too small to display data'))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()
                audit_records()
                sys.exit(0)

            elif (sys.argv[1] == 'show'):

                check_database()
                exit_if_database_is_empty()
                show_summary()
                sys.exit(0)

            elif (sys.argv[1] == 'show+'):

                if (check_if_prog_exists(['dmenu'])[0] == False):
                    print(text_error('Dmenu package was not found. Please install it & try again!'))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()
                search_bar_show()

            elif (sys.argv[1] == 'show-latest'):

                check_database()
                exit_if_database_is_empty()
                show_last_modified()
                sys.exit(0)

            elif (sys.argv[1] == 'copy+'):

                if (check_if_prog_exists(['dmenu', 'xclip'])[0] == False):
                    print(text_error('Dmenu package & xclip needs to be installed.'))
                    sys.exit(1)

                check_database()
                exit_if_database_is_empty()
                search_bar_copy()
                sys.exit(0)

            elif (sys.argv[1] == 'key-show'):

                check_database()
                key_show()
                sys.exit(0)

            elif (sys.argv[1] == 'change-enc-key'):

                check_database()
                pw_reset()
                sys.exit(0)

            elif (sys.argv[1] == 'keyring-clear'):

                keyring_reset()
                sys.exit(0)

            elif (sys.argv[1] == 'generator'):

                menu_generate_password_standalone()
                sys.exit(0)

            elif (sys.argv[1] == 'keyfile-list'):

                list_keyfile()
                sys.exit(0)

            elif (sys.argv[1] == 'keyfile-create'):

                if (check_if_prog_exists(['dd'])[0] == False): 
                    print(text_error('The program dd was not found. Please install it & try again!'))
                    sys.exit(1)

                generate_keyfile()
                sys.exit(0)

            elif (sys.argv[1] == 'keyfile-use'):

                fn = '/home/%s/.config/pwmgr/keyfile' % (os.getlogin())

                r = check_files([fn])

                print_block(1)

                if (not r):
                    print(text_error("No keyfile found, please consider updating config file manually "))
                    sys.exit(1)
                elif (check_if_prog_exists(['dd'])[0] == False): 
                    print(text_error('The program dd was not found. Please install it & try again!'))
                    sys.exit(1)
                else:
                    msg = 'Keyfile found in %s' % fn
                    print(text_debug(msg))
                    print_block(1)

                    choice = prompt_yes_no_instant("Do you want to use this keyfile? (Y/n): ", True)

                    if (not choice):
                        print_block(1)
                        sys.exit(0)

                    check_database()
                    use_keyfile(fn)
                    sys.exit(0)

            elif (sys.argv[1] == 'keyfile-remove'):

                check_database()
                remove_keyfile()
                sys.exit(0)

            elif (sys.argv[1] == 'help' or sys.argv[1] == '--help' or sys.argv[1] == '-h'):

                if (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
                    print(text_error("Option not found. Try using" + \
                                     color_b('orange') + " help " + \
                                     color_reset()))
                    sys.exit(0)

                else:
                    print_help()

                sys.exit(0)

            else:
                print(text_error("The selected option doesn't exist"))
                sys.exit(1)

        elif (argument_length == 3):

            if (sys.argv[1] == 'show'):

                result = convert_str_to_int(sys.argv[2])

                if (result[0] == False):
                    print(text_error("Requires an integer value"))
                    sys.exit(1)

                if (type(result[1]) == list):

                    index_list = result[1]
                    new_list = [i-1 for i in index_list]

                    check_database()
                    exit_if_database_is_empty()
                    
                    result = db_handler.validate_index(new_list)

                    if (result):
                        show_index_multiple(new_list)
                        sys.exit(0)
                    else:
                        print(text_error("Selected indexes are not within range"))
                        sys.exit(1)

                elif (type(result[1]) == int):

                    check_database()
                    exit_if_database_is_empty()

                    if (db_handler.validate_index((result[1]-1))):
                        show_index((result[1]-1))
                        sys.exit(0)
                    else:
                        print(text_error("Selected index is not within range"))
                        sys.exit(1)
                else:
                    print(text_error("Requires an integer or comma separated integer values"))
                    sys.exit(1)

            elif (sys.argv[1] == 'edit'):

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

                if (db_handler.validate_index((index-1))):
                    secure_edit_index((index-1))
                    sys.exit(0)
                else:
                    print(text_error("Selected index is not within range"))
                    sys.exit(1)

            elif (sys.argv[1] == 'search'):

                check_database()
                exit_if_database_is_empty()
                keyword = (sys.argv[2]).strip()
                search(keyword)
                sys.exit(0)

            elif (sys.argv[1] == 'copy'):

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

                if (db_handler.validate_index((index-1))):
                    secure_copy_password((index-1))
                    sys.exit(0)
                else:
                    print(text_error("Selected index is not within range"))
                    sys.exit(1)

            elif (sys.argv[1] == 'remove'):

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

                    if (db_handler.validate_index((index-1))):
                        delete_index((index-1))
                        sys.exit(0)
                    else:
                        print(text_error("Selected index is not within range"))
                        sys.exit(1)

                elif (type(index) == list):

                    new_list = [i-1 for i in index]
                    new_list = list(set(new_list))
                    
                    for i in new_list:
                        if (db_handler.validate_index(i) == False):
                            print(text_error("Selected index %s is not within range" % (i+1))) 
                            sys.exit(1)

                    # delete_index function can work on both single index / list of indexes
                    delete_index(new_list)
                    sys.exit(0)

                else:
                    print(text_error("Requires an integer value or a comma separated list"))
                    sys.exit(1)

            elif (sys.argv[1] == 'keyfile-create'):

                if (sys.argv[2].strip() == ''):
                    print(text_error('Key file name cannot be empty'))
                    sys.exit(1)

                generate_keyfile(sys.argv[2].strip())
                print_block(1)
                sys.exit(0)

            elif (sys.argv[1] == 'keyfile-use'):

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

            elif (sys.argv[1] == 'import-csv'):

                fn = sys.argv[2].strip()

                if (fn != '' and os.path.exists(fn)):
                    check_database()
                    import_from_csv(fn)
                    sys.exit(0)
                else:
                    print(text_error("The specified file %s doesn't exist" % fn))
                    sys.exit(1)

            elif (sys.argv[1] == 'export-csv'):

                fn = sys.argv[2].strip()

                if (fn != ''):
                    check_database()
                    export_to_csv(fn)
                    sys.exit(0)
                else:
                    print(text_error("Requires a file name"))
                    sys.exit(1)

            elif (sys.argv[1] == 'search-font'):

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

            if (sys.argv[1] == 'search'):

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

                if (not file_exists(input_file)):
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


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Configuration                                                    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

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

    default_cw = 10
    default_kw = 600

    if (not fn):
        set_default_font()
    else:
        r = check_if_font_exists(fn)

        if (not r):
            set_default_font()

    try:

        cw = int(cw)

        if (cw <= default_cw):
            config.update({'clipboard_wipe_interval':default_cw})
        else:
            config.update({'clipboard_wipe_interval':cw})

    except (ValueError, TypeError):
        config.update({'clipboard_wipe_interval':default_cw})

    try:

        kw = int(kw)

        if (kw <= 30):
            config.update({'keyring_wipe_interval':30})
        else:
            config.update({'keyring_wipe_interval':kw})

    except (ValueError, TypeError):
        config.update({'keyring_wipe_interval':default_kw})

    if (not th or type(th) != int or \
        not (th >= 1 and th <= 6)):
        config.update({'theme':66})
    else:
        config.update({'theme':th})

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
        return False

    return True


def get_screen_resolution():

    stdout, _, rc = run_cmd("xrandr | grep '*' | awk '{print $1}'")

    if rc != 0 or not stdout:
        return None

    w = int(stdout.split('x')[0])
    h = int(stdout.split('x')[1])

    return w,h


def initialize_resolution(init=False):

    global term_len_h, term_len_v

    if (not init and \
           global_value_initialized(term_len_h) and \
           global_value_initialized(term_len_v)):

        return 

    else:

        if (not module_imported('os')):

            term_len_h = 75
            term_len_v = 25

        else:

            try:
                term_len_h, term_len_v = os.get_terminal_size()
            except (OSError):
                term_len_h = 75
                term_len_v = 25


def initialize_theme(init=False):

    global config, theme_number, theme, \
           field_color_fg, term_bar_color

    if (init):
        pass
    elif (global_value_initialized(theme) and \
        global_value_initialized(field_color_fg) and \
        global_value_initialized(term_bar_color)):
        return

    try:
        theme_number = config.get('theme')
    except NameError:
        theme_number = 66

    if (theme_number == 1):
        # field_color_fg = '\x1B[1;38;5;44m'
        theme = color_theme_1()
        field_color_fg = '\x1B[1;38;5;33m'
        term_bar_color = '\x1B[1;38;5;75m'
    elif (theme_number == 2):
        theme = color_theme_2()
        field_color_fg = '\x1B[1;38;5;36m'
        term_bar_color = '\x1B[1;38;5;48m'
    elif (theme_number == 3):
        theme = color_theme_3()
        field_color_fg = '\x1B[1;38;5;214m'
        term_bar_color = '\x1B[1;38;5;216m'
    elif (theme_number == 4):
        theme = color_theme_4()
        field_color_fg = '\x1B[1;38;5;38m'
        term_bar_color = '\x1B[1;38;5;45m'
    elif (theme_number == 5):
        theme = color_theme_5()
        field_color_fg = '\x1B[1;38;5;208m'
        term_bar_color = '\x1B[1;38;5;216m'
    elif (theme_number == 6):
        theme = color_theme_6()
        field_color_fg = '\x1B[1;38;5;38m'
        term_bar_color = '\x1B[1;38;5;45m'
    elif (theme_number == 66):
        theme = color_theme_66()
        field_color_fg = '\x1B[1;38;5;87m'
        term_bar_color = '\x1B[1;38;5;45m'
    else:
        theme = color_theme_66()
        field_color_fg = '\x1B[1;38;5;87m'
        term_bar_color = '\x1B[1;38;5;45m'


def search_font_name(keyword=''):

    global field_color_fg

    stdout,_,_ = run_cmd("fc-list | grep -i '%s' | cut -d':' -f2" % (keyword))

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

    r, _, _ = run_cmd(['find /usr/share/fonts -iname "%s*"' % (rm_space_with_asterisk(fn))])

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


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Essential Functions                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def add():

    """
    Adds a record to database
    """

    global db_handler, db_file_path, field_color_fg

    cursor_show()
    clear_screen()
    print_block(1)
    print(info_bar_dynamic("Add Records  |  Press (Enter) to Skip  |  (Ctrl+c) Quit without saving"))
    print_block(4)

    site = prompt("Website: ")

    pwd = ''

    if (db_handler.check_duplicate_entry(site)):

        print_block(1)

        if (not prompt_yes_no_instant("Duplicate entry found. Do you want to continue? (y/N): ", False)):
            clear_screen()
            sys.exit(0)

    print_block(1)

    if (prompt_yes_no_instant("Auto generate password? (Y/n): ")):
        print_block(1)
        pwd = menu_generate_password_standalone(called_by_add_fn=True)
    else:
        print_block(1)
        pwd = prompt_password(True, 1)

    r = Record(site, pwd)

    clear_screen()
    print_block(1)

    choice = prompt_yes_no_instant("Do you want to add more info? (y/N): ", False)

    if (choice):
        clear_screen()
        print_block(1)
        print(info_bar_dynamic(' Add Record  |  Press (Enter) to Skip  ' + \
                               ' |  (Ctrl+c) Quit without saving'))

        print_block(4)

        r.set_email(prompt_with_blank("Email:  "))
        print_block(1)
        r.set_group(prompt_with_blank("Group:  "))
        print_block(1)
        r.set_username(prompt_with_blank("Username:  "))
        print_block(1)
        r.set_phone_number(prompt_with_blank("Phone#:  "))
        print_block(1)
        r.set_remark(prompt_with_blank("Notes:  "))
        print_block(1)
        r.set_email(prompt_with_blank("Recovery email:  "))
        print_block(1)
        r.set_two_factor(prompt_yes_no_instant("Two Factor enabled? (y/N):  ", \
                                                False))
        db_handler.add(r)
        db_handler.write_encrypted_database(db_file_path)

        clear_screen()

    else:
        ## We could have removed redundant logic but this way ensures we don't
        ## have menu bars displayed right beneath pw generation menu

        db_handler.add(r)
        db_handler.write_encrypted_database(db_file_path)

        clear_screen()


def show_summary(input_list=None):

    """
    Display a summary of the entries in the database

    """

    global db_handler

    data_summary = []

    length = db_handler.get_number_of_records()

    if (input_list == None):

        for i in range(length):
            r = db_handler.get_record_at_index_with_enc_pw(i)
            data = [(i+1), r.get_website(), r.get_email(), r.get_username(),  r.get_group()]
            data_summary.append(data)
    else:

        data_summary = []

        for i in range(len(input_list)):
            r = db_handler.get_record_at_index_with_enc_pw(input_list[i])
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

    global db_handler

    data_summary = []

    global term_len_h, term_len_v

    term_len_h, term_len_v = os.get_terminal_size()

    input_list = db_handler.get_records_last_modified()

    header = []
    data_ratio = []

    if (term_len_h > 100):

        header = [['Site', 3], ['   Group', 1], ['    Last Modified', 1.5]]
        data_ratio = [3, 1, 1.5]

        for i in range(len(input_list)):
            r = input_list[i][0]
            index = input_list[i][1]
            data = [(index+1), r.get_website(), r.get_group(), r.get_last_modified()]
            data_summary.append(data)
    else:

        header = [['Site', 3], ['    Last Modified', 2]]
        data_ratio = [3, 2]

        for i in range(len(input_list)):
            r = input_list[i][0]
            index = input_list[i][1]
            data = [(index+1), r.get_website(), r.get_last_modified()]
            data_summary.append(data)

    # This is for partitioning space & printing out header according to the
    # ratio specified by the second index

    print_block(1)
    print(color_menu_column_header(header))
    print_block(1)

    for item in data_summary:
        formatted_data = format_data_with_spacing(item, data_ratio)
        print(formatted_data)

    print_block(1)
    print(plain_menu_bars())
    print_block(1)


def show_index(index=None, display_multiple_index=False):

    """
    Display the record at the specified index from database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global db_handler

    if (index == None):
        return

    r = db_handler.get_record_at_index_with_enc_pw(index)

    header = ['Site', 'Password', 'Email', 'Username', 'Group', 'Phone#', \
            'Two Factor', 'Recovery Email', 'Last Modified', 'Notes']

    data = [r.get_website(), '', r.get_email(), r.get_username(), \
            r.get_group(), r.get_phone_number(), r.get_two_factor(), \
            r.get_recovery_email(), r.get_last_modified(), r.get_remark()]

    if (not display_multiple_index):
        print_block(1)
        print(plain_menu_bars())
        print_block(1)

        display_row_with_sec_mem(header, data, index)

        print_block(1)
        print(plain_menu_bars())
        print_block(1)
    else:
        display_row_with_sec_mem(header, data, index)


def get_record_at_index(index=None):

    """
    Display the record at the specified index from database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global db_handler

    if (index == None):
        return

    r = db_handler.get_record_at_index_with_enc_pw(index)

    header = ['Site', 'Password', 'Email', 'Username', 'Group', 'Phone#', \
            'Two Factor', 'Recovery Email', 'Last Modified', 'Notes']

    data = [r.get_website(), '', r.get_email(), r.get_username(), \
            r.get_group(), r.get_phone_number(), r.get_two_factor(), \
            r.get_recovery_email(), r.get_last_modified(), r.get_remark()]

    return header, data


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
            print_block(1)
            print(plain_menu_bars())
            print_block(1)
        else:
            print_block(2)


def delete_index(index=None):

    """
    Deletes record at the specified index, supports list of indexes
    """

    global db_handler, db_file_path

    if (index == None):
        return

    elif (type(index) == int):
        db_handler.remove_index(index)
        db_handler.write_encrypted_database(db_file_path)
        clear_screen()

    elif (type(index) == list):

        show_summary(index)

        choice = prompt_yes_no_instant("The records above will be deleted, continue? (y/N): ", False)

        print_block(1)

        if (choice):
            db_handler.remove_index(index) # This function is aware of lists 
            db_handler.write_encrypted_database(db_file_path)

        clear_screen()


def audit_records():

    """
    Performs security audit on internal database

    """
    ## Requires >= 100 width term, this check is 
    ## being done by arg_parser() so skipping this one

    global db_handler

    header, data = process_security_data()

    print_block(1)
    print(color_menu_column_header(header))
    print_block(1)

    ratio = [5,4,4,2,2.5]

    for r in data:
        print_audit_info(r, ratio)

    print_block(1)
    print(plain_menu_bars())
    print_block(1)


def process_security_data():

    global db_handler, db_file_path

    db_handler.audit_security()
    db_handler.write_encrypted_database(db_file_path)

    sorted_indexes = db_handler.sort_security_rating()

    header = [['Site',4.2] , ['PW Age',3.4], ['PW Reuse',3], ['    PW Strength',2],  ['Security Rating',1.5]]

    data = []

    color_rst          = color_reset()
    color_worst_shadow = '\x1B[1;38;5;196m\x1B[1;48;5;232m' 
    color_worst        = '\x1B[1;38;5;196m' 
    color_red          = color_b('red')
    color_gray         = '\x1B[1;38;5;246m' 
    color_yellow       = color_b('yellow')
    color_green        = color_b('green')  

    color_superb = '\x1B[1;38;5;87m'
    color_excellent = '\x1B[1;38;5;39m'
    color_good = '\x1B[1;38;5;79m'


    for i in range(len(sorted_indexes)):

        index = sorted_indexes[i]

        r = db_handler.get_record_at_index_with_enc_pw(index)

        site = r.get_website()

        site_info = [site, color_rst]

        """
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                                             Ratings
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

         pw_complexity (6)  's' =  6, 'e' =  5, 'g' =  2, 'a' =  0, 'w' = -3, 'u' = -6
         pw_age        (3)  'n' =  3, 'o' =  1, 'r' = -3, 't' = -5, 'h' = -6
         pw_reuse      (6)  '0' =  6, '1' =  0

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         Total score (15)     max = 15, min = 0 (negative values are set to 0)
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

            (15) Superb
            (14) Excellent
         (12-13) Good
         (10-11) Average
           (7-9) Weak
           (0-6) Critical

        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """

        pw_cmpx = r.get_pw_complexity()
        pw_cmpx_info = ''

        ## Adding data & color information as a list instead of hardcoded strings
        ## cos during display function it causes issues with text alignment

        if (pw_cmpx == 's'):
            color_info = '%s' % (color_superb)
            pw_cmpx_info = ['Superb', color_info]
        elif (pw_cmpx == 'e'):
            color_info = '%s' % (color_excellent)
            pw_cmpx_info = ['Excellent', color_info]
        elif (pw_cmpx == 'g'):
            color_info = '%s' % (color_good)
            pw_cmpx_info = ['Good', color_info]
        elif (pw_cmpx == 'a'):
            color_info = '%s' % (color_yellow)
            pw_cmpx_info = ['Average', color_info]
        elif (pw_cmpx == 'w'):
            color_info = '%s' % (color_red)
            pw_cmpx_info = ['Weak', color_info]
        elif (pw_cmpx == 'u'):
            color_info = '%s' % (color_worst)
            pw_cmpx_info = ['Unsuitable', color_info]
        elif (pw_cmpx == ''):
            color_info = '%s' % (color_gray)
            pw_cmpx_info = ['Audit Pending', color_info]

        pw_age = r.get_pw_age()
        pw_age_info = ''

        ## pw_age (3)  'n' =  3, 'o' =  1, 'r' = -3, 't' = -5, 'h' = -6
        if (pw_age == 'n'):
            color_info = '%s' % (color_green)
            pw_age_info = ['< 6 months', color_info]
        elif (pw_age == 'o'):
            color_info = '%s' % (color_yellow)
            pw_age_info = ['<= 1 year', color_info]
        elif (pw_age == 'r'):
            color_info = '%s' % (color_red)
            pw_age_info = ['1-1.5 year', color_info]
        elif (pw_age == 't'):
            color_info = '%s' % (color_red)
            pw_age_info = ['1.5-2 years', color_info]
        elif (pw_age == 'h'):
            color_info = '%s' % (color_worst)
            pw_age_info = ['> 2 years', color_info]
        elif (pw_age == ''):
            color_info = '%s' % (color_gray)
            pw_age_info = ['Audit Pending', color_info]

        pw_reuse = r.get_pw_reuse()
        pw_reuse_info = ''

        ## pw_reuse  (6)  '0' =  6, '1' =  0
        if (pw_reuse == '0'):
            color_info = '%s' % (color_yellow)
            pw_reuse_info = ['Not Found', color_info]
        elif (pw_reuse == '1'):
            color_info = '%s' % (color_red)
            pw_reuse_info = ['Found', color_info]

        s_rating = r.get_security_rating()
        s_rating_info = ''

        if (s_rating == ''):
            color_info = '%s' % (color_gray)
            s_rating_info = ['Audit Pending', color_info]

        else:

            ##    (15) Superb
            ##    (14) Excellent
            ## (12-13) Good
            ## (10-11) Average
            ##   (7-9) Weak
            ##   (0-6) Critical

            try:
                s_rating = int(s_rating)
            except ValueError:
                continue

            if (s_rating == 15):
                color_info = '%s' % (color_superb)
                s_rating_info = ['Superb', color_info]
            elif (s_rating == 14):
                color_info = '%s' % (color_excellent)
                s_rating_info = ['Excellent', color_info]
            elif (s_rating in [12,13]):
                color_info = '%s' % (color_good)
                s_rating_info = ['Good', color_info]
            elif (s_rating in [10,11]):
                color_info = '%s' % (color_yellow)
                s_rating_info = ['Average', color_info]
            elif (s_rating in [7,8,9]):
                color_info = '%s' % (color_red)
                s_rating_info = ['Weak', color_info]
            elif (s_rating in [0,1,2,3,4,5,6]):
                color_info = '%s' % (color_worst_shadow)
                s_rating_info = ['Critical', color_info]

        color_info = '%s' % (color_yellow)

        _index = [index+1, color_info]

        tmp_data = [ _index, site_info, pw_age_info, pw_reuse_info, pw_cmpx_info, s_rating_info ]

        data.append(tmp_data)

    return header, data


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

    ## tmp_data = [ _index, site_info, pw_age_info, pw_reuse_info, pw_cmpx_info, s_rating_info ]
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
            color_text_with_transparent_bg(''.join(list_to_be_processed[0]), data_list[1][1]) + \
            color_text_with_transparent_bg(''.join(list_to_be_processed[1]), data_list[2][1]) + \
            color_text_with_transparent_bg(''.join(list_to_be_processed[2]), data_list[3][1]) + \
            color_text_with_transparent_bg(''.join(list_to_be_processed[3]), data_list[4][1]) + \
            color_text_with_transparent_bg(''.join(list_to_be_processed[4]), data_list[5][1])

    print(text)


def copy_password(index=None):

    """
    Copy the specified index from database to clipboard

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global db_handler, config

    if (index == None):
        return

    try:

        pw = db_handler.get_pw_of_index(index)

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

                if (import_lib_wx()):
                    gui_msg('\n\t\t   Unable to copy password to clipboard' + \
                            "\n\nPlease update your password so that it doesn't use single quotes")
                else:
                    print(text_error('Unable to copy password to clipboard'))
                    print(text_debug("Please update your password so that it doesn't use single quotes") + '\n')
                    sys.exit(1)
        else:

            cmd1 = 'echo -n \'%s\' | xclip -selection clipboard' % pw
            os.system(cmd1)

        clear_clipboard()

    except IncorrectPasswordException:

        if (import_lib_wx()):
            gui_msg('\nDecyption of password field in database failed!' + \
                    '\n\n       Database could be partially corrupted')
        else:
            print(text_error('Decyption of password field in database failed!'))
            print(text_debug('Database could be corrupted, consider re-importing data using csv') + '\n')


def search(keyword=''):

    global db_handler

    if (keyword == ''):
        return

    result = db_handler.search_all(keyword)

    if (len(result) == 0):
        print_block(1)
        print(text_debug('Nothing found'))
        print_block(1)
    else:
        show_summary(result)


def search_extended(keyword='', category=''):

    global db_handler

    if (keyword == '' or category == ''):
        return

    result = []

    if (category == 'group'):
        result = db_handler.search_group(keyword)
    elif (category == 'site'):
        result = db_handler.search_website(keyword)
    elif (category == 'email'):
        result = db_handler.search_email(keyword)
    elif (category == 'username'):
        result = db_handler.search_username(keyword)

    if (len(result) == 0):
        print_block(1)
        print(text_debug('Nothing found'))
        print_block(1)
    else:
        show_summary(result)


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Clipboard Functions                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def secure_copy_password(index=None):

    """
    Uses a secure version of the original method, differece being that it
        erases memory after operation is complete

    Copy the specified index from database to clipboard

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global db_handler, config

    if (index == None):
        return

    sec_mem_handler = None

    try:

        sec_mem_handler = db_handler.get_pw_of_index_with_sec_mem(index)
        sec_mem_handler.copy_to_clipboard() # Auto wipes memory so no further action needed
        print()
        clear_clipboard()

    except IncorrectPasswordException:

        if (import_lib_wx()):
            gui_msg('\nDecyption of password field in database failed!' + \
                    '\n\n       Database could be corrupted, consider re-importing data using csv')
        else:

            print(text_error('Decyption of password field in database failed!'))
            print(text_debug('Database could be corrupted, consider re-importing data using csv') + '\n')

        sys.exit(1)

    except SecureClipboardCopyFailedException:
        print(text_error('Secure memory wipe function is unavailable (libc.so not found), using insecure method!'))
        copy_password(index)


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


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Secure Printing Function                                         ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def secure_edit_index(index=None):

    """
    Edit a record at the specified index & update it to database

    Args: The (index-1) that was shown to user in show_summary() function

    """

    global db_handler, db_file_path, field_color_fg, theme, term_len_h

    if (index == None):
        return

    initialize_theme()

    r = db_handler.get_record_at_index_with_enc_pw(index)

    header = ['Website', 'Password', 'Username', 'Email', 'Group', 'Notes', \
              'Two-factor', 'Recovery-email', 'Phone-number']

    data = [r.get_website(), '', r.get_username(), \
            r.get_email(), r.get_group(), r.get_remark(), r.get_two_factor(), \
            r.get_recovery_email(), r.get_phone_number()]

    sec_mem_handler = None

    sec_mem_handler_new = None

    try:
        sec_mem_handler = db_handler.get_pw_of_index_with_sec_mem(index)

    except IncorrectPasswordException:
        if (import_lib_wx()):
            gui_msg('\nDecyption of password field in database failed!' + \
                    '\n\n       Database could be corrupted, consider re-importing data using csv')
        else:
            print(text_error('Decyption of password field in database failed!'))
            print(text_debug('Database could be corrupted, consider re-importing data using csv') + '\n')
        sys.exit(1)

    except SecureClipboardCopyFailedException:
        if (import_lib_wx()):
            gui_msg('\n        Secure memory wipe function is unavailable (libc.so not found)' + \
                    '\n\nTry installing glibc package. If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    cursor_hide()
    custom_refresh(print_menu_bars=False, n1=1)

    print(info_bar_dynamic('Edit Records | Press (e) to Edit | (Enter) to Skip | (q) Quit without saving'))
    print_block(4)

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
                        data[i] = prompt_yes_no_instant("Two Factor authentication enabled? (y/N): ", False)
                        data_changed = True
                        cursor_hide()
                        break
                    else:
                        data[i] = prompt_for_edit_with_blank("           " + ' '*5)
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

                    cursor_show()
                    clear_screen()
                    sys.exit(1)

        except KeyboardInterrupt:

            sec_mem_handler.wipe_memory()

            if (sec_mem_handler_new != None):
                sec_mem_handler_new.wipe_memory()

            cursor_show()
            clear_screen()
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

            db_handler.update_index_with_sec_mem(r, index, sec_mem_handler_new)

        else:

            db_handler.update_index_with_sec_mem(r, index, sec_mem_handler)

        db_handler.write_encrypted_database(db_file_path)

    sec_mem_handler.wipe_memory()

    if (sec_mem_handler_new != None):
        sec_mem_handler_new.wipe_memory()

    cursor_show()
    clear_screen()


def display_row_with_sec_mem(field_list=[], data_list=[], index=None, header_width=20, indent=5):

    global term_len_h, theme, field_color_fg, config

    if (len(data_list) == 0 or len(field_list) == 0):
        return

    if (term_len_h < 50):
        print(text_error('Terminal size too small to display data'))
        sys.exit(1)

    if (not global_value_initialized(theme)):
        theme = ''

    try:

        sec_mem_handler = db_handler.get_pw_of_index_with_sec_mem(index)

    except IncorrectPasswordException:

        if (import_lib_wx()):
            gui_msg('\nDecyption of password field in database failed!' + \
                    '\n\n       Database could be corrupted, consider re-importing data using csv')
        else:
            print(text_error('Decyption of password field in database failed!'))
            print(text_debug('Database could be corrupted, consider re-importing data using csv') + '\n')

        sys.exit(1)

    except SecureClipboardCopyFailedException:
        if (import_lib_wx()):
            gui_msg('\n        Secure memory wipe function is unavailable (libc.so not found)' + \
                    '\n\nTry installing glibc package. If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    theme_num = config.get('theme')

    color_not_audited = '\x1B[1;38;5;250m\x1B[1;48;5;232m'
    color_unsuitable  = '\x1B[1;38;5;88m\x1B[1;48;5;232m'
    color_bad         = '\x1B[1;38;5;9m\x1B[1;48;5;232m'
    color_neutral     = '\x1B[1;38;5;221m\x1B[1;48;5;232m'
    color_good        = '\x1B[1;38;5;79m\x1B[1;48;5;232m'
    color_excellent   = '\x1B[1;38;5;39m\x1B[1;48;5;232m'
    color_superb      = '\x1B[1;38;5;87m\x1B[1;48;5;232m'
    color_rst = color_reset()

    audit_rating = db_handler.audit_pw_complexity(sec_mem_handler.get_str())

    last_mod_rating = db_handler.audit_pw_age_single_record(index)

    max_length = 0

    for i in range(len(data_list)):
        if (len(data_list[i]) > max_length):
            max_length = len(data_list[i])

    indent_text = ' ' * indent

    for i in range(len(data_list)):

        h_list = list(' ' * header_width)

        text_list = []

        f_list_char = list(field_list[i])

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
                        text_highlight(''.join(h_list)) + \
                        field_color_fg + ''.join(text_list[0]) + color_rst
            else:
                text = field_color_fg + indent_text + \
                        text_highlight(''.join(h_list)) + \
                        ''.join(text_list[0])

            print(text)

            for line in text_list[1:]:

                text = indent_text + ' ' * len(h_list) + ''.join(line) + color_rst

                print(text)
        else:

            for k in range(len(d_list_char)):
                text_l_obj[k] = d_list_char[k]

            if (i == 1):

                text = ''

                if (theme_num == 66):

                    text = '\x1B[1;38;5;214m' + indent_text + \
                            text_highlight(''.join(h_list))
                else:

                    text = field_color_fg + indent_text + \
                            text_highlight(''.join(h_list))

                sys.stdout.write(text)

                pw_sec_color = ''

                ## pw_complexity (6)  's' =  6, 'e' =  5, 'g' =  2,
                ##                    'a' =  0, 'w' = -3, 'u' = -6

                if (theme_num == 66):

                    if (audit_rating == ''):
                        pw_sec_color = color_not_audited
                    elif (audit_rating == 'u'):
                        pw_sec_color = color_unsuitable
                    elif (audit_rating == 'w'):
                        pw_sec_color = color_bad
                    elif (audit_rating == 'a'):
                        pw_sec_color = color_neutral
                    elif (audit_rating == 'g'):
                        pw_sec_color = color_good
                    elif (audit_rating == 'e'):
                        pw_sec_color = color_excellent
                    elif (audit_rating == 's'):
                        pw_sec_color = color_superb
                    else:
                        pw_sec_color = color_not_audited

                sys.stdout.write('%s' % pw_sec_color)
                sec_mem_handler.print_str()
                sys.stdout.write('%s' % color_rst)
                print()

            elif (i == 8 and theme_num == 66):

                ## pw_age (3)  'n' =  3, 'o' =  1,
                ##             'r' = -3, 't' = -5, 'h' = -6

                last_mod_color = ''

                if (last_mod_rating == 'n'):
                    last_mod_color = color_good
                elif (last_mod_rating == 'o'):
                    last_mod_color = color_neutral
                elif (last_mod_rating == 'r' or \
                      last_mod_rating == 't' or \
                      last_mod_rating == 'h'):
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


                text = '\x1B[1;38;5;214m' + indent_text + text_highlight(''.join(h_list)) + \
                        last_mod_color + ''.join(text_l_obj) + color_rst

                print(text)

            else:

                text = ''

                if (theme_num == 66):

                    text = '\x1B[1;38;5;214m' + indent_text + \
                            text_highlight(''.join(h_list)) + \
                            field_color_fg + ''.join(text_l_obj) + color_rst
                else:

                    text = field_color_fg + indent_text + \
                            text_highlight(''.join(h_list)) + \
                            ''.join(text_l_obj)

                print(text)

    sec_mem_handler.wipe_memory()


def display_row_static_with_sec_mem(field_list=[], data_list=[], index=None, header_width=20, indent=5):

    global config, term_len_h, term_len_v, theme, field_color_fg, db_handler, sec_mem_handler

    if (len(data_list) == 0 or len(field_list) == 0 or index == None):
        return

    if (term_len_h < 50):
        print(text_error('Terminal size too small to display data'))
        sys.exit(1)

    theme_num = config.get('theme')

    if (not global_value_initialized(theme)):
        theme = ''

    sec_mem_handler = None

    color_not_audited = '\x1B[1;38;5;250m\x1B[1;48;5;232m'
    color_unsuitable  = '\x1B[1;38;5;88m\x1B[1;48;5;232m'
    color_bad         = '\x1B[1;38;5;9m\x1B[1;48;5;232m'
    color_neutral     = '\x1B[1;38;5;221m\x1B[1;48;5;232m'
    color_good        = '\x1B[1;38;5;79m\x1B[1;48;5;232m'
    color_excellent   = '\x1B[1;38;5;39m\x1B[1;48;5;232m'
    color_superb      = '\x1B[1;38;5;87m\x1B[1;48;5;232m'

    color_rst = color_reset()

    try:
        sec_mem_handler = db_handler.get_pw_of_index_with_sec_mem(index)

    except IncorrectPasswordException:
        if (import_lib_wx()):
            gui_msg('\nDecyption of password field in database failed!' + \
                    '\n\n       Database could be corrupted, consider re-importing data using csv')
        else:
            print(text_error('Decyption of password field in database failed!'))
            print(text_debug('Database could be corrupted, consider re-importing data using csv') + '\n')
        sys.exit(1)

    except SecureClipboardCopyFailedException:
        if (import_lib_wx()):
            gui_msg('\n        Secure memory wipe function is unavailable (libc.so not found)' + \
                    '\n\nTry installing glibc package. If problem persists, switch to pwmgr v2.1.1')
        sys.exit(1)

    audit_rating = db_handler.audit_pw_complexity(sec_mem_handler.get_str())

    last_mod_rating = db_handler.audit_pw_age_single_record(index)

    count = 0

    try:

        while (True):

            sleep(0.05)

            term_len_var_h, term_len_var_v = os.get_terminal_size()

            if (term_len_var_h == term_len_h and \
                    term_len_var_v == term_len_v and \
                    count != 0):

                continue

            else:

                if (term_len_var_v < 14):

                    clear_screen()
                    print_block(1)
                    print(text_error('Vertical screen size too small to display data'))
                    sleep(1)
                    clear_screen()
                    sleep(0.5)
                    continue

                count += 1

                term_len_h = term_len_var_h
                term_len_v = term_len_var_v

                # This is the number of vertical lines excluding
                #     data that needs to be printed
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
                                text_highlight(''.join(h_list)) + ''.join(text_list[0])

                        print(text)

                        for line in text_list[1:]:

                            if (theme_num == 66):
                                text = indent_text + ' ' * len(h_list)  + ''.join(line) + color_rst
                            else:
                                text = field_color_fg + indent_text + ' ' * len(h_list) + color_rst + ''.join(line) + color_rst

                            print(text)
                    else:

                        for k in range(len(d_list_char)):
                            text_l_obj[k] = d_list_char[k]

                        if (i == 1):

                            pw_sec_color = ''

                            text = field_color_fg + indent_text + text_highlight(''.join(h_list))
                            sys.stdout.write(text)

                            if (theme_num == 66):
                                ## pw_complexity (6)  's' =  6, 'e' =  5, 'g' =  2,
                                ##                    'a' =  0, 'w' = -3, 'u' = -6

                                if (audit_rating == ''):
                                    pw_sec_color = color_not_audited
                                elif (audit_rating == 'u'):
                                    pw_sec_color = color_unsuitable
                                elif (audit_rating == 'w'):
                                    pw_sec_color = color_bad
                                elif (audit_rating == 'a'):
                                    pw_sec_color = color_neutral
                                elif (audit_rating == 'g'):
                                    pw_sec_color = color_good
                                elif (audit_rating == 'e'):
                                    pw_sec_color = color_excellent
                                elif (audit_rating == 's'):
                                    pw_sec_color = color_superb
                                else:
                                    pw_sec_color = color_not_audited

                                sys.stdout.write('%s' % pw_sec_color)
                                sec_mem_handler.print_str()
                                sys.stdout.write('%s' % color_rst)

                            else:
                                sec_mem_handler.print_str()

                            print()

                        else:

                            if (i == 8 and theme_num == 66):

                                ## pw_age (3)  'n' =  3, 'o' =  1,
                                ##             'r' = -3, 't' = -5, 'h' = -6

                                last_mod_color = ''

                                if (last_mod_rating == 'n'):
                                    last_mod_color = color_good
                                elif (last_mod_rating == 'o'):
                                    last_mod_color = color_neutral
                                elif (last_mod_rating == 'r' or \
                                      last_mod_rating == 't' or \
                                      last_mod_rating == 'h'):
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
                                text = field_color_fg + indent_text + text_highlight(''.join(h_list)) + ''.join(text_l_obj)
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

    cursor_show()
    clear_screen()
    sys.exit(0)


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Advanced Printing Function                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def color_menu_column_header(header_list=[], left_indent=7):

    global term_len_h, theme

    if (not global_value_initialized(theme)):
        theme = ''

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

        ## Making sure we have 2 space between fields
        if (len(char_list)+1 >= space_partition):
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


def format_text_center(text='', term_len_h=''):

    if (len(text) > term_len_h):
        _text = text.split()
        _text = _text[:term_len_h]
        _text[-1] = '.'
        _text[-2] = '.'
        _text[-3] = '.'
        return ''.join(_text)

    else:

        left_indent = int((term_len_h - len(text)) / 2)
        right_indent = term_len_h - left_indent - len(text)

        return left_indent * ' ' + text + right_indent * ' '


def remove_color_at_index(text='', index=0, pattern=''):

    if (text != ''):

        end_index = index

        try:

            i = index

            for j in range(0, len(pattern)):

                if (text[i] == pattern[j]):
                    i += 1
                    end_index = i
                    continue
                else:
                    return text

            max_count = 3

            l = 0

            while (l < max_count):

                if (text[end_index+l].isdigit()):
                    l += 1
                else:
                    break

            if (l == 0):
                return text

            end_index += l

            if (end_index < len(text) and \
                    text[end_index] == 'm'):

                end_index += 1

                if (index == 0):
                    return text[end_index:]
                else:
                    return text[:index] + text[end_index:]

        except IndexError:
            pass

    return text


def extract_plain_text(text=''):
    '''
    Removes colors codes from text
    '''

    _text = text

    fg_pattern          = '\x1B[0;38;5;'
    fg_bold_pattern     = '\x1B[1;38;5;'
    bg_pattern          = '\x1B[0;48;5;'
    bg_bold_pattern     = '\x1B[1;48;5;'

    color_rst           = '\x1B[0m'
    cursor_show_pattern = '\033[?25h'
    cursor_hide_pattern = '\033[?25l'

    if (fg_pattern in _text):
        index = _text.find(fg_pattern)

        while (index != -1):
            _text = remove_color_at_index(_text, index, fg_pattern)
            index = _text.find(fg_pattern)

    if (fg_bold_pattern in _text):
        index = _text.find(fg_bold_pattern)

        while (index != -1):
            _text = remove_color_at_index(_text, index, fg_bold_pattern)
            index = _text.find(fg_bold_pattern)

    if (bg_pattern in _text):
        index = _text.find(bg_pattern)

        while (index != -1):
            _text = remove_color_at_index(_text, index, bg_pattern)
            index = _text.find(bg_pattern)

    if (bg_bold_pattern in _text):
        index = _text.find(bg_bold_pattern)

        while (index != -1):
            _text = remove_color_at_index(_text, index, bg_bold_pattern)
            index = _text.find(bg_bold_pattern)

    if (color_rst in _text):
        _text = _text.replace(color_rst, '')

    if (cursor_show_pattern in _text):
        _text = _text.replace(cursor_show_pattern, '')

    if (cursor_hide_pattern in _text):
        _text = _text.replace(cursor_hide_pattern, '')

    return _text


def recolour_text(text='', color=''):

    text = list(extract_plain_text(text))

    for i in range(0, len(text)):

        if (i == ' '):
            continue
        else:
            text[i] = color + text[i]
            text[-1] = text[-1] + color_reset()
            break

    return ''.join(text)


def color_text_with_transparent_bg(text='', color=''):

    _text = list(text)

    rst = color_reset()

    i = 0

    while (i < len(_text)):

        if (_text[i] != ' '):
            _text[i] = color + _text[i]

            j = i+1

            while(j < len(text)):

                if (_text[j] == ' ' or j == len(_text)-1):
                    _text[j] = rst + _text[j]
                    break
                else:
                    j += 1

            i = j+1

        else:

            i += 1

    return ''.join(_text)


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Keyfile & Keyring Functions                                      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

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
        data_l = [data.strip() for data in data_l]
        return (True, ''.join(data_l))


def keyfile_write(fp='', num_bytes=1000):

    initialize_charset()

    global lcase, symbol, ucase, number, char_set_complete

    random.seed()

    kf_data = ''

    for i in range(num_bytes):

        choice = random.choice([0,5,2,4,3,1])

        if (choice == 0 or choice == 1):
            kf_data = "%s%s" % (kf_data, random.choice(symbol))
        elif (choice == 2 or choice == 3):
            kf_data = "%s%s" % (kf_data, random.choice(number))
        elif (choice == 4):
            kf_data = "%s%s" % (kf_data, random.choice(lcase))
        elif (choice == 5):
            kf_data = "%s%s" % (kf_data, random.choice(ucase))

    return write_str_to_file_as_block(kf_data, fp)


def write_str_to_file_as_block(data='', fp=''):

    block_width = 50

    if (len(data) <= block_width):

        with open(fp, 'w'):
            try:
                fp.write(data)
            except IOError:
                return False

    number_of_rows = int(math.ceil(len(data)/block_width))

    index = 0

    with open(fp, 'w') as fh:

        for i in range(number_of_rows):

            if (i == number_of_rows-1):

                try:
                    fh.write(data[index:])
                    fh.write('\n')
                except IOError:
                    return False
            else:

                try:
                    fh.write(data[index:index+block_width])
                    fh.write('\n')
                except IOError:
                    return False

            index += block_width

    return True


def generate_keyfile(fp='', confirm=True, called_by_add_fn=False):

    rst = color_reset()
    color_green  = color_b('green')
    color_yellow = color_b('yellow')

    length = 1000

    clear_screen()
    print_block(1)

    if (not called_by_add_fn):
        print(info_bar_dynamic("Encryption management (generate-keyfile) | (Ctrl+c) Quit without saving"))
        print_block(4)

    while (True):

        l = prompt_with_blank("Enter length (default 1000 bytes): ")

        if (l == ""):
            break

        try:
            l = int(l)
        except (ValueError):
            print(text_error('An integer value is required'))
            continue

        if (l < 1000):
            print(text_error('Length cannot be less that 1000 bytes'))
            continue
        else:
            length = l
            break

    if (fp == ''):

        keyfile_name = 'keyfile'
        _fp = '/home/%s/.config/pwmgr/%s' % (os.getlogin(), keyfile_name)

        if (not os.path.isdir(os.path.dirname(_fp))):
            os.makedirs(os.path.dirname(_fp))

        if (confirm):

            if (os.path.isfile(_fp)):
                print_block(1)
                confirm_txt = 'File exists in \'' + color_green + _fp + \
                               color_yellow + '\'. Overwrite file? (Y/n) '
                r = prompt_yes_no_instant(confirm_txt, True)

                if (not r):
                    print_block(1)
                    sys.exit(0)

        clear_screen()
        print_block(1)
        msg = 'Creating keyfile: %s%s%s' % (color_green, _fp, rst)
        print(text_debug(msg))

        keyfile_write(_fp, length)

        print_block(1)
        print(text_debug('Key file creation successful'))

    else:

        _fp = fp

        if (_fp.startswith('~/')):
            _fp = '/home/%s/%s' % (os.getlogin(), _fp[2:]) 

        if (not os.path.isdir(os.path.dirname(_fp))):
            os.makedirs(os.path.dirname(_fp))

        if (confirm):

            if (os.path.isfile(_fp)):

                print_block(1)
                confirm_txt = 'File exists in \'' + color_green + _fp + \
                               color_yellow + '\'. Overwrite file? (Y/n) '
                r = prompt_yes_no_instant(confirm_txt, True)

                if (not r):
                    print_block(1)
                    sys.exit(0)


        clear_screen()
        print_block(1)
        msg = 'Creating keyfile: %s%s%s' % (color_green, _fp, rst)
        print(text_debug(msg))

        keyfile_write(_fp, length)

        print_block(1)
        print(text_debug('Key file creation successful'))


def use_keyfile(keyfile_path=''):

    global db_handler, config, config_file, db_file_path 

    master_key = db_handler.get_key()

    pw = ''

    kf = config.get('keyfile_path')

    value1 = ''
    color = color_b('yellow')
    rst = color_reset()

    cursor_hide()
    clear_screen()
    print_block(1)
    print(info_bar_dynamic("Encryption management (use-keyfile) | (Ctrl+c) Quit without saving"))
    print_block(4)

    while (True):

        key = ''

        value1 = getpass(color_symbol_info() + color + " Enter password: " + rst)
        value1 = value1.strip()

        if (value1 == ""):
            print(text_error("Field cannot be blank"))
            continue

        if (kf != ''):
            key = db_handler.generate_new_key(value1, False, False, kf)
        else:
            key = db_handler.generate_new_key(value1, False, False)

        if (key != master_key):
            print(text_error("Master password is incorrect, try again"))
            continue
        else:
            pw = value1
            break

    try:
        db_handler.use_keyfile(pw, keyfile_path)
    except (FileNotFoundError):
        print(text_error("Key file not found"))
        sys.exit(0)

    config.update({'keyfile_path':keyfile_path})
    write_config(config, config_file)
    db_handler.write_encrypted_database(db_file_path)

    cursor_show()
    clear_screen()

    if (keyring_set_scrambled(db_handler.get_key()) == False):
        print(text_error("use_keyfile(): Unable to store password in keyring"))
        print_block(1)
        sys.exit(1)


def list_keyfile():

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
        color_green = color_b('green')
        c_rst = color_reset()

        msg = 'Current keyfile: %s%s%s' % (color_green, kf, c_rst)

        print(text_debug(msg))
        print_block(1)

        kf_data = ''

        output = keyfile_load(kf)

        if (output[0]):
            kf_data = bytes(output[1], 'utf-8')

        s = sha256(kf_data)

        hash_value = s.hexdigest()

        msg = 'Keyfile data hash (sha-256): %s%s%s' % \
                (color_green, hash_value, c_rst)

        print(text_debug(msg))

        print_block(1)


def remove_keyfile():

    global db_handler, config, config_file, db_file_path 

    cursor_hide()
    clear_screen()
    print_block(1)
    print(info_bar_dynamic("Encryption management (remove-keyfile) | (Ctrl+c) Quit without saving"))
    print_block(4)

    kf = config.get('keyfile_path')

    color = color_b('yellow')
    rst = color_reset()

    if (kf == ''):
        clear_screen()
        sys.exit(1)

    master_key = db_handler.get_key()
    pw  = ''

    while (True):

        key = ''

        value1 = getpass(color_symbol_info() + color + " Enter password: " + rst)
        value1 = value1.strip()

        if (value1 == ""):
            print(text_error("Field cannot be blank"))
            continue

        key = db_handler.generate_new_key(value1, False, False, kf)

        if (key != master_key):
            print(text_error("Master password is incorrect, try again"))
            continue
        else:
            pw = value1
            print_block(1)
            break

    db_handler.remove_keyfile(pw)

    config.update({'keyfile_path':''})
    write_config(config, config_file)

    db_handler.write_encrypted_database(db_file_path)

    cursor_show()
    clear_screen()

    if (keyring_set_scrambled(db_handler.get_key()) == False):
        print(text_error("use_keyfile(): Unable to store password in keyring"))
        sys.exit(1)


def keyring_get():

    """
    Returns the encryption key stored in keyring
    """

    global app_name

    key_id, stderr, _ = run_cmd('keyctl request user %s' % (app_name))

    if (stderr):
        return False

    key, stderr, _ = run_cmd('keyctl print %s' % key_id)

    if (stderr):
        return False

    return key


def keyring_set(value):

    """
    Set the encryption key in keyring

    """

    global app_name

    _, stderr, _ = run_cmd('keyctl add user %s %s @u' % (app_name, value))

    if (stderr):
        return False

    return True


def keyring_set_scrambled(value):

    output = key_scramble(value)

    temp_key = ''
    scrambled_key = ''

    if (output[0]):

        scrambled_key = output[1][0]
        temp_key      = output[1][1]

        fp = '/home/%s/.config/pwmgr/tmp' % os.getlogin()

        if (not os.path.isdir(fp)):
            os.makedirs(fp)

        temp_key_fp = '%s/temp_key.txt' % fp

        try:
            with open(temp_key_fp, 'w') as fh:
                fh.write(temp_key)
        except IOError:
            return False

        keyring_set(scrambled_key)

        return True

    else:

        return False


def key_scramble(value_str=''):

    if (type(value_str) != str):
        raise InvalidParameterException('key_scramble(): input needs to be of type str')
    elif (value_str == ''):
        raise InvalidParameterException('key_scramble(): input str cannot be empty')

    try:
        _value = base64.urlsafe_b64encode(bytes(value_str, 'utf-8')).decode()
    except (UnicodeEncodeError, BaseException):
        return (False, (), 'key_scramble(): Unable to encode to b64 format')

    converted_output = convert_str_to_int_list(_value)

    value_int_l = []

    if (not converted_output[0]):
        return False
    else:
        value_int_l = converted_output[1]

    temp_key = generate_pass_single(len(_value))

    output_l = []

    for i in range(len(value_int_l)):

        try:
            output_l.append(hex(value_int_l[i] ^ ord(temp_key[i])))
        except (UnicodeEncodeError, BaseException, TypeError, ValueError):
            return (False, (), 'key_scramble(): failed to xor str value with generated key')

    ## hex values separated by ',' are encoded in b64 format
    scrambled_key_b64 = base64.urlsafe_b64encode(bytes(','.join(output_l), 'utf-8')).decode()

    return (True, (scrambled_key_b64, temp_key))


def keyring_get_scrambled():

    scrambled_key = keyring_get()

    if (not scrambled_key):
        return (False, '')

    temp_key = ''

    fp = '/home/%s/.config/pwmgr/tmp' % os.getlogin()

    if (not os.path.isdir(fp)):
        os.makedirs(fp) 

    temp_key_fp = '%s/temp_key.txt' % fp

    try:
        with open(temp_key_fp, 'r') as fh:
            temp_key = fh.read()
    except IOError:
        return (False, '')

    output = key_unscramble(scrambled_key, temp_key)

    if (output[0]):
        return (True, output[1])
    else:
        return (False, '')


def key_unscramble(value='', temp_key=''):

    if (len(value) == 0 or len(temp_key) == 0):
        raise InvalidParameterException('unscramble_key(): input parameters cannot be empty')

    _value = ''

    if (type(value) == str):
        _value = bytes(value, 'utf-8')

    try:
        _value = base64.urlsafe_b64decode(_value).decode()
    except (UnicodeDecodeError, BaseException, ValueError):
        return (False, 'key_unscramble(): error#1 decoding from b64 encoded text')

    _value = _value.split(',')

    # Conversion from hex to int
    for i in range(len(_value)):
        try:
            _value[i] = int(_value[i], 16)
        except ValueError:
            return (False, (), '')

    output_str = ''

    for i in range(len(_value)):

        try:
            output_str += chr(_value[i] ^ ord(temp_key[i]))
        except TypeError:
            return (False, 'key_unscramble(): failed to xor str value with generated key')

    try:
        output_str = base64.urlsafe_b64decode(output_str).decode()
    except (UnicodeDecodeError, BaseException, ValueError):
        return (False, 'key_unscramble(): error#2 decoding from b64 encoded text')

    return (True, output_str)


def keyring_reset():

    """
    Remove the current key from the keyring

    """

    global app_name

    stdout, _, _ = run_cmd('keyctl purge -s user %s' % app_name)

    output = stdout.strip().split(' ')[1]

    if (int(output) == 0):
        print(text_error('No password found in keyring'))
    else:
        print_block(1)
        print(text_debug('Password has been deleted from keyring'))
        print_block(1)


def keyring_set_expiration():

    global config, app_name

    t = config.get('keyring_wipe_interval')

    stdout,stderr,_ = run_cmd('keyctl request user %s' % (app_name))

    if (stderr):
        return False

    key_id = stdout

    _, stderr, _ = run_cmd('keyctl timeout %s %s' % (key_id, t))

    if (stderr):
        return False

    return True


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Utility Functions                                                ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def module_imported(module_name=''):
    # need to import sys module

    if (module_name in sys.modules):
        return True
    else:
        return False


def global_value_initialized(value=''):

    try:

        if (type(value) == str and value != ''):
            return True
        elif (type(value) == int and value != -1):
            return True
        elif (type(value) == float and value != -1):
            return True
        elif (type(value) == dict and len(value) != 0):
            return True
        elif (type(value) == list and len(value) != 0):
            return True
        elif (type(value) == tuple and len(value) != 0):
            return True
        else:
            return False

    except NameError:
        return False


def l(value=''):

    """
    Returns lower case version of input string

    """

    return value.lower()


def convert_list_to_str(l=[]):

    return ','.join(l)


def convert_str_to_int_list(value=''):

    output = []

    for i in range(len(value)):

        try:
            output.append(ord(value[i]))
        except TypeError:
            return (False, [])

    return (True, output)


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
    os.system('clear')


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

        stdout = stdout.decode('utf-8').strip()
        stderr = stderr.decode('utf-8').strip()

        if (verbose == True):
            print(stdout)

        return stdout, stderr, process.returncode


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Search Bar Functions                                             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

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

    global config

    # Setting Background / Foreground colors
    # based on the theme that has been set

    _color_background = ''
    _color_foreground = ''

    if (config.get('theme') == 1):
        _color_background = '#0e3061'
        _color_foreground = '#dfd5c6'
    elif (config.get('theme') == 2):
        _color_background = '#033314'
        _color_foreground = '#e0c572'
    elif (config.get('theme') == 3):
        _color_background = '#000000'
        _color_foreground = '#ed8d07'
    elif (config.get('theme') == 4):
        _color_background = '#0e3e52'
        _color_foreground = '#dfd5c6'
    elif (config.get('theme') == 5):
        _color_background = '#6c3a00'
        _color_foreground = '#dfd5c6'
    elif (config.get('theme') == 6):
        _color_background = '#072a37'
        _color_foreground = '#e5900f'
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

    global db_handler

    summary_list = db_handler.get_summary()

    try:

        index = run_searchbar(summary_list)

        if (index == None):
            sys.exit(1)

    except ValueError:
        sys.exit(1)

    cursor_hide()

    global term_len_h

    header, data = get_record_at_index(index)
    display_row_static_with_sec_mem(header, data, index)


def search_bar_copy():

    """
    Displays search bar & copies chosen password to clipboard

    Args:    N/A

    Returns: N/A
    """

    global db_handler

    summary_list = db_handler.get_summary()

    index = run_searchbar(summary_list)

    if (index == None):
        sys.exit(1)

    secure_copy_password(index)


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Database RW                                                      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def check_database():

    global file_name, db_file_path, app_name, db_handler, password_in_keyring, \
            config, config_file

    pw_master = ''

    lib_gui_available = True

    if (not import_lib_wx()):
        lib_gui_available = False

    config_path = '/home/%s/.config/pwmgr/' % (os.getlogin())

    if (os.path.exists(config_path) == False):
        os.mkdir(config_path)

    db_file_path = '%s%s' % (config_path, file_name)

    db_handler = ManageRecord()

    keyfile_path = config.get('keyfile_path')

    result = True

    if (keyfile_path != ''):

        val = check_files([keyfile_path])

        if (not val):
            msg = 'Keyfile not found in %s' % keyfile_path
            print(text_error(msg))
            sys.exit(1)

    if (os.path.isfile(db_file_path) == False):
        # No database found

        clear_screen()
        print_block(1)
        print(info_bar_dynamic("PWMGR Setup | (Ctrl+c) Quit without saving"))
        print_block(4)
        print(text_debug('No database found'))
        print_block(1)

        if (prompt_yes_no_instant("Do you want to create a new one? (Y/n): ", True)):
            print_block(1)
            pw_master = prompt_password(enforce_min_length=True, min_length=8)
            print_block(1)

            keyfile_name = 'keyfile'
            keyfile_path = ''

            if (prompt_yes_no_instant("Do you want to use a keyfile? (Y/n): ", True)):
                keyfile_path = '/home/%s/.config/pwmgr/%s' % (os.getlogin(), keyfile_name)
                generate_keyfile(keyfile_path, confirm=False, called_by_add_fn=True)

            db_handler.generate_new_key(pw_master, True, True, keyfile_path)
            db_handler.write_encrypted_database(db_file_path)
            config.update({'keyfile_path':keyfile_path})
            write_config(config, config_file)

            pw_master = generate_pass_single(32)

            if (keyring_set_scrambled(db_handler.get_key()) == False):
                print(text_error("check_database(): error#01 Unable to store password in keyring"))
                sys.exit(1)

            if (keyring_set_scrambled(db_handler.get_key())):
                keyring_set_expiration()
            else:

                if (lib_gui_available):
                    gui_msg("Unable to store password in keyring, do you have keyctl installed?")
                else:
                    print(text_error("Unable to store password in keyring, do you have keyctl installed?"))
                    sleep(5)

            clear_screen()
            return

        else:
            print_block(1)
            sys.exit(0)

    # (Previous database exists)
    # We search for password in keyring, if nothing found we prompt user
    #       for master password & attempt to decrypt it
    #

    result = False

    key = keyring_get_scrambled()

    if (key[0]):
        key = key[1]
    else:
        key = False

    '''
     * We use 2 exception handlers, cos IncorrectPasswordException & 
       IncorrectKeyException() overlap with other exception handlers
       so we try to minimise code repetition as much as possible

     * Updated old code (commented out) which mainly used commandline
       for interacting with user. The new one interacts with user
       with GUI prompts for error, password input, etc. It is done
       because if pwmgr is used with key bindings, the user might not
       know if things go wrong as cmd prompt might just close without showing 
       anything.
    '''

    try:
        try:

            if (key == False):

                password_in_keyring = False

                if (lib_gui_available):
                    pw_master = prompt_password_master_gui()

                    if (type(pw_master) == bool and pw_master == False):
                        sys.exit(0)
                else:
                    pw_master = prompt_password_master_cmdline()

                result = db_handler.load_database(filename=db_file_path, \
                                                      password=pw_master, \
                                                      load_key_from_keyring=False, \
                                                      path_to_keyfile=keyfile_path)
            else:

                result = db_handler.load_database(filename=db_file_path, \
                                                      load_key_from_keyring=True, \
                                                      enc_key=bytes(key, 'utf-8'))

        except (UnsupportedFileFormatException):

            if (lib_gui_available):

                gui_msg("\n\n  Unfortunately PWMGR no longer supports this file format\n\n" + \
                        "  Go through the following steps to fix the problem:\n\n" + \
                        "    1.  Export database using 'export-csv data.csv' on pwmgr 2.6 or earlier\n" + \
                        "    2.  Remove current installation: 'rm -rf ~/.config/pwmgr/'\n" + \
                        "    3.  Run 'import data.csv' on latest version of pwmgr >= 3.0\n\n" + \
                        "  * Releases section of the github page lists downloadable versions\n")
            else:

                print(text_error("Unfortunately PWMGR no longer supports this file format"))

                msg =  "  Go through the following steps to fix the problem:\n\n" + color_b('yellow') + \
                       "    1.  Export database using 'export data.csv' on pwmgr 2.6 or earlier\n" + \
                       "    2.  Remove current installation: 'rm -rf ~/.config/pwmgr/'\n" + \
                       "    3.  Run 'import data.csv' on latest version of pwmgr >= 3.0\n\n" + color_reset() + \
                       "  * Releases section of the github page lists downloadable versions\n" 

                print(msg)

            sys.exit(0)

        except (IntegrityCheckFailedException):

            r = False

            if (lib_gui_available):
                r = gui_confirmation('\nHash mismatch detected. Data could have been corrupted!\n\n' + \
                                     '\t\t\tPress OK to repair database\n')
            else:
                pass

            if (r):

                if (key):
                    result = db_handler.load_database(filename=db_file_path,            \
                                                          override_integrity_check=True, \
                                                          load_key_from_keyring=True,    \
                                                          enc_key=bytes(key, 'utf-8'))
                else:
                    result = db_handler.load_database(filename=db_file_path, password=pw_master, \
                                                          override_integrity_check=True, \
                                                          path_to_keyfile=keyfile_path)

                if (result): # Database decryption succeeded
                    db_handler.write_encrypted_database(db_file_path)
                    # wiping pw with random values
                    key       = generate_pass_single(32)
                    pw_master = generate_pass_single(32)
                    sys.exit(0)
            else:
                sys.exit(0)


        if (result):  # Database decryption succeeded

            ## TODO: option in config to disable key scrambling if its buggy
            if (password_in_keyring == False):
                if (keyring_set_scrambled(db_handler.get_key())):
                    keyring_set_expiration()
                else:
                    if (lib_gui_available):
                        gui_msg("Unable to store password in keyring, do you have keyctl installed?")
                    else:
                        print(text_error("Unable to store password in keyring, do you have keyctl installed?"))

        # wiping pw with random values
        key       = generate_pass_single(32)
        pw_master = generate_pass_single(32)

    except IncorrectPasswordException:

        if (lib_gui_available):
            gui_msg('\nUnable to decrypt data due to incorrect password / keyfile\n')
        else:
            print(text_error('Unable to decrypt data due to incorrect password / keyfile'))

        sys.exit(1)

    except DataCorruptedException:

        if (lib_gui_available):
            gui_msg('\nDatabase is corrupted, try to restore from backup\n')
        else:
            print(text_error('Database is corrupted, try to restore from backup'))

        sys.exit(1)

    except IncorrectKeyException:

        if (lib_gui_available):
            gui_msg("\nUnable to decrypt data as stored key is incorrect." + \
                    "\n\nPlease use 'keyring-clear' to remove it\n")
        else:
            print(text_error("Unable to decrypt data as stored key is incorrect.\n" + \
                 "Please use 'keyring-clear' to remove it"))

        sys.exit(1)


def exit_if_database_is_empty():

    global db_handler

    n = db_handler.get_number_of_records()

    if (n == 0):
        print_block(1)
        print(text_debug('No records found in database'))
        print_block(1)
        sys.exit(0)


def key_show():

    """
    Display the current key that is being used for encryption

    Note: Needs to be called after database has been loaded in memory using
          the check_database() function
        
    """

    global db_handler

    c_value = color_b('green')
    c_rst = color_reset()

    key = db_handler.get_key()
    print()
    msg = 'Current Key: %s%s%s' % (c_value, key, c_rst)
    print(text_debug(msg))
    print()


def pw_reset():

    """
    Change the current password that is used for database encryption 

    Note: Needs to be called after database has been loaded in memory using
          the check_database() function

    """

    global app_name, db_handler, db_file_path, config

    cursor_hide()
    clear_screen()
    print_block(1)
    print(info_bar_dynamic("Encryption management (pw-reset) | (Ctrl+c) Quit without saving"))
    print_block(4)

    kf = config.get('keyfile_path')

    new_pwd = ''

    try:
        new_pwd = prompt_password_master(8)
    except KeyboardInterrupt:
        clear_screen()
        sys.exit()

    if (kf != ''):

        db_handler.use_keyfile(new_pwd, kf)
    else:
        db_handler.change_password(new_pwd)

    db_handler.write_encrypted_database(db_file_path)

    keyring_set_scrambled(db_handler.get_key())

    cursor_show()
    clear_screen()


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   File IO functions                                                ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def read_from_file(fp='', chars_to_skip=[], \
        startswith_char_l=[], endswith_char_l=[]):

    if (not os.path.isfile(fp)):
        return (False, [])

    data = []

    try:

        with open(fp, 'r') as fh:
            data = fh.read().strip().splitlines()

    except (IOError, BaseException) as e:
        return (False, [])

    data = remove_all_elements_from_list(data, chars_to_skip, \
            startswith_char_l, endswith_char_l)

    return (True, data)


def write_list_to_file(data=[], fp=''):

    if (fp == ''):
        raise InvalidParameterException('write_list_to_file(): input file cannot be empty')
    elif (len(data) == 0):
        return False

    try:

        with open(fp, 'w') as fh:

            for item in data:
                _item = '%s\n' % item
                fh.writelines(_item)

    except (IOError, BaseException):
        return False

    return True


def file_exists(fp=''):

    '''
    Returns the abs path if '~' is present
    '''

    if (fp == ''):
        return False

    _fp = ''

    if (fp.startswith('~/')):
        _fp = '/home/%s/%s' %(os.getlogin(),fp[2:])
    else:
        _fp = fp

    if (os.path.isfile(_fp)):
        return (True, _fp)
    else:
        return (False, '')


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

        stdout, _, rc = run_cmd(['which %s' % p])

        if (rc == 1):
            return False, p
        else:
            l.append(stdout)

    return True, ''


def remove_all_elements_from_list(l=[], element_l=[], \
        starts_with_l=[], ends_with_l=[]):

    _l = l

    for item in element_l:
        _l = [x for x in _l if x != item]

    for item in starts_with_l:
        _l = [x for x in _l if x.startswith(item) != True]

    for item in ends_with_l:
        _l = [x for x in _l if x.endswith(item) != True]

    return _l


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Import / Export Functions                                        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def import_from_csv(file_name):

    """
    Imports from csv formatted file into database
    """

    global db_handler, db_file_path

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

            db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 3):

            if (r[0].strip() in ['site', 'website', 'address'] and \
                    r[1].strip() in ['password', 'pass', 'pwd'] and \
                    r[2].strip() in ['username', 'user', 'usr']):

                csv_list = csv_list[1:]

            db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 4):

            if (r[0].strip() in ['site', 'website', 'address'] and \
                    r[1].strip() in ['password', 'pass', 'pwd'] and \
                    r[2].strip() in ['username', 'user', 'usr'] and \
                    r[3].strip() in ['email', 'mail']):

                csv_list = csv_list[1:]

            db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 5):

            if (r[0].strip() in ['site', 'website', 'address'] and \
                    r[1].strip() in ['password', 'pass', 'pwd'] and \
                    r[2].strip() in ['username', 'user', 'usr'] and \
                    r[3].strip() in ['email', 'mail'] and \
                    r[4].strip() in ['notes', 'comment', 'remark']):

                csv_list = csv_list[1:]

            db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 10):

            if (','.join(r) ==
                    'site,pass,last_modified,email,username,group,remark,two_factor,recovery_email,phone_number'):

                csv_list = csv_list[1:]

            db_handler.convert_csvlist_to_record(csv_list)

        elif (len(r) == 14):

            header = 'site,pass,last_modified,email,username,group,remark,two_factor,recovery_email,' + \
                    'phone_number,pw_age,pw_reuse,pw_complexity,security_rating'
            
            if (','.join(r) == header):

                csv_list = csv_list[1:]

            db_handler.convert_csvlist_to_record(csv_list)

        else:

            text_error("Unable to import database from csv file due to unsupported format")
            print_block(1)
            sys.exit(1)

        db_handler.write_encrypted_database(db_file_path)

        cursor_show()
        print(text_debug('%s entries have been imported to database' % len(csv_list)))
        print_block(1)
    else:
        print_block(1)
        print(text_error('Incorrect csv format detected '))
        print(text_debug('Two formats are accepted. Read \'import csv\' section'))
        print_block(1)
        sys.exit(1)


def export_to_csv(file_name):

    """
    Exports csv formatted database to the specified file
    """

    global db_handler

    exit_if_database_is_empty()

    db_handler.export_csv(file_name)

    cursor_show()
    print(text_debug('Exported database to: %s%s%s' % (color_b('green'), file_name, color_reset())))
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
        return ''

    data_l = []

    try:

        fh = open(filename, 'r')

        data = csv.reader(fh)

        for row in data:
            data_l.append(row)

        fh.close()

    except IOError:
        return ''

    if (len(data_l) != 0 and test_if_single_quoted(data_l[0])):
        data_l = remove_single_quote_from_list(data_l)

    return data_l


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


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   GUI Functions                                                    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def import_lib_wx():

    try:
        import wx
        return True
    except ModuleNotFoundError:
        return False


def gui_msg(value=''):

    if (value == ''):
        return

    import wx
    app = wx.App()

    frame = wx.Frame(None, title='pwmgr')
    msg = wx.MessageDialog(frame, value, caption='pwmgr', style=wx.OK|wx.CENTRE)

    msg.ShowModal()
    msg.Destroy()


def gui_confirmation(value=''):

    import wx
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


def prompt_password_master_gui():

    import wx
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


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Help Text                                                        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def print_header():

    global __app__, __current_revision__

    txt_color = '\x1B[1;38;5;87m' 

    lines = '    ' + '\u2501' * 71

    print()
    print(lines)

    header = \
    """
                             %s%s %s%s%s
    """ % (txt_color, text_highlight(__app__), \
            txt_color, text_highlight(__current_revision__), color_reset())

    print(text_highlight(header))

    print(lines)


def print_help():

    print_header()

    txt_color = ''

    field_number_color = color_b('cyan')
    field_data_color   = color_b('green')

    print(
    '''

    %sadd%s

        %sAdd a new site to database%s


    %saudit%s

        %sPerforms a security audit on all records & generates
        %sa report on the overall security posture.

        %s* Factors such as password complexity, reuse & age
        %s  are considered in order to determine the overall
        %s  risk of using that password


    %sedit %s[record number]%s

        %sEdit an entry in the database%s


    %ssearch [ group | site | email | username | all ] %s[keyword]%s

        %sSearch by group, site, etc.

        %s* By default, if no other parameters are specified,
        %s    the '%ssearch %sall%s' function is used%s


    %sshow+%s

        %sSearch & display an entry using search bar%s


    %sshow %s[record number]%s

        %sShow details about a specific record from database

        %s* If a record number is not specified, the show command
        %s     displays a brief summary of the entire database

        %s* Multiple comma separated values can also be passed
        %s     e.g: '%spwmgr -o %s1,2,3'%s


    %sshow-latest%s

        %sShow all entries from database sorted chronologically 


    %scopy+%s

        %sSearches for a record using search bar &
           copies the password to clipboard%s


    %scopy %s[record number]%s

        %sCopies password for a specific entry to clipboard%s 


    %sremove %s[record number]%s

        %sRemove an entry from database

        %s* This command can remove multiple entries
             e.g: '%spwmgr -d %s55,48'%s


    %skeyring-clear%s

        %sAllows the user to remove password from keyring

        %s* This command can be useful for example if you have
        %s  a different password database & you want to remove
        %s  the previous password that was set on the keyring%s


    %skey-show%s

        %sDisplays the current master key that is being used
        %sfor encryption / decryption%s


    %schange-enc-key%s

        %sAllows the user to change the master password%s
    ''' % ( color_b('orange'), color_reset(), txt_color, color_reset(), \

            color_b('orange'), color_reset(), \
                            txt_color,txt_color,txt_color, \
                            txt_color,txt_color, \

            color_b('orange'), color_b('yellow'), color_reset(), \
                txt_color,  color_reset(), \

            color_b('orange'), color_b('yellow'), color_reset(), \
                txt_color,txt_color,txt_color, \
                color_b('orange'), color_b('yellow'), txt_color, color_reset(), \

            color_b('orange'), color_reset(), txt_color, color_reset(), \

            color_b('orange'), color_b('yellow'), color_reset(), \
                txt_color,txt_color, \
                txt_color, txt_color, txt_color, \
                color_b('orange'), color_b('yellow'), color_reset(), \

            color_b('orange'), color_reset(), txt_color, \

            color_b('orange'), color_reset(), txt_color, color_reset(), \

            color_b('orange'), color_b('yellow'), color_reset(), \
                txt_color, color_reset(), \

            color_b('orange'), color_b('yellow'), color_reset(), \
                                txt_color, txt_color, \
                                color_b('orange'), color_b('yellow'), color_reset(), \

            color_b('orange'), color_reset(), \
                txt_color,txt_color,txt_color,txt_color,color_reset(), \

            color_b('orange'), color_reset(),txt_color,txt_color,color_reset(), \

            color_b('orange'), color_reset(),txt_color, color_reset()))


    print(
    '''
    %sgenerator%s

        %sGrants access to the password generator%s


    %skeyfile-list%s

        %sList the keyfile that is currently being used by the database

        %s* Please note that data hash is different from file hash%s


    %skeyfile-create %s[file path]%s

        %sAllows the user to generate a secure keyfile

        %s* If a path is not provided, the key file is saved in
        %s  '%s~/.config/pwmgr%s' directory%s


    %skeyfile-remove%s

        %sRemoves the existing key file that is being used by the database

        %s* Without a key file, only master password will be used for 
        %s  encryption / decryption of database%s


    %skeyfile-use %s[file path]%s

        %sAdd key file to compliment the master password

        %s* If a path is not provided, pwmgr will search for key file
        %s  in '%s~/.config/pwmgr%s' directory

        %s* This function can also be used to change an existing keyfile%s
    '''  % (color_b('orange'), color_reset(), txt_color, color_reset(), \

            color_b('orange'), color_reset(), \
                txt_color,txt_color, color_reset(), \

            color_b('orange'), color_b('green'), color_reset(), \
                txt_color, txt_color, \
                txt_color, color_b('green'), txt_color, color_reset(), \

            color_b('orange'), color_reset(), \
                txt_color,txt_color,txt_color, color_reset(), \

            color_b('orange'), color_b('green'), color_reset(), \
                txt_color,txt_color,txt_color, \
                color_b('green'), color_reset(), \
                txt_color, color_reset()))


    print(
    '''
    %sselect-cols-csv %s[order of rows] %s[input file] [output file]%s

        %sLoads csv database, selects & rearranges columns in the specified order

        %s* Can also be used to remove columns that are not needed%s
    ''' % (color_b('orange'), color_b('yellow'), \
             color_b('green'), color_reset(),\
             txt_color,txt_color,color_reset()))

    print(
    '''
    %simport-csv %s[input file]%s

        %sImports database from csv file%s

        %s* The following formats are supported:%s

            %s1) %ssite,password%s
            %s2) %ssite,password,username%s
            %s3) %ssite,password,username,email%s
            %s4) %ssite,password,username,email,notes%s
            %s5) %ssite,pass,last_modified,email,notes, ..%s

            %s(#5 has 14 fields, including security audit attributes)%s
    ''' % (color_b('orange'), color_b('green'), color_reset(), \
           txt_color, color_reset(), \
           txt_color, color_reset(), \
           field_number_color,field_data_color,color_reset(), \
           field_number_color,field_data_color,color_reset(), \
           field_number_color,field_data_color,color_reset(), \
           field_number_color,field_data_color,color_reset(), \
           field_number_color,field_data_color,color_reset(), \
           txt_color, color_reset()))


    print(
    '''
    %sexport-csv %s[output file]%s

        %sExports all fields in the database to csv format%s


    %ssearch-font %s[keyword]%s

        %sShows you exact font names that you need to specify to customize search bar%s

    ''' % ( color_b('orange'), color_b('green'), color_reset(), \
            txt_color, color_reset(), \
            color_b('orange'), color_b('yellow'), color_reset(), \
            txt_color, color_reset()))


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   Terminal & Printing Functions                                    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def detect_screen_res_change():

    global term_len_h

    try:
        term_len_var_h = os.get_terminal_size()[0]

        if (term_len_var_h != term_len_h):
            term_len_h = term_len_var_h
            return True, term_len_h
        else:
            return False, term_len_h

    except (OSError):
        return False, term_len_h


def align_text_vertically(data_len_v=15):

    term_len_var_h, term_len_var_v = os.get_terminal_size()

    # This is the number of vertical lines excluding
    #     data that needs to be printed
    print('\n' * int((term_len_v - data_len_v)/2))


def get_screen_size(self):

    try:

        h, v = os.get_terminal_size()

        self.__term_len_h = h
        self.__term_len_v = v

    except (OSError):

        pass


def cursor_hide():

    print("\033[?25l")


def cursor_show():

    print("\033[?25h")


def bold():

    return "\x1B[1m"


def text_highlight(text=''):

    return bold() + text + color_reset()


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


def color_bg(c=''):

    """
    Background colors
    """

    if (c == 'white'):
        return '\x1B[1;48;5;15m'
    elif (c == 'blue'):
        return '\x1B[1;48;5;27m' 
    elif (c == 'cyan'):
        return '\x1B[1;48;5;51m'
    elif (c == 'yellow'):
        return '\x1B[1;48;5;221m'
    elif (c == 'orange'):
        return '\x1B[1;48;5;214m'
    elif (c == 'red'):
        return '\x1B[1;48;5;196m'
    elif (c == 'green'):
        return '\x1B[1;48;5;118m'
    elif (c == 'black'):
        return '\x1B[1;48;5;232m'
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


def color_theme_1():

    s = '\x1B[1;38;5;123m\x1B[1;48;5;21m'
    return s


def color_theme_2():

    s = '\x1B[1;38;5;15m\x1B[1;48;5;24m'
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

    s = '\x1B[1;38;5;38m\x1B[1;48;5;232m'
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

    text = '\n  ' + color_b('red') + color_symbol_error() + \
            color_reset() + ' ' + bold() + text +  ' ' + color_reset() + '\n'     

    return text


def text_debug(text=''):

    text = color_symbol_debug() + " " + bold() + text + color_reset()
    return text


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


def plain_menu_bars(text='\u2501'):

    global term_len_h, term_bar_color

    initialize_theme()

    return term_bar_color + text * term_len_h + color_reset() 


def color_menu_bars(color=''):

    global term_len_h

    if (color == ''):
        global theme
        color = theme

    return color + ' ' * term_len_h + color_reset()


def color_menu_text(text='', color=''):

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

    if (color==''):
        global theme

        if (not global_value_initialized(theme)):
            initialize_theme()

        text =  theme + ' '*left + text + ' '*right + color_reset()
    else:
        text =  color + ' '*left + text + ' '*right + color_reset()

    return text


def info_bar_dynamic(text=''):

    global theme, term_len_h

    if (not global_value_initialized(theme)):
        initialize_theme()

    return theme + format_text_center(text, term_len_h) + color_reset()


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   User Input & related                                             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def prompt_with_blank(question=""):

    return input(color_symbol_info() + ' ' + color_b('yellow') + question + color_reset())


def prompt(question=""):

    color = color_b('yellow')
    rst = color_reset()

    value = ""

    while (value == ""):

        value = input(color_symbol_info() + ' ' + color + question + rst)

        if (value == ""):
            print(text_error("Field cannot be blank"))

    return value.lower()


def prompt_for_edit_with_blank(question=""):

    return input(color_symbol_prompt() + ' ' + color_b('yellow') + question + color_reset())


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
            print(text_error('Less than %d characters not allowed' % min_value))
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


def prompt_password_master_cmdline():

    value = ""

    print()

    while True:

        value = getpass(color_symbol_info() + color_b('yellow') + \
                text_highlight(" Enter password: ") + color_reset())

        value = value.strip()

        if (value == ""):
            print(text_error("Field cannot be blank"))
            continue
        else:
            break

    return value


def prompt_password_master(min_length=8):

    """
    Used to change master password of database
    """

    global db_handler, config

    master_key = db_handler.get_key()
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

        print()

        value2 = getpass(color_symbol_info() + color + " Retype password:    " + rst)
        value2 = value2.strip()

        if (value2 != value1):
            print(text_error("Password don't match, try again"))
            continue

        else:

            cursor_hide()

            if (kf != ''):
                key = db_handler.generate_new_key(value1, False, False, kf)
            else:
                key = db_handler.generate_new_key(value1, False, False)

            if (key == master_key):
                print(text_error("New password cannot be the same as old password"))
                cursor_show()
                continue
            else:
                return value1


def prompt_yes_no(question="", default=True):

    """
    Asks yes/no & returns a boolean value.
    """

    choice_list = ['da', 'y', 'yes', 'yesh', 'n', 'no', 'nou']

    while (True):
        choice = prompt_with_blank(question)

        if (choice in choice_list):
            if (choice in choice_list[:4]):
                return True
            else:
                return False
        elif (choice == ''):
            return default
        else:
            print(text_error("Invalid answer.  Please answer 'yes/no'"))


def prompt_yes_no_instant(question="", default=True, \
                          quit_if_keyboard_interrupt=True):
    """
    Asks yes/no & returns a boolean value.
    """

    q =  color_symbol_info() + ' ' + color_b('yellow') + question + color_reset() 

    try:

        while (True):

            sys.stdout.write(q)
            sys.stdout.flush()

            char = getch()

            print()

            if (char == '\n'):
                return default
            elif (char == 'y'):
                return True
            elif (char == 'n'):
                return False
            else:
                print(text_error("Invalid answer.  Please type 'y/n'"))

    except KeyboardInterrupt:

        if (quit_if_keyboard_interrupt):
            clear_screen()
            sys.exit()

        else:
            msg = 'prompt_yes_no_instant(): keyboard interrupt requested'
            raise KeyboardInterrupt(msg)


def prompt_yes_no_blank(question=""):

    """
    Asks yes/no & returns a boolean value.
    """

    choice_list = ['y', 'yes', 'yesh', 'n', 'no', 'nou']

    while (True):
        choice = prompt_with_blank(question)

        if  (choice in choice_list):
            if (choice in choice_list[:3]):
                return True
            else:
                return False
        elif (choice == ''):
            return ''
        else:
            print(text_error("Invalid answer. Please answer 'yes/no' or leave blank"))


'''
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃   PW Generator Functions                                           ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
'''

def initialize_charset():

    global symbol, ucase, number, lcase

    if (not global_value_initialized(symbol) and \
            global_value_initialized(ucase)  and \
            global_value_initialized(number) and \
            global_value_initialized(lcase)):

        ## Original, got replaced by opt
        #symbol  = "<:()|;{}!@#%^&+_*,/-\\][$?>"
        #ucase   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        #number  = "0123456789"
        #lcase   = "abcdefghijklmnopqrstuvwxyz"

        lcase    = "ambynzcodpeqfrgshtiujvkwlx"
        symbol   = "!@#$<%?^&+*>:"
        ucase    = "AMBYNZCODPEQFRGSHTIUJVKWLX"
        number   = "0123456789"


def generate_pass(length=10):

    """
    Generates a grid of 10 passwords of length 10,
        and selects a random column among them

    Args:
        length (int): Length of the generated password
        grid(bool):   Returns a grid of generated password
                        of size length x length

        enableSymbols (bool): Allow symbol in password (default: True)

    Returns:
        (str): Generated password

                or

        int []: An array of generated passwords
    """

    '''
    0   = symbol
    1   = numbers
    2   = lower case
    3   = upper case

    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #              Char primary           #
    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                    10+ chars

    Seq  Example            Code

    1    abcdef!@1A      -> 2222220013
    4    !@AaBbCc12      -> 0032323211
    7    !1abcdef@A      -> 0122222203
    9    1ABC!@abc2      -> 1333002221

                    15+ chars

    Seq  Example            Code

    1    abcdefgh!@#12AB -> 222222220001133
    4    !@#AaBbCcDd1234 -> 000323232321111
    7    !@123abcdefgh#A -> 001112222222203
    9    1ABCDE!@#abcde2 -> 133333000222221

                    21+ chars
    Seq  Example            Code

    1    abcdefghi!@#$%123ABCD -> 222222222000001113333
    4    !@#$%^&AaBbCcDd123456 -> 000000032323232111111
    7    !@123abcdefghijkl#ABC -> 001112222222222220333
    9    1ABCDE!@#abcde2$%^FGH -> 133333000222221000333

    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #            Number primary           #
    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                   10+ chars

    Seq  Example            Code

    5    A!123456a@  -> 3011111120
    2    a123!456A@  -> 2111011130
    8    1!2A34a5@6  -> 1013112101
    10   1234abcdA*  -> 1111222230

                  15+ chars

    Seq  Example            Code

    5    AB!@12345678ab@ -> 330011111111220
    2    a1234!@5678A#$% -> 211110011113000
    8    1!2A34a5@6B7b8# -> 101311210131210
    10   12345678abcdeA* -> 111111112222230


                  21+ chars

    Seq  Example            Code

    5    ABC!@12345678910ab#$% -> 333001111111111122000
    2    a1234!@5678A#$%91011^ -> 211110011113000111110
    8    1!2A34a5@6B7b8#910C$% -> 101311210131210111300
    10   1234567891011abcdeAB* -> 111111111111122222330

    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #            Symbol primary           #
    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
              10+ chars

    Seq  Example            Code

    3    !a@A#1$2%^     -> 0203010100
    6    a1!@#$%^A2     -> 2100000031

                  15+ chars

    3   !a@A#1$2%b^3&B* -> 020301010201030
    6   a12!@#$%^&*A345 -> 211000000003111

                  21+ chars

    3   !a@A#1$2%b^3&B*c!4@d% -> 020301010201030201020
    6   a12!@#$%^&*A345!@#a78 -> 211000000003111000211

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #       Final Code 10 chars     #
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ┃           2222220013          ┃
    ┃           2111011130          ┃
    ┃           0203010100          ┃
    ┃           0032323211          ┃
    ┃           3011111120          ┃
    ┃           2100000031          ┃
    ┃           0122222203          ┃
    ┃           1013112101          ┃
    ┃           1333002221          ┃
    ┃           1111222230          ┃
    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #      Final Code 15 chars      #
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ┃        222222220001133        ┃
    ┃        211110011113000        ┃
    ┃        020301010201030        ┃
    ┃        000323232321111        ┃
    ┃        330011111111220        ┃
    ┃        211000000003111        ┃
    ┃        001112222222203        ┃
    ┃        101311210131210        ┃
    ┃        133333000222221        ┃
    ┃        111111112222230        ┃
    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #      Final Code 21 chars      #
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ┃     222222222000001113333     ┃
    ┃     211110011113000111110     ┃
    ┃     020301010201030201020     ┃
    ┃     000000032323232111111     ┃
    ┃     333001111111111122000     ┃
    ┃     211000000003111000211     ┃
    ┃     001112222222222220333     ┃
    ┃     101311210131210111300     ┃
    ┃     133333000222221000333     ┃
    ┃     111111111111122222330     ┃
    #━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    '''

    initialize_charset()

    global lcase, symbol, ucase, number, char_set_complete


    '''
    Legend:
     0   = symbol
     1   = number
     2   = lower case
     3   = upper case
    '''

    code_l_10 = [            '2222220013', '2111011130', \
                             '0203010100', '0032323211', \
                             '3011111120', '2100000031', \
                             '0122222203', '1013112101', \
                             '1333002221', '1111222230'  ]

    code_l_15 = [       '222222220001133', '211110011113000', \
                        '020301010201030', '000323232321111', \
                        '330011111111220', '211000000003111', \
                        '001112222222203', '101311210131210', \
                        '133333000222221', '111111112222230'  ]

    code_l_21 = [ '222222222000001113333', '211110011113000111110', \
                  '020301010201030201020', '000000032323232111111', \
                  '333001111111111122000', '211000000003111000211', \
                  '001112222222222220333', '101311210131210111300', \
                  '133333000222221000333', '111111111111122222330'  ]


    code_l = []

    password_array = []

    diff = 0

    if (length >= 21):
        code_l = code_l_21
        diff = length - 21
    elif (length >= 15):
        code_l = code_l_15
        diff = length - 15
    else:
        code_l = code_l_10
        diff = length - 10

    random.seed()

    for item in code_l:

        password = ''

        for i in range(len(item)):

            code_int = int(item[i])
        
            if   (code_int == 2):
                password = "%s%s" % (password, random.choice(lcase))
            elif (code_int == 1):
                password = "%s%s" % (password, random.choice(number))
            elif (code_int == 0):
                password = "%s%s" % (password, random.choice(symbol))
            elif (code_int == 3):
                password = "%s%s" % (password, random.choice(ucase))

        if (diff == 0):
            pass
        elif (diff == 1 ):
            password += random.choice(char_set_complete)
        else:
            mid = int (diff / 2)
            pw_remaining = ''

            for i in range(diff):
                pw_remaining += random.choice(char_set_complete)

            password = pw_remaining[:mid] + password + pw_remaining[mid:]


        password_array.append(password)

    return password_array


def generate_pass_single(length=21):

    """
    Borrowed from pwmgr generator fn, customized for pw scrambling
    """

    lcase    = "ambynzcodpeqfrgshtiujvkwlx"
    symbol   = "!@#$<%?^&+*>:"
    ucase    = "AMBYNZCODPEQFRGSHTIUJVKWLX"
    number   = "0123456789"

    char_set_complete = symbol + ucase + number + lcase

    '''
    Legend:
     0   = symbol
     1   = number
     2   = lower case
     3   = upper case
    '''

    random.seed()

    code_l_21 = [ '211110011113000111110', \
                  '020301010201030201020', \
                  '333001111111111122000', \
                  '101311210131210111300', \
                  '112310123110123233130'  ]

    code_l_21 = random.choice(code_l_21)

    password  = ''

    diff = 0

    if (length >= 21):
        diff = length - 21

    for i in range(len(code_l_21)):

        code_int = code_l_21[i]

        if   (code_int == '2'):
            password += random.choice(lcase)
        elif (code_int == '1'):
            password += random.choice(number)
        elif (code_int == '0'):
            password += random.choice(symbol)
        elif (code_int == '3'):
            password += random.choice(ucase)

    if (diff == 1 ):
        password += random.choice(char_set_complete)
    else:
        mid = int (diff / 2)
        pw_remaining = ''

        for i in range(diff):
            pw_remaining += random.choice(char_set_complete)

        password = pw_remaining[:mid] + password + pw_remaining[mid:]

    return password


def menu_generate_password_standalone(called_by_add_fn=False):

    """
    Password generator that helps the user pick a password
    """

    color = color_b('yellow')
    rst = color_reset()

    if (not called_by_add_fn):
        cursor_show()
        clear_screen()
        print_block(1)
        print(info_bar_dynamic("Password generator settings | (Ctrl+c) Quit without saving"))
        print_block(4)

    pwd = ''

    length = prompt_int(color + " Length (default 15): " + rst, \
                        default=15, min_value=10, max_value=100)

    cursor_hide()

    initialize_resolution()

    global term_len_h, term_len_v

    initialize_theme()

    global theme_number, theme, \
           field_color_fg, term_bar_color

    header_text_color = ''
    pw_field_color    = ''

    # Header text
    if (theme_number == 66):
        header_text_color = color_b('white') + '\x1B[1;48;5;233m'
        pw_field_color    = '\x1B[1;48;5;233m\x1B[1;38;5;214m'
    elif (theme_number == 1):
        header_text_color = theme
        pw_field_color = '\x1B[1;48;5;18m\x1B[1;38;5;123m'    
    elif (theme_number == 2):
        header_text_color = theme
        pw_field_color = '\x1B[1;48;5;233m\x1B[1;38;5;214m'
    elif (theme_number == 3): 
        header_text_color = color_b('white') + '\x1B[1;48;5;233m'
        pw_field_color    = '\x1B[1;48;5;233m\x1B[1;38;5;214m'
    elif (theme_number == 4): 
        header_text_color = theme
        pw_field_color    = '\x1B[1;48;5;233m\x1B[1;38;5;214m'
    elif (theme_number == 5):
        header_text_color = theme
        pw_field_color    = '\x1B[1;48;5;233m\x1B[1;38;5;214m'
    elif (theme_number == 6): 
        header_text_color = '\x1B[1;38;5;233m' + '\x1B[1;48;5;39m'
        pw_field_color    = '\x1B[1;48;5;233m\x1B[1;38;5;214m'


    term_len_var_h = term_len_h
    term_len_var_v = term_len_v

    header = ''

    count  = 0

    while (pwd == ''):

        password_list = generate_pass(length)

        for password in password_list:

            # output = detect_screen_res_change()
            term_len_var_h, term_len_var_v = os.get_terminal_size()

            ################# Aligning Text Vertically ##################

            if (term_len_var_v < 18+3):

                clear_screen()
                print_block(1)
                print(text_error('Vertical screen size too small to display data'))
                sleep(1)
                clear_screen()
                sleep(0.5)
                continue

            term_len_h = term_len_var_h
            term_len_v = term_len_var_v

            clear_screen()

            if (term_len_v <= 30):

                # This is the number of vertical lines excluding
                #     data that needs to be printed
                num_vert_lines = term_len_v - 17

                num_lines_top = int(num_vert_lines/2)

                if ((num_vert_lines % 2) != 0):
                    num_lines_top = int(num_vert_lines/2) - 1

                print_block(num_lines_top)

            else:
                print('\n' * 3)

            header =  header_text_color + format_text_center('PWMGR Generator', term_len_h) + rst

            print(color_menu_bars(header_text_color))
            print(header)
            print(color_menu_bars(header_text_color))
            print_block(5)

            pw_text = color_text_with_transparent_bg(format_text_center(password, term_len_h), pw_field_color)

            print(pw_text)
            print_block(5)

            if (theme_number == 1):

                if (called_by_add_fn):
                    menu_text = "(G) Press any key to generate | (S) Select | (Q) Quit"
                else:
                    menu_text = "(G) Press any key to generate | (Q) Quit"

            else:
                if (called_by_add_fn):
                    menu_text = "(G) Generate password | (S) Select | (Q) Quit"
                else:
                    menu_text = "(G) Generate password | (Q) Quit"

            print(color_menu_bars(header_text_color))

            if (theme_number == 6):
                print(color_menu_text(menu_text, header_text_color))
            else:
                print(color_menu_text(menu_text))

            print(color_menu_bars(header_text_color))

            while (True):

                try:
                    char = getch()
                except(KeyboardInterrupt, OverflowError):
                    clear_screen()
                    sys.exit(0)

                if (char == 'g' or char == 'G'):
                    break
                elif ((char == 's' or char == 'S') and called_by_add_fn):
                    pwd = password
                    break
                elif (char == 'q' or char == 'Q'):
                    cursor_show()
                    clear_screen()
                    sys.exit(0)
                else:
                    pass

            if (pwd != ''):
                break

    cursor_show()

    if (called_by_add_fn):
        return pwd


def main():

    try:
        parse_args()
    except KeyboardInterrupt:
        cursor_show()
        clear_screen()
        sys.exit(1)


if __name__ == "__main__":
    main()
