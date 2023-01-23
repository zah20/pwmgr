#!/usr/bin/python3

import sys, os, subprocess
from time import sleep

global program_name

program_name = 'wipe_pwmgr.py'


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


def clear_clipboard():

    cmd1 = 'echo -n "" | xclip -selection clipboard'

    os.system(cmd1)

    print(text_debug('clipboard has been cleared'))


def clear_keyring():

    """
    Remove the current key from the keyring

    """

    app_name = 'pwmgr'

    cmd = 'keyctl purge -s user %s 1>&/dev/null' % app_name

    os.system(cmd)

    print(text_debug('keyring has been cleared'))


def check_running_instance(p_name):

    """
    Check running processes for a given program name

    Returns: (bool, str list)

            If True, returns a list of pid owned by that program.
            Otherwise returns False with an empty list 

    """
    
    cmd = "ps aux | grep python3 | grep '%s' | grep -v '/bin/sh' | awk '{print $2}'" % p_name

    stdout,stderr,rc = run_cmd(cmd)

    l = stdout.splitlines()

    current_pid = str(os.getpid()).strip()

    l.remove(current_pid)

    if (len(l) == 0):
        return False, []
    else:
        return True, l


def stop_running_process(p_name):

    r = check_running_instance(p_name)

    if r[0]:

        pid_list = r[1]

        for p in pid_list:
            # print('Stopping process: ', p)
            cmd = 'kill -9 %s' % p
            run_cmd(cmd)


def print_usage():

    print("\n  Usage: %s [clipboard wipe interval] [keyring wipe interval]\n" % sys.argv[0])
    print("         ./%s 60 600\n" % sys.argv[0])


def text_error(text=''):

    text = '\n  ' + color_pair_error() + color_symbol_error() + ' ' + \
            text + ' ' + color_reset() + '\n'

    return text


def text_debug(text=''):

    text = (color_symbol_debug() + " " + text_highlight(text))
    return text


def text_highlight(text=''):

    text = text_b() + text + color_reset()
    return text


def text_b():

    return "\x1B[1m"


def color_symbol_debug():

    text = '  ' + color_b('yellow') + '[*]' + color_reset()
    return text


def color_pair_error():

    return color_pair('red_black')


def color_pair(p=''):

    """
    Color pair combination

    parameter format:
        foreground_background
            e.g: 'white_black'
    """

    if (p == 'red_black'):
        s = '%s%s' % (color_b('red'), color_bg('black'))
        return s


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


def color_reset():
    """
    Reset bg & fg colors
    """

    return "\x1B[0m"


def color_symbol_error():

    return '[-]'


def main():

    # 2 args: clipboard wipe interval, keyring wipe interval
    
    if (len(sys.argv) != 3):
        print_usage()
        sys.exit(1)

    try:

        arg1 = int(sys.argv[1])
        arg2 = int(sys.argv[2])

    except (ValueError):

        print(text_error('wipe_pwmgr.py(): Invalid input parameter'))
        print_usage()
        sys.exit(1)

    global program_name

    stop_running_process(program_name)

    min_val = min(arg1, arg2)
    
    diff = 0

    clipboard_clear_enabled = True
    keyring_clear_enabled = True

    if (arg1 == 0):
        clipboard_clear_enabled = False

    if (arg2 == 0):
        keyring_clear_enabled = False

    if (not clipboard_clear_enabled or not keyring_clear_enabled):

        if (clipboard_clear_enabled):
            sleep(arg1)
            clear_clipboard()

        if (keyring_clear_enabled):
            sleep(arg2)
            clear_keyring()

    else:

        if (arg1 == arg2):

            sleep(arg1)
            clear_clipboard()
            clear_keyring()

        elif (min_val == arg1):

            diff = arg2 - arg1

            sleep(arg1)
            clear_clipboard()

            sleep(diff)
            clear_keyring()

        else:

            diff = arg1 - arg2

            sleep(arg2)
            clear_keyring()

            sleep(diff)
            clear_clipboard()


if __name__ == "__main__":

    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
