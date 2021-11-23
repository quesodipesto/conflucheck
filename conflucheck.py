from typing import Type
from colorama.ansi import clear_screen
import requests
import time
import re
import os
import sys
from packaging import version
from colorama import init, Fore
init()
requests.packages.urllib3.disable_warnings()
header = (' _____                 __  _          _____  _    _  ______  _____  _  __        __     ___  ''\n'
          '/ ____|               / _|| |        / ____|| |  | ||  ____|/ ____|| |/ /       /_ |   / _ \ ''\n'
          '| |      ___   _ __  | |_ | | _   _ | |     | |__| || |__  | |     |   /  __   __| |  | | | |''\n'
          '| |     / _ \ |  _ \ |  _|| || | | || |     |  __  ||  __| | |     |  <   \ \ / /| |  | | | |''\n'
          '| |____| (_) || | | || |  | || |_| || |____ | |  | || |____| |____ |   \   \ V / | | _| |_| |''\n'
          '\_____| \___/ |_| |_||_|  |_| \__,_| \_____||_|  |_||______|\_____||_|\_\   \_/  |_|(_)\___/'' Created by QuesoDiPesto''\n'
          + Fore.LIGHTGREEN_EX+'                                         ---> CVE-2021-26084 checker <---'+Fore.WHITE)


def help():

    print(Fore.LIGHTRED_EX + header + '\n' + Fore.GREEN + 'Welcome to ConfluCHECK 1.0\n'
          'Tool operation:\n'
          + Fore.CYAN+'Examples:'
          + Fore.CYAN + '\n[-] URL with port: ' + Fore.RED +
          'python3 conflucheck.py http(s)://xxx.xxx.xxx.xxx:yyyy'
          + Fore.CYAN+'\n[-] URL without port: ' + Fore.RED +
          'python3 conflucheck.py http(s)://xxx.xxx.xxx.xxx'
          + Fore.CYAN+'\n[-] List with URL with or without port: ' + Fore.RED + 'python3 conflucheck.py list_with_links.txt')


def screen_clear():
    # for mac and linux(here, os.name is 'posix')
    if os.name == 'posix':
        _ = os.system('clear')
    else:  # for windows platform
        _ = os.system('cls')


def checkIP(myip, what_is):
    # try:
    if what_is == 'url':
        output = ['']
        output[0] = 'None'
        print(Fore.YELLOW + '[+] URL: '+myip + Fore.WHITE)
        try:
            response = requests.get(myip, verify=False)
            print(Fore.GREEN + "[-]" + Fore.WHITE +
                  " Connection estabiliced with " + myip)
            output_1 = re.findall(
                '(meta\sname=\"ajs-version-number\"\scontent=\"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2})', response.text)
            output = re.findall(
                "[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}", output_1[0])
        except:
            print(Fore.RED+'[-]'+Fore.WHITE +
                  ' Connection error with ' + myip)
        if output[0] != 'None':
            print(Fore.GREEN + "[-]" + Fore.WHITE +
                  ' Possible located version: ' + Fore.GREEN + output[0] + Fore.WHITE)
            if version.parse(output[0]) < version.parse("6.13.23"):
                print(
                    Fore.RED + '[+] Potentially vulnerable target\n' + Fore.WHITE)
            elif version.parse(output[0]) > version.parse("6.14.0") and version.parse(output[0]) < version.parse("7.4.11"):
                print(
                    Fore.RED + '[+] Potentially vulnerable target\n' + Fore.WHITE)
            elif version.parse(output[0]) > version.parse("7.5.0") and version.parse(output[0]) < version.parse("7.11.6"):
                print(
                    Fore.RED + '[+] Potentially vulnerable target\n' + Fore.WHITE)
            elif version.parse(output[0]) > version.parse("7.12.0") and version.parse(output[0]) < version.parse("7.12.5"):
                print(
                    Fore.RED + '[+] Potentially vulnerable target\n' + Fore.WHITE)
            else:
                print(
                    Fore.GREEN + 'This Confluence appliance is not vulnerable\n' + Fore.WHITE)
        else:
            print(
                'Not Confluence version detected or some error occur \n')
    elif what_is == 'txt':
        output = ['']
        count_links = 0
        with open(sys.argv[1], 'r') as f:
            for line in f:
                count_links += 1
                output[0] = 'None'
                print(Fore.YELLOW + '[+] URL: '+line.rstrip('\n') + Fore.WHITE)
                try:
                    response = requests.get(line.rstrip('\n'), verify=False)
                    print(Fore.GREEN + "[-]" + Fore.WHITE +
                          " Connection estabiliced with " + line.rstrip('\n'))
                    output_1 = re.findall(
                        '(meta\sname=\"ajs-version-number\"\scontent=\"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2})', response.text)
                    output = re.findall(
                        "[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}", output_1[0])
                except:
                    print(Fore.RED+'[-]'+Fore.WHITE +
                          ' Connection error with ' + line.rstrip('\n'))
                if output[0] != 'None':
                    print(Fore.GREEN + "[-]" + Fore.WHITE +
                          ' Possible located version: ' + Fore.GREEN + output[0] + Fore.WHITE)
                    if version.parse(output[0]) < version.parse("6.13.23"):
                        print(
                            Fore.RED + '[+] Potentially vulnerable target\n' + Fore.WHITE)
                    elif version.parse(output[0]) > version.parse("6.14.0") and version.parse(output[0]) < version.parse("7.4.11"):
                        print(
                            Fore.RED + '[+] Potentially vulnerable target\n' + Fore.WHITE)
                    elif version.parse(output[0]) > version.parse("7.5.0") and version.parse(output[0]) < version.parse("7.11.6"):
                        print(
                            Fore.RED + '[+] Potentially vulnerable target\n' + Fore.WHITE)
                    elif version.parse(output[0]) > version.parse("7.12.0") and version.parse(output[0]) < version.parse("7.12.5"):
                        print(
                            Fore.RED + '[+] Potentially vulnerable target\n' + Fore.WHITE)
                    else:
                        print(
                            Fore.GREEN + 'This Confluence appliance is not vulnerable\n' + Fore.WHITE)
                else:
                    print(
                        'Not Confluence version detected or some error occur \n')
            print(Fore.YELLOW + '[+] Reviewed: ' +
                  str(count_links) + ' web addresses.')


if __name__ == "__main__":
    screen_clear()
    arguments = len(sys.argv)
    if arguments != 2:
        help()
    elif re.findall('(.txt)', sys.argv[1]):
        print(Fore.CYAN + header + Fore.WHITE)
        txt_check = re.findall('(.txt)', sys.argv[1])
        if txt_check[0] == '.txt':
            txt_ok = 'txt'
            print(Fore.LIGHTMAGENTA_EX +
                  '[º] Openning: ' + sys.argv[1] + Fore.WHITE)
            start = time.time()
            checkIP(sys.argv[1], txt_ok)
            end = time.time()
            print(Fore.YELLOW + '[-] Search performance in: ' +
                  str(end-start) + ' seconds' + Fore.WHITE)
        else:
            print('Error TXT')
    else:
        print(Fore.CYAN + header + Fore.WHITE)
        url_check = re.findall(
            '(http(s?)\:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\:[0-9]{1,6})?)', sys.argv[1])
        if url_check[0][0] == sys.argv[1]:
            url_ok = 'url'
            start = time.time()
            checkIP(sys.argv[1], url_ok)
            end = time.time()
            print(Fore.YELLOW + '[-] Search performance in: ' +
                  str(end-start) + ' seconds' + Fore.WHITE)
        else:
            print('Error URL')
