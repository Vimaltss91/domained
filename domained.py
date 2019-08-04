import argparse, os, requests, time, csv, datetime, glob, subprocess, re
import configparser, smtplib, sys
from signal import signal

today = datetime.date.today()
domains=sys.argv[2]
print (domains)

def get_args():

    parser = argparse.ArgumentParser(

        description='domained')

    parser.add_argument(

        '-d', '--domain', type=str, help='Domain', required=False, default=False)

    parser.add_argument(

        '-su', '--subdomain', help='SubDomain', action='store_true', default=False)

    parser.add_argument(

        '-n', '--nmap', help='Masscan', action='store_true',default=False)

    #parser.add_argument(

     #   '-di', '--dirsearch', help='dirsearch', action='store_true',default=False)

    parser.add_argument(

        '-dns', '--massdns', help='Massdns', action='store_true',default=False)

    parser.add_argument(

        '--upgrade', help='Upgrade', action='store_true', default=False)

    parser.add_argument(

        '--install', help='Install', action='store_true', default=False)

    parser.add_argument(

        '-q', '--quick', help='Quick', action='store_true', default=False)


    parser.add_argument(

        '--fresh', help='Remove output Folder', action='store_true', default=False)


    return parser.parse_args()

newpath = r'output'

if not os.path.exists(newpath):

    os.makedirs(newpath)





def banner():

    print("""\033[1;31m

         ___/ /__  __ _  ___ _(_)__  ___ ___/ /

        / _  / _ \/  ' \/ _ `/ / _ \/ -_) _  / 

        \_,_/\___/_/_/_/\_,_/_/_//_/\__/\_,_/  

    \033[1;34m\t\t\tgithub.com/cakinney\033[1;m""")

    globpath = ("*.csv")

    globpath2 = ("*.lst")

def dirsearch():

    print("\n\n\033[1;31mRunning dirsearch \n\033[1;37m")

    urls="{}/output/{}/{}_valid.txt".format(script_path,domain,domain)

    dirsearch_cmd="xterm -e bash -c 'python3 {}/bin/dirsearch/dirsearch.py -L{} -e * - F -x 400 --plain-text-report ~/Downloads/domained/output/{}/{}_dirsearch.txt {}; exec bash' &".format(script_path,urls,domain,domain,domains)


    print("\n Running Cmd : {}".format(dirsearch_cmd))

    os.system(dirsearch_cmd)

    time.sleep(5)


def massdns_dig():

    print("\n\n\033[1;31mRunning massdns_dig \n\033[1;37m")

    dig_out="{}/output/{}/{}_dig.txt".format(script_path,domain,domain)
    massdns_file= "{} -r ".format(os.path.join(script_path, 'bin/massdns/bin/massdns'))
    resolvers = "{}/{}".format(script_path, 'bin/massdns/lists/resolvers.txt')
    word_file="{}/output/{}/{}-WithoutHttps.txt".format(script_path,domain,domain)

    dig_cmd=massdns_file+" ~/Downloads/domained/resolvers.txt"+" -t A -w "+dig_out+" "+word_file

    print("\n Running Cmd : {}".format(dig_cmd))

    os.system(dig_cmd)

    time.sleep(5)

    dig_cmd_ip='grep -A 1 "ANSWER SECTION:" {}/output/{}/{}_dig.txt|grep IN | sort -u | cut -d " " -f 5 >> {}/output/{}/{}_ip_All.txt'.format(script_path,domain,domain,script_path,domain,domain)

    print("\n Running Cmd : {}".format(dig_cmd_ip))

    os.system(dig_cmd_ip)

    time.sleep(5)

    remove_dig_cmd="rm  {}".format(dig_out)
    os.system(remove_dig_cmd)

def massdns_dig_ip():

    print("\n\n\033[1;31mRunning massdns_dig_ip_All \n\033[1;37m")
    
    ip_all="{}/output/{}/{}_ip_All.txt".format(script_path,domain,domain)
    ip_address="{}/output/{}/{}_ip.txt".format(script_path,domain,domain)
    
    file= open(ip_all)
    output= open (ip_address,'a+')

    for f in file:
	ipaddress_reg='''(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))'''
	m = re.search(ipaddress_reg,f)
	if m:
	    output.write(f)
	#output.close()


    time.sleep(5)


def masscan():

    print("\n\n\033[1;31mRunning masscan \n\033[1;37m")

    ip_address="{}/output/{}/{}_ip.txt".format(script_path,domain,domain)
    masscan_output="{}/output/{}/{}_masscan_out.txt".format(script_path,domain,domain)
    massscanFile="cd {}/bin/masscan".format(script_path)
    ports="-p21-23,25,53,80-81,110,135,137-139,143-144,443,445,1433-1434,2323,3128,3306,3389,63458,60112,8080-8081,8443,8545,8888,9100  --rate 200 >> {}".format(masscan_output)

    #Subcmd = "xterm -e bash -c '{} -iL {} {}; exec bash' &".format(massscanFile,ip_address,ports)
    Subcmd="{} -iL {} {} ".format("masscan",ip_address,ports)
    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(Subcmd))

    os.system(massscanFile)
    time.sleep(2)
    os.system(Subcmd)
    

    print("\n\033[1;31mMasscan Complete\033[1;37m")

def sublist3r(brute=False):

    print("\n\n\033[1;31mRunning Sublist3r \n\033[1;37m")

    sublist3rFileName = "{}_sublist3r.txt".format(output_base)

    #Subcmd = "xterm -e bash -c 'python {} -v -t 15 -d {} -o {}; exec bash' &".format(
    Subcmd = "python {} -v -t 15 -d {} -o {}".format(

         os.path.join(script_path, 'bin/Sublist3r/sublist3r.py'),

         domain, sublist3rFileName)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(Subcmd))

    os.system(Subcmd)

    print("\n\033[1;31mSublist3r Complete\033[1;37m")

    time.sleep(5)
	
	
def enumallfilemove():

    print("\n\n\033[1;31mRunning for the enumall file move\n\033[1;37m")

    enumallfilemoveCmd = "mv {}.lst output".format(domain)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(enumallfilemoveCmd))

    os.system(enumallfilemoveCmd)

    print("\n\033[1;31mFile Move Completed Complete\033[1;37m")

    time.sleep(40)

def create_folder():

    print("\n\n\033[1;31mRunning for folder creation move\n\033[1;37m")

    mkdir_cmd="mkdir -p ~/Downloads/domained/output/{}".format(domain)

    os.system(mkdir_cmd)

    print("\n\033[1;31mFolder creation completed Completed Complete\033[1;37m")

    domain_valid="echo {}{} > {}/output/{}/{}_valid.txt".format("https://",domain,script_path,domain,domain)
    domain_valid="echo {} > {}/output/{}/{}_valid_domain.txt".format(domain,script_path,domain,domain)

    time.sleep(5)


def massdns_subdomain():

    print("\n\n\033[1;31mRunning for the subdomain grep\n\033[1;37m")

    massdnsCmd1 = "grep {} ~/Downloads/domained/output/{}_massdns.txt ".format(domain, domain)
    massdnsCmd2 = "cut -d' ' -f1| sed 's/.$//' >> ~/Downloads/domained/output/{}_jaddx.txt".format(domain)
    massdnsCmd= "{} | {} ".format(massdnsCmd1, massdnsCmd2)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(massdnsCmd))

    os.system(massdnsCmd)

    print("\n\033[1;31mFile Move Completed Complete\033[1;37m")

    time.sleep(40)


def massdns_crt_subdomain():

    print("\n\n\033[1;31mRunning for the crt_subdomain grep\n\033[1;37m")

    massdnsCmd1 = "grep {} ~/Downloads/domained/output/{}_massdns_crt.txt ".format(domain, domain)
    massdnsCmd2 = "cut -d' ' -f1| sed 's/.$//' >> ~/Downloads/domained/output/{}_crt.txt".format(domain)
    massdnsCmd= "{} | {} ".format(massdnsCmd1, massdnsCmd2)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(massdnsCmd))

    os.system(massdnsCmd)

    print("\n\033[1;31mFile Move Completed Complete\033[1;37m")

    time.sleep(40)

	

def SubFinder():

    print("\n\n\033[1;31mRunning SubFinder \n\033[1;37m")

    SubFinderFileName = script_path+"/{}_subfinder.txt".format(output_base)

    SubFinder_word_file = os.path.join(script_path, 'wordlist.txt')

    #SubfinderCmd = "~/go_projects/bin/subfinder -d {} -b -w {} -t 100 -o {}".format(domain, SubFinder_word_file,SubFinderFileName)
    SubfinderCmd = "xterm -e bash -c '~/go_projects/bin/subfinder -d {} -t 100 -o {}; exec bash' &".format(domain,SubFinderFileName)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(SubfinderCmd))

    os.system(SubfinderCmd)

    print("\n\033[1;31mSubFinder Complete\033[1;37m")

    time.sleep(2)


def subjack():

    print("\n\n\033[1;31mRunning Subjack \n\033[1;37m")

    subjackFileName = script_path+"/output/{}/{}_subjack.txt".format(domain,domain)

    subjack_word_file = script_path+'/output/{}/{}-WithoutHttps.txt'.format(domain,domain)

    #SubfinderCmd = "~/go_projects/bin/subfinder -d {} -b -w {} -t 100 -o {}".format(domain, SubFinder_word_file,SubFinderFileName)
    SubjackCmd = "xterm -e bash -c '~/go_projects/bin/subjack -w {} -a -t 100 -timeout 30 -o {}; exec bash' &".format(subjack_word_file,subjackFileName)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(SubjackCmd))

    os.system(SubjackCmd)

    print("\n\033[1;31msubjackComplete\033[1;37m")

    time.sleep(60)

def inception():

    print("\n\n\033[1;31mRunning Inception \n\033[1;37m")

    inception_output = script_path+"/output/{}/{}_inception.txt".format(domain,domain)


    inceptionFileName = script_path+'/output/{}/{}_valid_domain.txt'.format(domain,domain)

    inceptionCmd = "~/go_projects/bin/inception -d {} >> {}".format(inceptionFileName,inception_output)

    #inceptionCmd = "xterm -e bash -c '~/go_projects/bin/inception -d {} >> {}; exec bash' &".format(inceptionFileName,inception_output)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(inceptionCmd))

    os.system(inceptionCmd)

    print("\n\033[1;31minceptionCmd Complete\033[1;37m")

    time.sleep(60)

def inception_single():

    print("\n\n\033[1;31mRunning Inception \n\033[1;37m")

    inception_output = script_path+"/output/{}/{}_inception.txt".format(domain,domain)


    inceptionFileName = script_path+'/output/{}/{}_valid_domain.txt'.format(domain,domain)

    inceptionCmd = "~/go_projects/bin/inception -d {} >> {}".format(inceptionFileName,inception_output)


    #inceptionCmd = "xterm -e bash -c '~/go_projects/bin/inception -d {} >> {}; exec bash' &".format(inceptionFileName,inception_output)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(inceptionCmd))

    os.system(inceptionCmd)

    print("\n\033[1;31minceptionCmd Complete\033[1;37m")

    time.sleep(6)

def aquatone_new():

    print("\n\n\033[1;31mRunning Aquatone New \n\033[1;37m")

    Aquatone_newFileName = script_path+"/output/{}/{}_aquatone_new.txt".format(domain,domain)

    aquatone_valid_txt = '~/Downloads/domained/output/{}/{}_valid.txt'.format(domain,domain)

    #SubfinderCmd = "~/go_projects/bin/subfinder -d {} -b -w {} -t 100 -o {}".format(domain, SubFinder_word_file,SubFinderFileName)
    aquatone_newCmd = "xterm -e bash -c 'cat {} | ~/go_projects/bin/aquatone -out {}; exec bash' &".format(aquatone_valid_txt,Aquatone_newFileName)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(aquatone_newCmd))

    os.system(aquatone_newCmd)

    print("\n\033[1;31mAquatone Complete\033[1;37m")

    time.sleep(60)


def gobuster():

    print("\n\n\033[1;31mRunning GoBuster \n\033[1;37m")

    gobusterFileName = script_path+"/{}_gobuster.txt".format(output_base)

    gobuster_word_file = '~/Downloads/domained/bin/gobuster/wordlist_dns.txt'

    gobusterCmd = "xterm -e bash -c '~/go_projects/bin/gobuster -m dns -u {} -t 50 -w {} -o {}; exec bash' &".format(domain,gobuster_word_file,gobusterFileName)

    #gobusterCmd = "~/go_projects/bin/gobuster -m dns -u {} -t 50 -w {} -o {}".format(domain,gobuster_word_file,gobusterFileName)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(gobusterCmd))

    os.system(gobusterCmd)

    print("\n\033[1;31mGoBuster Complete\033[1;37m")

    time.sleep(2)

def waybackurljs():

    print("\n\n\033[1;31mRunning waybackurl JS \n\033[1;37m")

    waybackurljs_FileName = script_path+"/{}_waybackurl_js.txt".format(output_base)


    waybackurl_jsCmd = "~/go_projects/bin/waybackurls {} | grep '\.js' | uniq | sort >> {}&".format(domain,waybackurljs_FileName)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(waybackurl_jsCmd))

    os.system(waybackurl_jsCmd)

    print("\n\033[1;31mway backurls js Complete\033[1;37m")

    time.sleep(5)


def waybackurl():

    print("\n\n\033[1;31mRunning WayBack URL \n\033[1;37m")

    #enumallCMD = "python {} {}".format(
    waybackurlCMD = "xterm -e bash -c 'python {} {}; exec bash' &".format(

        os.path.join(script_path, 'bin/waybackurl/waybackurl.py'), domain)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(waybackurlCMD))

    os.system(waybackurlCMD)

    print("\n\033[1;31m wayback URL Complete\033[1;37m")

    time.sleep(5)



def enumall():

    print("\n\n\033[1;31mRunning Enumall \n\033[1;37m")

    #enumallCMD = "python {} {}".format(
    enumallCMD = "xterm -e bash -c 'python {} {}; exec bash' &".format(

        os.path.join(script_path, 'bin/domain/enumall.py'), domain)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(enumallCMD))

    os.system(enumallCMD)

    print("\n\033[1;31menumall Complete\033[1;37m")

    time.sleep(20)


def altdns():

    print("\n\n\033[1;31mRunning altdns \n\033[1;37m")

    altdnsdomain= "echo {} >> ~/Downloads/domained/output/{}_sublist3r.txt".format(domain, domain)

    os.system(altdnsdomain) 

    time.sleep(1)

    altdnsCMD = "python {} -i ~/Downloads/domained/output/{}_sublist3r.txt -o ~/Downloads/domained/{}_permutation.txt -w ~/Downloads/domained/bin/altdns/words.txt".format(
    #enumallCMD = "xterm -e bash -c 'python {} {}; exec bash' &".format(

        os.path.join(script_path, 'bin/altdns/altdns.py'), domain, domain)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(altdnsCMD))

    os.system(altdnsCMD)

    print ("Permutation is completed")

    altdns_massdnsCMD = "{} -r ~/Downloads/domained/resolvers.txt -t A -w {}_altdns_massdns.txt ~/Downloads/domained/{}_permutation.txt".format(os.path.join(script_path, 'bin/massdns/bin/massdns'), '/root/Downloads/domained/'+output_base, domain)

    print ("Running the command {}".format(altdns_massdnsCMD))    

    os.system(altdns_massdnsCMD)

    time.sleep(2)

    altdns_grep1= "grep -A 1 'ANSWER SECTION:' ~/Downloads/domained/output/{}_altdns_massdns.txt".format(domain)

    altdns_grep2=">> ~/Downloads/domained/output/{}_altdns.txt".format(domain)

    altdns_grep_cmd= "{} | grep IN| cut -d' ' -f1| sed 's/.$//' {}". format(altdns_grep1, altdns_grep2)

    print ("Running the cmd {}".format(altdns_grep_cmd))

    os.system(altdns_grep_cmd)

    alt_remove= "rm ~/Downloads/domained/{}_permutation.txt ~/Downloads/domained/output/{}_altdns_massdns.txt".format(domain, domain)

    print ("Running the cmd for removal of the Permutaion file {}".format(alt_remove))

    os.system(alt_remove)

    print("\n\033[1;31m altdnsComplete\033[1;37m")

    time.sleep(1)





def massdns():

    print("\n\n\033[1;31mRunning massdns \n\033[1;37m")

    word_file = os.path.join(script_path, 'bin/massdns/all.txt' )

    resolvers = os.path.join(script_path, 'bin/massdns/lists/resolvers.txt')

    massdnsCMD = 'python {} {} {} | {} -r {} -t A -o S -w {}_massdns.txt'.format(
    #massdnsCMD = "xterm -e bash -c 'python {} {} {} | {} -r {} -t A -o S -w {}_massdns.txt; exec bash' &".format(

        os.path.join(script_path, 'bin/massdns/scripts/subbrute.py'), word_file, domain,

        os.path.join(script_path, 'bin/massdns/bin/massdns'), resolvers, '/root/Downloads/domained/'+output_base)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(massdnsCMD))

    os.system(massdnsCMD)

    print("\n\033[1;31mMasscan Complete\033[1;37m")

    time.sleep(5)

def mass_subrute():

    print("\n Running Command for the MAssdns Subbrute")

    massdns_location="{}/output/{}_massdns.txt".format(script_path,domain)

    subbrute_location="{}/output/{}_subbrute.txt".format(script_path,domain)

    subbruteCMD="""grep "{}" {} | cut -d " " -f 1|sed 's/.$//' >> {}""".format(domain,massdns_location,subbrute_location)

    print(subbruteCMD)
    os.system(subbruteCMD)

    time.sleep(3)

    remove_massdns="rm {}".format(massdns_location)

    os.system(remove_massdns)

def whatweb():

    print("\n\n\033[1;31mRunning whatweb \n\033[1;37m")


    Current_loca = os.path.join(script_path)

    #whatweb_CMD = "xterm -e bash -c 'whatweb --input-file={}/output/{}/{}_valid.txt --log-verbose={}/output/{}/{}_whatweb.txt; exec bash' &".format(Current_loca,domain,domain,Current_loca,domain,domain)

    whatweb_CMD = "whatweb --input-file={}/output/{}/{}_valid.txt --log-verbose={}/output/{}/{}_whatweb.txt".format(Current_loca,domain,domain,Current_loca,domain,domain)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(whatweb_CMD))

    os.system(whatweb_CMD)

    print("\n\033[1;31m Whatweb Complete\033[1;37m")

def whatweb_single():

    print("\n\n\033[1;31mRunning whatweb \n\033[1;37m")


    Current_loca = os.path.join(script_path)


    whatweb_CMD = "whatweb {}{} --log-verbose={}/output/{}/{}_whatweb.txt".format("https://",domain,Current_loca,domain,domain)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(whatweb_CMD))

    os.system(whatweb_CMD)

    print("\n\033[1;31m Whatweb Complete\033[1;37m")


def massdns_crt():

    print("\n\n\033[1;31mRunning massdns_crt \n\033[1;37m")

    word_file = os.path.join(script_path, 'bin/massdns/all.txt' if bruteall else 'bin/massdns/all.txt')

    resolvers = os.path.join(script_path, 'bin/massdns/lists/resolvers.txt' )

    #massdnsCMD = 'python {} {} | {} -r {} -t A -o S -w {}_massdns.txt'.format(
    massdns_crt_CMD = "xterm -e bash -c 'python {} {} | {} -r {} -t A -o S -w {}_massdns_crt.txt; exec bash' &".format(

        os.path.join(script_path, 'bin/massdns/scripts/ct.py'),domain,

        os.path.join(script_path, 'bin/massdns/bin/massdns'), resolvers, '/root/Downloads/domained/'+output_base)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(massdns_crt_CMD))

    os.system(massdns_crt_CMD)

    print("\n\033[1;31mMassdns Complete\033[1;37m")

    time.sleep(1)




def amass():

    print("\n\n\033[1;31mRunning Amass \n\033[1;37m")

    amassFileName = "{}_amass.txt".format(output_base)

    #amassCmd = "~/go_projects/bin/amass  -passive -norecursive -noalts -d {} -o {}".format(domain, amassFileName)
    amassCmd = "xterm -e bash -c '~/go_projects/bin/amass -passive -norecursive -noalts -d {} -o {}; exec bash' &".format(domain, amassFileName)

    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(amassCmd))

    os.system(amassCmd)

    print("\n\033[1;31mAmass Complete\033[1;37m")

    time.sleep(10)

def urlstatus():

    print("\n\n\033[1;31mRunning url status \n\033[1;37m")
    urllocation="~/Downloads/domained/output/{}/{}-unique.txt".format(domain,domain)

    urlstatusFileName = "~/Downloads/domained/output/{}/{}_status.txt".format(domain,domain)

    urlstatusCmd="cat {}| parallel -j50 -q curl -w 'Status:%{}\\t  %{}\\n' -o /dev/null -sk > {} ".format(urllocation,"{http_code}","{url_effective}",urlstatusFileName)

    #urlstatusCmd="xterm -e bash -c  'cat {}| parallel -j50 -q curl -w 'Status:%{}\\t  %{}\\n' -o /dev/null -sk > {} ; exec bash' &".format(urllocation,"{http_code}","{url_effective}",urlstatusFileName)

    print(urlstatusCmd)


    print("\n\033[1;31mRunning Command: \033[1;37m{}".format(urlstatusCmd))

    os.system(urlstatusCmd)

    print("\n\033[1;31mURL Status Complete\033[1;37m")

    time.sleep(20)


def urlstatus_domain():

    print("\n\n\033[1;31mRunning url status valiad and domain \n\033[1;37m")

    urlstatusFileName = "{}/output/{}/{}_status.txt".format(script_path,domain,domain)
    urlsvalidFileName = "{}/output/{}/{}_valid.txt".format(script_path,domain,domain)
    file=open(urlstatusFileName)
    output=open(urlsvalidFileName,"a+")
    for f in file:
	if "Status:000" in f:
		pass
	else:
		url=f.split("\t")[-1]
		output.write(url.strip()+"\n")
    output.close()
    file.close()

    time.sleep(10)

    urlsvalidDomainFileName = "{}/output/{}/{}_valid_domain.txt".format(script_path,domain,domain)
    validfile=open(urlsvalidFileName) 
    outputs=open(urlsvalidDomainFileName,"a+")
    for i in validfile:
	domain_valid=i.split("//")[-1]
	outputs.write(domain_valid)  
    outputs.close()


def upgradeFiles():

    binpath = os.path.join(script_path, 'bin')

    old_wd = os.getcwd()

    if not os.path.exists(binpath):

        os.makedirs(binpath)

    else:

        print("Removing old bin directory: {}".format(binpath))

        os.system('rm -rf {}'.format(binpath))

        os.makedirs(binpath)

    print('Changing into domained home: {}'.format(script_path))

    os.chdir(script_path)

    unameChk = str(subprocess.check_output(['uname', '-am']))

    if "kali" not in unameChk:

        print("\n\033[1;31mKali Linux Recommended!\033[1;37m")

        time.sleep(1)

    sublist3rUpgrade = ("git clone https://github.com/aboul3la/Sublist3r.git ./bin/Sublist3r")

    print("\n\033[1;31mInstalling Sublist3r \033[1;37m")

    os.system(sublist3rUpgrade)

    subInstallReq = ("pip install -r bin/Sublist3r/requirements.txt")

    os.system(subInstallReq)

    print("Sublist3r Installed\n")



    enumallUpgrade = ("git clone https://github.com/jhaddix/domain.git ./bin/domain")

    print("\n\033[1;31mInstalling Enumall \033[1;37m")

    print("\nenumall Installed\n")

    os.system(enumallUpgrade)

    knockpyUpgrade = ("git clone https://github.com/guelfoweb/knock.git ./bin/knockpy")

    print("\n\033[1;31mInstalling Knock \033[1;37m")

    os.system(knockpyUpgrade)

    print("\nKnockpy Installed\n")

    sublstUpgrade = ("git clone https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056 ./bin/sublst")

    print("\n\033[1;31mCopying JHaddix All Domain List: \033[1;37m")

    print("\nJHaddix All Domain List Installed\n")

    os.system(sublstUpgrade)

    SLsublstUpgrade = (

        "wget -O ./bin/sublst/sl-domains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/sortedcombied-knock-dnsrecon-fierce-reconng.txt")

    print("\n\033[1;31mCopying SecList Domain List \033[1;37m")

    print("\nSecList Domain List Installed\n")

    os.system(SLsublstUpgrade)

    subbruteUpgrade = ("git clone https://github.com/TheRook/subbrute.git ./bin/subbrute")

    print("\n\033[1;31mInstalling Subbrute \033[1;37m")

    os.system(subbruteUpgrade)

    print("\nSubbrute Installed\n")

    amassUpgrade = ("go get github.com/caffix/amass")

    print("\n\033[1;31mInstalling Amass \033[1;37m")

    os.system(amassUpgrade)

    massdnsUpgrade = ("git clone --branch v0.2 --single-branch https://github.com/blechschmidt/massdns ./bin/massdns")

    print("\n\033[1;31mInstalling massdns \033[1;37m")

    os.system(massdnsUpgrade)

    massdnsMake = ("make -C ./bin/massdns")

    os.system(massdnsMake)

    print("\nMassdns Installed\n")

    os.system("cp ./bin/subbrute/resolvers.txt ./")

    if "kali" in unameChk:

        reconNGInstall = ("apt-get install recon-ng")

        print("\n\033[1;31mInstalling Recon-ng \033[1;37m")

        os.system(reconNGInstall)

        print("\nRecon-ng Installed\n")

    else:

        print("Please install Recon-ng - https://bitbucket.org/LaNMaSteR53/")

    print("\n\033[1;31mAll tools installed \033[1;37m")

    print('Changing back to old working directory: {}'.format(old_wd))

    os.chdir(old_wd)





def subdomainfile():

    sublist3rFileName = "{}_sublist3r.txt".format(output_base)

    enumallFileName = "{}.lst".format(output_base)

    massdnsFileName = "{}_jaddx.txt".format(output_base)

    amassFileName = "{}_amass.txt".format(output_base)

    SubFinderFileName = "{}_subfinder.txt".format(output_base)

    AltdnsFileName = "{}_altdns.txt".format(output_base)

    subbruteFileName="{}_subbrute.txt".format(output_base)

    gobusterFileName = "{}_gobuster.txt".format(output_base)

    subdomainAllFile = "{}-all.txt".format(output_base)

    f1 = open(subdomainAllFile, "w")
    f1.close()

    print ("Displaying the Subfinder location", SubFinderFileName)
	
    print("\nOpening GoBuster File\n")
    try:
        with open(gobusterFileName) as f:
            SubHosts = f.read().splitlines()
        f.close()
        time.sleep(2)
        subdomainCounter = 0
        f1 = open(subdomainAllFile, "a")
        f1.writelines("\n\nGoBuster")
        for hosts in SubHosts:
            hosts=hosts.split()[1]
            hosts = "".join(hosts)
            f1.writelines("\n" + hosts)
            subdomainCounter = subdomainCounter + 1
        f1.close()
        os.remove(gobusterFileName)
        print("\n{} Subdomains discovered by GoBuster".format(subdomainCounter))
    except:
        print("\nError Opening GoBuster File!\n")

    print("\nOpening Sublist3r File\n")
    try:
        with open(sublist3rFileName) as f:
            SubHosts = f.read().splitlines()
        f.close()
        time.sleep(2)
        subdomainCounter = 0
        f1 = open(subdomainAllFile, "a")
        f1.writelines("\n\nsublist3r")
        for hosts in SubHosts:
            hosts = "".join(hosts)
            f1.writelines("\n" + hosts)
            subdomainCounter = subdomainCounter + 1
        f1.close()
        os.remove(sublist3rFileName)
        print("\n{} Subdomains discovered by Sublist3r".format(subdomainCounter))
    except:
        print("\nError Opening Sublist3r File!\n")


    print("\nOpening Amass File\n")
    try:
        with open(amassFileName) as f:
            SubHosts = f.read().splitlines()
        f.close()
        time.sleep(1)
        subdomainCounter = 0
        f1 = open(subdomainAllFile, "a")
        f1.writelines("\n\namass")
        for hosts in SubHosts:
            hosts = hosts.split(".	")[0]
            if domain in hosts:
                hosts = "".join(hosts)
                f1.writelines("\n" + hosts)
                subdomainCounter = subdomainCounter + 1
        f1.close()
        os.remove(amassFileName)
        print("\n{} Subdomains discovered by Amass".format(subdomainCounter))
    except:
        print("\nError Opening massdns File!\n")


    try:
	print("running insidee the try for subfinder")
	Subfilderlocation="/root/Downloads/domained/output/{}_subfinder.txt".format(domain)
	print(Subfilderlocation)
        with open(Subfilderlocation) as f:
            SubHosts = f.read().splitlines()
	time.sleep(2)
        f.close()
        time.sleep(2)
        subdomainCounter = 0
        f1 = open(subdomainAllFile, "a")
        f1.writelines("\nsubfinder")
        for hosts in SubHosts:
            hosts = "".join(hosts)
            f1.writelines("\n" + hosts)
            subdomainCounter = subdomainCounter + 1
        f1.close()
        os.remove(Subfilderlocation)
        print("\n{} Subdomains discovered by Subfinder".format(subdomainCounter))
    except:
        print("\nError Opening Subfinder File!\n")

    try:
	print("running insidee the try for subbrute")
	Subbrutelocation="/root/Downloads/domained/output/{}_subbrute.txt".format(domain)
	print(Subbrutelocation)
        with open(Subbrutelocation) as f:
            SubHosts = f.read().splitlines()
	time.sleep(2)

        f.close()
        time.sleep(2)
        subdomainCounter = 0
        f1 = open(subdomainAllFile, "a")
        f1.writelines("\nsubbrute")
        for hosts in SubHosts:
            hosts = "".join(hosts)
            f1.writelines("\n" + hosts)
            subdomainCounter = subdomainCounter + 1
        f1.close()
        os.remove(Subbrutelocation)
        print("\n{} Subdomains discovered by Subbrute".format(subdomainCounter))
    except:
        print("\nError Opening Subbrute File!\n")


    print("\nCombining Domains Lists\n")
    domainList = open(subdomainAllFile, "r")
    uniqueDomains = set(domainList)
    domainList.close()
    subdomainUniqueFile = "{}-unique.txt".format(output_base)
    uniqueDomainsOut = open(subdomainUniqueFile, "w")
    for domains in uniqueDomains:
        domains = domains.replace("\n", "")
        if domains.endswith(domain):
            uniqueDomainsOut.writelines("https://{}\n".format(domains))
    uniqueDomainsOut.close()
    time.sleep(1)
    rootdomainStrip = domain.replace(".", "_")

    print("\nCombining Domains without httpsLists\n")
    domainList = open(subdomainAllFile, "r")
    uniqueDomains = set(domainList)
    domainList.close()
    subdomainUniqueFilewithoutHttps = "{}-WithoutHttps.txt".format(output_base)
    uniqueDomainsOut = open(subdomainUniqueFilewithoutHttps, "w")
    for domains in uniqueDomains:
        domains = domains.replace("\n", "")
        if domains.endswith(domain):
            uniqueDomainsOut.writelines("{}\n".format(domains))
    uniqueDomainsOut.close()
    time.sleep(1)
    rootdomainStrip = domain.replace(".", "_")

    print("\nCleaning Up Old Files\n")
    try:
        os.system("rm {}*".format(domain))
        os.system("rm {}*".format(rootdomainStrip))
    except:
        print("\nError Removing Files!\n")


    print ("\n Creating folder and moving all file")

    try:
	mkdir_cmd="mkdir -p ~/Downloads/domained/output/{}".format(domain)
	os.system(mkdir_cmd)
	time.sleep(2)

	mv_cmd="mv ~/Downloads/domained/output/{}* ~/Downloads/domained/output/{}".format(domain,domain)
	os.system(mv_cmd)

    except:
	print("Error in creating ot moving file")

if __name__ == "__main__":

    banner()

    args = get_args()

    domain = args.domain

    output_base = "output/{}".format(domain)

    script_path = os.path.dirname(os.path.realpath(__file__))

    install = args.install

    quick = args.quick
    nmap= args.nmap
    subdomain=args.subdomain
    #massdns=args.massdns
    #dirsearch=args.dirsearch
    

    fresh = args.fresh


    if fresh:

        os.system("rm -r output")

        newpath = r'output'

        os.makedirs(newpath)

    if install:

        upgradeFiles()

    else:

        if domain:

            if quick:

                #Aquatone() # 
                #massdns()
		        #massdns_crt()

                
                amass()
                SubFinder()
                gobuster()
                sublist3r()
                massdns()
                mass_subrute()
                waybackurl()
                waybackurljs()
                subdomainfile()
                subjack()
                urlstatus()
                urlstatus_domain()
                whatweb()
                inception()
                aquatone_new()
                massdns_dig()
                massdns_dig_ip()
                masscan()
                dirsearch()
                
                #massdns()
                #altdns()
                #enumallfilemove()
                #massdns_subdomain()
            elif subdomain:
                massdns()
                #amass()
                #SubFinder()
                #gobuster()
                #sublist3r()
                #waybackurl()
                #waybackurljs()
                #subdomainfile()
                #subjack()

            #elif dirsearch:
                #dirsearch()

            elif massdns:
                urlstatus()
                urlstatus_domain()
                aquatone_new()
                massdns_dig()
                massdns_dig_ip()

            elif nmap:
                masscan()

                



      
