#! /usr/bin/python
#
# snom multicast telephone discovery
#
#
# Author: Filip Polsakiewicz <filip.polsakiewicz@snom.de>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socket
import struct
import sys
import re
import time
import string



from optparse import OptionParser

class sip_message(object):
    """Basic representation of a snom phone."""

    def __init__(self, isReq=False, ip=None, port=5060, ip2=None, port2=5060, pkt=None):
        """Default constructor."""
        self.msg_isReq = isReq
        self.msg_rcvIP = ip
	self.msg_rcvPort = port
        self.msg_LocalIP = ip2
	self.msg_LocalPort = port2
	self.msg_method = 'NONE'
	self.msg_pkt = pkt
	self.msg_url = '\0'

def get_headerline_by_name(buffer, name):
	"""find the header line by name"""
	lines = buffer.split('\r\n')
	lineindex = 1
	while True:
		if len(lines[lineindex]) > 2:
			result = int(lines[lineindex].find(name, 0, 10))
			if result != -1:
				return lineindex
			lineindex += 1
		else:
			break
	return 0

def IncreaseMacAddress(mac):
	"""increase the mac value of mac string and process the carry issue"""
	macValue = string.atoi(mac, 16)
	macValue += 1
	mac = "%012x"%macValue
	return mac

def parse(text):
    """Parses the incoming SUBSCRIBE."""
    try:
        lines = text.split('\r\n')

        # Line 1 conatains the SUBSCRIBE and our MAC
        msg = sip_message(pkt=text)
	result = int(lines[0][0:7].find('SIP/2.0'))
	if result == -1:
		msg.msg_isReq = True
		print 'this is a request message'
	else:
		print 'this is a response message'

	#Let's find the Method Type from second line on
	lineindex = 1
	while True:
		if len(lines[lineindex]) > 2:
			result = int(lines[lineindex].find('CSeq:'))
			if result != -1:
				msg.msg_method = lines[lineindex][8:]
				break
			lineindex += 1
		else:
			break

	result = int(text.find('http://'))
	if result != -1:
		msg.msg_url = text[result:]
	lineindex += 1

        return msg
    except:
        print "this may be empty packet\r\n"
        return None

def get_ip_address():
	# This is a simple hack to find our IP address
	# AFAIK this is the only platform-independent way to obtain the address

	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(('snom.com', 0))
	return s.getsockname()[0]

def sendresponse(sock, buffer, msg_info):
	lines = buffer.split('\r\n')
	# Some SIP info we need
	lineindex = get_headerline_by_name(buffer, "Call-ID")
	if lineindex == 0:
		return False
	call_id = lines[lineindex][9:]
	lineindex = get_headerline_by_name(buffer, "CSeq")
	if lineindex == 0:
		return False
	cseq = lines[lineindex][6]
	lineindex = get_headerline_by_name(buffer, "Via")
	if lineindex == 0:
		return False
	via_header = lines[lineindex]
	lineindex = get_headerline_by_name(buffer, "From")
	if lineindex == 0:
		return False
	from_header = lines[lineindex]
	lineindex = get_headerline_by_name(buffer, "To")
	if lineindex == 0:
		return False
	to_header = lines[lineindex]
	ok_response = "SIP/2.0 200 OK\r\n"
	ok_response += via_header + "\r\n"
	ok_response += "Contact: <sip:" + msg_info.msg_LocalIP + ":" + "%d"%msg_info.msg_LocalPort + ";transport=tcp;handler=dum>\r\n"
	ok_response += to_header + "\r\n"
	ok_response += from_header + "\r\n"
	ok_response += "Call-ID: %s\r\n" % call_id
	ok_response += "CSeq: %s NOTIFY\r\nExpires: 0\r\nContent-Length: 0\r\n\r\n" % cseq

	print "from[%s:%d] to[%s:%d]\r\n"%(msg_info.msg_LocalIP, msg_info.msg_LocalPort, msg_info.msg_rcvIP, msg_info.msg_rcvPort)
	#print "%s\r\n"%ok_response
	sock.sendto(ok_response, (msg_info.msg_rcvIP, msg_info.msg_rcvPort))
	return True

multicast_address = None
mac_address="000b82000001"

parser = OptionParser()
parser.add_option('-d', '--multicast', action="store", dest="multicast_address", help="PDS discovery address")
parser.add_option('-r', '--multicast port', action="store", dest="multicast_port", help="PDS discovery port")
parser.add_option('-l', '--localip', action="store", dest="local_ip", help="local ip address")
parser.add_option('-p', '--localport', action="store", dest="local_port", help="local port number")
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="make lots of noise")
parser.add_option('-t', '--interval', action="store", dest="test_interval", help="test interval")
parser.add_option("-c", "--count", action="store", dest="request_num", help="request amount of sip subscribe with increasing MAC")
(options, args) = parser.parse_args()


print """
  '__'
  (oo)
  (__)````````)\\
     ||-----||  *
"""
print "multicast SUBSCRIBE is sent to %s\n" % '192.168.124.165'


if not options.local_ip:
    ip_adr = get_ip_address()
else:
    ip_adr = options.local_ip

if not options.multicast_address:
    multicast_address = '192.168.124.165'
else:
    multicast_address = options.multicast_address


if not options.multicast_port:
    multicast_port = 5060
else:
    multicast_port = int(options.multicast_port)


if not options.local_port:
    local_port = int(5060)
else:
    local_port = options.local_port

if not options.request_num:
    request_num = int(100)
else:
    request_num = int(options.request_num)


if not options.test_interval:
    test_interval = float(1)
else:
    test_interval = float(options.test_interval)


print "Local IP Address is :: %s" % ip_adr
print "=" * 80
#time.sleep(20)

cseq = 1
url_count = 0
test_count = 0

# Create a socket to send data
sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sendsock.bind(('%s' % ip_adr, local_port))
sendsock.settimeout(1)

print "test is started, request amount is %d\r\n"%request_num

# send multicast SUBSCRIBE request to local network...
while True:
	if request_num <= 0:
		break
	request_num = 0
	#if options.verbose:
	print mac_address

	multi_SUBSCRIBE = '''SUBSCRIBE sip:192.168.124.165:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.124.64:5060;branch=z9hG4bK727089497;rport
From: <sip:1650@192.168.124.165>;tag=202346309
To: <sip:1652@192.168.124.165>;tag=d388f0bc-6967-48fe-8e7b-1f21f7500495
Call-ID: 747469135-5060-33@192.168.124.64
CSeq: 200202 SUBSCRIBE
Contact: <sip:1650@192.168.124.64:5060>
Max-Forwards: 70
Supported: replaces, path, timer, eventlist
User-Agent: Grandstream GXV3240 1.0.3.6
Expires: 0
Supported: replaces, path, timer, eventlist
Event: dialog
Accept: application/dialog-info+xml, multipart/related, application/rlmi+xml
Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE, MESSAGE
Content-Length: 0
'''

	sendsock.sendto(multi_SUBSCRIBE, (multicast_address, multicast_port))

	recv_retry = 2
	while True:
		# Create a socket to receive data
		try:
			subs, rcvaddress= sendsock.recvfrom(10240)
		except:
			print "there is no packet %s\r\n" % recv_retry
			recv_retry -= 1
			if recv_retry <= 0:
				break
			continue
		if options.verbose: print subs
		service_msg = parse(subs)
		service_msg.msg_LocalIP = ip_adr
		service_msg.msg_LocalPort = local_port
		rcv_host, rcv_port = rcvaddress
		service_msg.msg_rcvIP = rcv_host
		service_msg.msg_rcvPort = rcv_port

		if service_msg:
			if service_msg.msg_isReq:
				print "%s request is received, url=%s\r\n" % (service_msg.msg_method, service_msg.msg_url)
				if len(service_msg.msg_url) > 0:
					url_count += 1

				sendresponse(sendsock, subs, service_msg)
				break
			else:
				print "%s response is received\r\n" % service_msg.msg_method

	mac_address = IncreaseMacAddress(mac_address)
	test_count += 1
	time.sleep(test_interval)

sendsock.close()

print "=" * 40
print "Final Statistics:"
print "try %d times, get %d valid url\r\n" % (test_count , url_count)
print "=" * 40
time.sleep(1)
