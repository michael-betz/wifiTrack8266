#!/usr/bin/python3
'''
DNS server which can be used to receive sensor data in a sneaky way.
Takes the subdomain part, decrypts it and publishes the payload over mqtt.
'''
import datetime
import sys
import time
import threading
import traceback
import socketserver
import paho.mqtt.client as mqtt
import ssl
from dnslib import *
from dns_coder import DnsCoder
import argparse
import json


def hexdump(res):
    for i, b in enumerate(res):
        if(len(res) > 16 and (i % 16) == 0):
            print("\n{:04x}: ".format(i), end="")
        print("{:02x} ".format(b), end="")
    print()


g_lastqn = ''


def is_printable(s):
    printable_chars = bytes(string.printable, 'ascii')
    return all(c in printable_chars for c in s)

def dns_response(data, clientAddress):
    global g_lastqn
    """
    This is called for each received packet. Do something with it
    """
    ts = datetime.datetime.now()
    try:
        request = DNSRecord.parse(data)
    except Exception as e:
        print(type(e), e)
        return bytes()
    reply = DNSRecord(
        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
        q=request.q
    )
    qname = request.q.qname
    qn = str(qname)     # The actual Domain string with `.` at the end
    qtype = request.q.qtype
    qt = QTYPE[qtype]   # Should be `A` if valid request

    if qn == g_lastqn:
        return reply.pack()
    g_lastqn = qn

    if qt != 'A' or "_" in qn:
        return reply.pack()

    if not qn.lower().endswith(args.domain + '.'):
        return reply.pack()

    print('{0} :{1:>3s} : {2:s} : '.format(ts, qt, qn), end='')
    if args.mqtt_srv:
        mc.publish('dns/addr', '{0:}:{1:}'.format(*clientAddress))
        mc.publish('dns/raw', qn)
    try:
        payload = dnsC.dns_dec(qn.replace(args.domain, ''))
    except Exception as e:
        print("DECODE ERROR", type(e), e, end='')
        payload = bytes()
    if len(payload):
        if args.mqtt_srv:
            mc.publish('dns/payload', payload)
        if is_printable(payload):
            print(payload.decode(), end='')
        else:
            hexdump(payload)
    rIP = '13.37.13.{0}'.format(len(payload))
    reply.add_answer(
        RR(rname=qname, rtype=qtype, rclass=1, ttl=5, rdata=A(rIP))
    )
    print()
    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        data = self.get_data()
        self.send_data(
            dns_response(data, clientAddress=self.client_address)
        )


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--domain',
        default='.blabla.com',
        help='static part of the domain like .blabla.com'
    )
    parser.add_argument(
        '--port',
        help='UDP port where the server is running',
        type=int,
        default=53
    )
    parser.add_argument(
        '--mqtt-srv',
        help='MQTT server to connect to'
    )
    parser.add_argument(
        '--mqtt-usr',
        help='MQTT username for auth.'
    )
    parser.add_argument(
        '--mqtt-pw',
        help='MQTT password for auth.'
    )
    parser.add_argument(
        '--mqtt-topic',
        help='MQTT base topic. Will publish on <base>/payload and <base>/raw',
        default='dns'
    )
    parser.add_argument(
        '--mqtt-secure',
        action='store_true',
        help="Enable MQTT with encryption over SSL"
    )
    args = parser.parse_args()

    if args.mqtt_srv:
        print("Connecting to mqtt broker", args.mqtt_srv, "...")
        mc = mqtt.Client()
        mc.username_pw_set(args.mqtt_usr, args.mqtt_pw)
        if args.mqtt_secure:
            mc.tls_set_context(ssl.create_default_context())
            mc.connect(args.mqtt_srv, 8883)
        else:
            mc.connect(args.mqtt_srv)
        mc.loop_start()
        mc.publish('dns/raw', 'dns_server.py connected')

    print("Setting up crypto ...")
    with open('secrets.json') as f:
        secrets = json.load(f)
    dnsC = DnsCoder(
        bytes.fromhex(secrets['secret_key']),
        secrets['coding_table']
    )

    print("Starting nameserver...")
    servers = [
        socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler),
        # socketserver.ThreadingTCPServer(('', PORT), TCPRequestHandler),
    ]
    for s in servers:
        # that thread will start one more thread for each request
        thread = threading.Thread(target=s.serve_forever)
        # exit the server thread when the main thread terminates
        thread.daemon = True
        thread.start()
        print("{0} server loop running in thread: {1}".format(
            s.RequestHandlerClass.__name__[:3],
            thread.name
        ))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
