#!/usr/bin/python3
# -*- coding: utf-8 -*-
#Sandra Cobos

"""Program Servidor UDP"""

import socketserve
import sys
from os import system
from uaclient import UAHandler,

RESP_COD = {100: 'SIP/2.0 100 Trying\r\n',
            180: 'SIP/2.0 180 Ring\r\n',
            200: 'SIP/2.0 200 OK'}


class ConfigHandler(socketserver.DatagramRequestHandler):
    """Configuracion cabecera server con los metodos"""
    listenning = ""

    def handle(self):
        data = self.request[0].decode('utf-8')
    print(data)
    obj_log.log_write("recv", REGPROX, data)
    met = data.split()[0]
    if met == "INVITE":
            portp = data.split('m=audio ')[1].split()[0]
            iprtp = data.split('o=')[1].split()[1]
            ConfigHandler.listenning = (iprtp, portp)
            to_send = (RESP_COD[100] + RESP_COD[180] + RESP_COD[200] + "\r\n"
                    + "Content-Type: application/sdp\r\n\r\nv=0\r\no={} {}\r\n"
                    + "s=Conver\r\nt=0\r\nm=audio {} RTP\r\n\r\n")
            to_send = to_send.format(NAME, SERVER[0], PORTP)
            self.wfile.write(bytes(to_send, 'utf-8'))
    elif met == "ACK":
            cmd = "./mp32rtp -i {} -p {} < {}"
            system(cmd.format(SERVER[0], PORTP, AUD_PATH))
    elif met == "BYE":
            to_send = (RESP_COD[200] + "\r\n\r\n")
            self.wfile.write(bytes(to_send, 'utf-8'))
            obj_log.log_write("send", REGPROX, to_send)
    elif met == "ACK":
            cmd = "./mp32rtp -i {} -p {} < {}"
            obj_log.log_write("", "", "")
            system(cmd.format(SERVER[0], PORTP, AUD_PATH))
    elif met == "BYE":
            to_send = (RESP_COD[200] + "\r\n\r\n")
            self.wfile.write(bytes(to_send, 'utf-8'))
            obj_log.log_write("send", REGPROX, to_send)


if __name__ == "__main__":
    "programa principal. escucha servidor"
    try:
        CONFIG = sys.argv[1]
    except (IndexError, ValueError):
        sys.exit("Usage: python3 uaserver.py config")
    cHandler = UAHandler(CONFIG)
    NAME = cHandler.config['account']['username']
    PASS = cHandler.config['account']['passwd']
    SERVER = (cHandler.config['uaserver']['ip'],
              int(cHandler.config['uaserver']['puerto']))
    PORTP = cHandler.config['rtpaudio']['puerto']
    REGPROX = (cHandler.config['regproxy']['ip'],
               int(cHandler.config['regproxy']['puerto']))
                    cHandler.config['regproxy']['puerto'])
    LOG_PATH = cHandler.config['log']['path']
    obj_log = log(LOG_PATH)
    AUD_PATH = cHandler.config['audio']['path']
    SERV = socketserver.UDPServer(SERVER, ConfigHandler)
    print("Escuchando...")
    try:
        SERV.serve_forever()
    except KeyboardInterrupt:
        sys.exit("\r\nClosed")
