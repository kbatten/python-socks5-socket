#!/usr/bin/env python

# monkey patch socks5 support into sockets

import os
import socket
import struct


def _split_proxy(uri, port):
    split_auth = uri.split("@")
    if uri == "":
        split_uri = []
    elif len(split_auth) == 2:
        split_first = split_auth[0].split(":")
        split_second = split_auth[1].split(":")
        if len(split_first) == 3:
            split_uri = [int(split_first[0])] + split_first[1:] + [split_second[0], int(split_second[1])]
        else:
            split_uri = [int(split_first[0])] + split_first[1:] + [""] + [split_second[0], int(split_second[1])]
    else:
        split_small = split_auth[0].split(":")
        split_uri = [int(split_small[0])] + [""] + [""] + [split_small[1]] + [int(split_small[2])]
    if len(split_uri) != 5:
        split_uri = None
    elif split_uri[0] != port:
        split_uri = None
    return split_uri


# CAVEATS:
# only supports ipv4
# only supports socks5
# user/pass auth has not been tested
# if socks_proxy env variable is set, all socket connections on that port will use it
class Socks5Socket(socket.socket):
    def connect(self, address):
        # socks_proxy=<DESTPORT:>[username[:password]@]<PROXYHOST:><PROXYPORT>
        socks_proxy = _split_proxy(os.getenv("socks_proxy",""), address[1])

        if not socks_proxy:
            true_socket.connect(self, address)
        else:
#            print "{socks_host}:{socks_port} -> {remote_host}:{remote_port}".format(socks_host=socks_proxy[3], socks_port=socks_proxy[4], remote_host=address[0], remote_port=address[1])
            true_socket.connect(self, (socks_proxy[3], socks_proxy[4]))
            auth_methods_available = 1
            auth_methods = [0x00]
            if socks_proxy[1]:
                auth_methods_available += 1
                auth_methods.append(0x02)

            # greet the socks server
            msg = struct.pack("!BB",0x05,auth_methods_available)
            for auth_method in auth_methods:
                msg += struct.pack("!B", auth_method)
#            print msg.encode("hex")
            self.send(msg)
            resp = self.recv(2)
#            print resp.encode("hex")
            (version, auth_method) = struct.unpack("!BB", resp)

            # authorize to the socks server
            if auth_method == 0x00:
                pass
            elif auth_method == 0x02:
                # TODO: test this :/
                msg = struct.pack("!BBsBs", 0x01, len(socks_proxy[1]), socks_proxy[1], len(socks_proxy[2]), socks_proxy[2])
#                print msg.encode("hex")
                self.send(msg)
                resp = self.recv(2)
#                print resp.encode("hex")
                (version, status) = struct.unpack("!BB", resp)
                if status != 0:
                    self.close()
                    raise Exception("socks authorization failed")
            else:
                raise Exception("no acceptable socks authorization available")

            # set connection to tcp/ip stream, ipv4
            ipb = [int(b) for b in address[0].split(".")]
            msg = struct.pack("!B B B B BBBB H",0x05,0x01,0x00,0x01,ipb[0],ipb[1],ipb[2],ipb[3],address[1])
#            print msg.encode("hex")
            self.send(msg)
            resp = self.recv(10)
#            print resp.encode("hex")
            (version, status) = struct.unpack("!B B 8x", resp)
            if status != 0:
                self.close()
                raise Exception("socks connection failed, error: " + status)
            

true_socket = socket.socket
socket.socket = Socks5Socket
