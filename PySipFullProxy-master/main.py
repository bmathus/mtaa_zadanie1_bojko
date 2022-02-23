import sipfullproxy
import logging
import time
import socket
import socketserver

print("SIP Proxy")
print("Press anything - to start proxy server")
print("Press 0 - to exit")
if input() != "0":

    host_name = socket.gethostname()
    ipaddress = socket.gethostbyname(host_name)

    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s',filename='dennik.log',level=logging.INFO,datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y"))
    logging.info(f"SIP Proxy starter at: {host_name}, {ipaddress}:{5060}")

    sipfullproxy.recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress,5060)
    sipfullproxy.topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress,5060)
    
    udp_server = socketserver.UDPServer(("0.0.0.0", 5060), sipfullproxy.UDPHandler)
    print("Proxi is running...press ctrl+c to terminate")
    udp_server.serve_forever()
else:
    exit()


