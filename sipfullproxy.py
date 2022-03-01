
#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socketserver
import re
import string
import socket
import sys
import time
import logging

HOST, PORT = '0.0.0.0', 5060

#reg vyrazy na hladanie jednotlivých poli v obsahu SIP spravy
rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
#rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
#rx_invalid = re.compile("^192\.168")         
#rx_invalid2 = re.compile("^10\.")            
#rx_cseq = re.compile("^CSeq:")
rx_callid = re.compile("Call-ID: (.*)$")
#rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

#dict udržiavajúci registrovaných použivatelov
#kluč je SiP URL registovaneho konta/uživatela z pola To:
#hodnota je pole kde sa nachadza ipadresa:port,info o sockete okial sa zaregistroval,ipadresa klienta,validita registracie
registrar = {} 

callIDs = [] #pomocne pole pre dennik hovorov
ringing = [] #pomocne pole pre dennik hovorov
recordroute = ""
topvia = "" #Via: pole ktoré pridá proxy do message header pri presposlany INVITE,ACK alebo NonInvite správy

#vypis dat spravy v hexy tvare pre log v debug mode - tuto funckiu nepouživame
def hexdump( chars, sep, width ):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust( width, '\000' )
        logging.debug("%s%s%s" % ( sep.join( "%02x" % ord(c) for c in line ),sep, quotechars( line )))

#pomocna funckia na kvotovanie - tuto funckiu nepoužívame
def quotechars( chars ):
	return ''.join( ['.', c][c.isalnum()] for c in chars )

#funcia za vypis času v logu v debug mode - tuto funckiu nepouživame
def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))

#trieda samotnej implementacie SIP serverna na spracovanie SIP sprav ktore pridu na server a ich preposielanie dalej
class UDPHandler(socketserver.BaseRequestHandler):   
    
    #metoda na vypis obsahu registrara v logu ak je v debug mode - my debug mode nepouživame
    def debugRegister(self):
        logging.debug("*** REGISTRAR ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key,registrar[key][0]))
        logging.debug("*****************")
    
    #metoda na zmenu request sip 
    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:   #registrar.has_key(uri): prerobene
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method,uri)
    
    #metoda na odstranenie poľa Route: zo z message header SIP správy
    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data #vrati nove data pre SIP spravu s vymazaným Route: riadkom
    
    #metoda ktorý vracia upraveny obsah SIP spravy ktory vytvori z obsahu prijatej spravy a to tak že
    #- prida do message headeru správy dalšie vlastné Via: pole s rovnakym branch ale končiacim na m
    #- do pôvodneho prijateho Via: prida received a rport teda ipadresu a port klienta od ktoreho je sprava prijata
    def addTopVia(self):
        branch= ""
        data = [] #tu budu dáta noveho message headeru
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:#ak je  cyklus na riadku Via: a nachádza sa v nom branch, tak pridá predneho vlastne Via s rovnakým branch
                    branch=md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(line):#ak je vo Via: riadku rport 
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport",text) #tak nastavi do received a rport ipadresu a port klienta od ktoreho prišla správa
                else:
                    text = "received=%s" % self.client_address[0]#ak sa rport neuvadza nastavi len ipadresu
                    via = "%s;%s" % (line,text)
                data.append(via)
            else:
                data.append(line)
        return data #funckia vráti nove data pre spravu ktora sa bude preposielať s pridaným vlastným Via: polom

    #metoda ktorá vymaže z obsahu prijatej spravy najvrchnejšie pole Via:     
    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)
        return data #vráti upravene data s vymazanym najvrchnejším Via:

    #kontrola validity teda či už nahodu registracia daneho uživatela/konta (teda jeho SIP URL) už nevypršala
    def checkValidity(self,uri): #argumentom je SIP URI pod ktoru je uživatel/konto registrovane v registrary
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:#ak aktualny ca < ako cas vo voladity danej registracie
            return True #registracia je ešte validna
        else:
            del registrar[uri] #vymyzanie registracia z registrara
            logging.warning("registration for %s has expired" % uri)
            return False #registracia nieje validna respektivne už expirovala a bola vymyzana
    
    #metoda na zistenie socketu a ip adresy klienta pomocou SIP URL uživatela uloženej v registrary
    def getSocketInfo(self,uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return (socket,client_addr)
        
    #funckia ktorá z pola To: alebo t: vracia SIP URL konta(použivatela) napr. meno@ipproxy
    def getDestination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" %(md.group(1),md.group(2))
                break
        return destination

    #funckia ktora z pola From: alebo f: vráti SIP URL konta(použivatela) napr. meno@ipproxy      
    def getOrigin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" %(md.group(1),md.group(2))
                break
        return origin
    
    #metoda ktorá vracia hodnotu CallID zo SIP správy
    def getCallId(self,data):
        callid = ""
        for line in data:
            if rx_callid.search(line):
                return line[9:]
        return callid

    #metoda na zostavenie a odoslanie odpovede so zadaným status kodom klientovy od ktoreho sprava prišla
    #odosiela odpovede na REGISTER,SUBSCRIBE,PUBLISH,NOTIFY a ine chybove stavy ktore môžu nastať
    #responce je zostaveny z obsahu pôvodnej spravy + upravy
    def sendResponse(self,code):
        request_uri = "SIP/2.0 " + code #zostavenie status line s verzou sip a stavovým kodom
        self.data[0]= request_uri #nastavenie status line datach pôvodnej správy
        index = 0
        data = [] #pole kde budu riadky message headeru zostavovanej odpovede
        #message header odpovede sa zostavení pomocou message headeru prijatej spravy
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line): #ak riadok s polom To: alebo t:
                if not rx_tag.search(line): #ak sa v poli To: nenachádza to tag, tak tam prida tag=123456
                    data[index] = "%s%s" % (line,";tag=123456")
            if rx_via.search(line) or rx_cvia.search(line): #ak riadok s polom Via: alebo v:
                # rport processing
                if rx_rport.search(line):#ak sa v poli Via: nachádza rport
                    #tak v nom zahradi rport za receive="ip adresa klienta";rport="port klienta" od ktoreho prišiel request na ktory sa ide odpovedať
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace("rport",text) 
                else: #ak nie prida na koniec received="port klienta"
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line,text)      
            if rx_contentlength.search(line): #ak riadok s polom ContentLength tak mu nastaví 0
                data[index]="Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index]="l: 0"
            index += 1
            if line == "":
                break
        data.append("")
        text = "\r\n".join(data) #text = string.join(data,"\r\n") prerobene 
        self.socket.sendto(text.encode("utf-8"),self.client_address) #odoslanie zostavenej odpovede klientovi
        showtime()
        logging.info("<<- [%s] %s" % (self.getCallId(data),data[0]))
        logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))
        
    #metoda na spracovanie REGISTER správy a odpoved klientovi ktorý ju poslal
    def processRegister(self):
        #hodnoty z jednotlivých polí prijatej REGISTER správy
        fromm = ""            #SIP URL z pola To:
        contact = ""          #ipadresa:port z pola Contact: 
        contact_expires = ""  #hodnota expires z pola Contact:
        header_expires = ""   #hodnota expires z pola Expires
        expires = 0           #bud hodnota expires z pola Expires: alebo z pola Contatc:
        validity = 0          #aktualny čas prijatia spravy + hodnota expires

        for line in self.data: #prechádzame všetky riadky z prijatej SIP spravy - teda request line a riadky v message header
            if rx_to.search(line) or rx_cto.search(line): #ak sme na riadku s polom To: alebo t:
                md = rx_uri.search(line) # ak je v danom riadku SIP URI
                if md:
                    fromm = "%s@%s" % (md.group(1),md.group(2)) #ulozi SIP URL z pola To:
            if rx_contact.search(line) or rx_ccontact.search(line): #ak sme na riadku s polom Contact: alebo m:
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2) #ipadresa:port z pola Contact:
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1) #ak ma Contact: pole hodnotu expires tak to si ulozi
            md = rx_expires.search(line) #ak ma Contact: pole hodnotu expires tak to si ulozi
            if md:
                header_expires = md.group(1) #uloži si hodnotu pola resp. riadka Expires: napr 3600 

        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)
            
        if expires == 0: #ak je to sprava na deregistraciu teda expires = 0
            if fromm in registrar: 
                del registrar[fromm] #vymazava si zaznam z registraru podla kluca SIP URL
                self.sendResponse("200 Vsetko okey") #odpoved na deregistraciu 200 OK
                return
        else:
            now = int(time.time())
            validity = now + expires

        #vypis pre naš dennik hovorov a debug log
        logging.info("->> %s | From: %s | Contact: %s" % (self.data[0],fromm,contact))
        logging.debug("Client address: %s:%s" % self.client_address)
        logging.debug("Expires= %d" % expires)
        #zaregistruje použivatela od ktoreho bola prijata tato REGISTER sprava - teda prida mu zaznam do registrara
        registrar[fromm]=[contact,self.socket,self.client_address,validity]
        self.debugRegister()
        self.sendResponse("200 Vsetko okey") #odosle odpoved na registraciu 200 OK

    #metoda na spracovanie prijatej INVITE spravy od klienta a preposlanie druhemu klientovy
    def processInvite(self):
        logging.debug("-----------------")
        logging.debug(" INVITE received ")
        logging.debug("-----------------")
        origin = self.getOrigin()           #z pola From: prijatej spravy si ulozi SIP URI - uzivatel ktori odosiela invite a proxi ho prijala
        destination = self.getDestination() #z pola To: prijatej spravy si ulozi SIP URI - uzivatel ktoremu preposleme INVITE
        callid = self.getCallId(self.data)  #CallID prijatej správy

        oznam = ""
        if callid not in callIDs: #ak ide o prvy INVITE daneho hovoru tak zaloguje že ide o pozvanie do hovoru
            oznam = "- pozvanka do hovoru"
            callIDs.append(callid)
        logging.info("->> [%s] INVITE %s| From:%s -> To:%s" % (callid,oznam,origin,destination))

        if len(origin) == 0 or origin not in registrar: #ak origin 0 alebo odosielatel nieje zaregistrovany
            # odpovedame klientovi od ktoreho prisiel invite 400 Zla poziadavka
            self.sendResponse("400 Zla poziadavka")
            return
        if len(destination) > 0:
            #ak je uzivatel ktoremu mame preposlat INVITE zaregistrovany a jeho registracia ešte valídna
            if destination in registrar and self.checkValidity(destination):
                socket,claddr = self.getSocketInfo(destination) #zistenie socketu klienta ktoremu sa INVITE prepošle
                #self.changeRequestUri()
                self.data = self.addTopVia() #pridanie dalsieho vlastneho Via: do obsahu pôvodnej spravy
                data = self.removeRouteHeader() #odstranenie Route: pola z obsahu prijatej ACK spravy
                #insert Record-Route
                data.insert(1,recordroute) #pridanie vlastnej record route tejto SIP proxy na začiatok message headeru
                text = "\r\n".join(data)                     
                socket.sendto(text.encode("utf-8"), claddr)  #socket posiela bytes takže text treba encode
                showtime()
                logging.info("<<- [%s] INVITE %s| From:%s -> To:%s" % (self.getCallId(data),oznam,origin,destination))
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))
            else:
                # odpovedame klientovi od ktoreho prisiel invite 480 Zla poziadavka
                self.sendResponse("480 Docasne nedostupny") #inak odpoved 480 Docasne nedostupny
        else:
            # odpovedame klientovi od ktoreho prisiel invite 500 Zla poziadavka
            self.sendResponse("500 Interny error servera")

    #metoda na spracovanie prijatej ACK spravy a zostavenie ACK spravy na preposlanie druhemu klientovu ktoremu bola mierená
    def processAck(self):
        logging.debug("--------------")
        logging.debug(" ACK received ")
        logging.debug("--------------")
        destination = self.getDestination() #SIP URL z pola To: prijatej ACK spravy
        callid = self.getCallId(self.data)  #Call ID prijatej ACK správy

        oznam = ""
        if callid in ringing:
            #oznam v denniku hovorov že ide o zaciatok hovoru teda ide o ACK ktore potvrdzuje uspesne zodvihnutie hovoru 
            oznam = "- zaciatok hovoru " 
            ringing.remove(callid)
       
        logging.info("->> [%s] ACK %s" % (callid,oznam))
        if len(destination) > 0:
            #ak je konto teda SIP URI z pola To: prijatej spravy zaregistrovane, 
            #teda ktoremu pojde ACK je destination zaregistrovany - zostavy sa prenho ACK sprava
            if destination in registrar: 
                socket,claddr = self.getSocketInfo(destination) #socket info o klientovi ktoremu sa ide preposlat ACK
                #self.changeRequestUri() 
                self.data = self.addTopVia() #pridanie dalsieho vlastneho Via: do obsahu pôvodnej spravy
                data = self.removeRouteHeader() #odstranenie Route: pola z obsahu prijatej ACK spravy
                #insert Record-Route
                data.insert(1,recordroute) #pridanie vlastnej record route tejto SIP proxy na začiatok message headeru
                text = "\r\n".join(data) 
                socket.sendto(text.encode("utf-8"),claddr) #encode textu na bytes a preposlanie ACK klientovi
                showtime()
                logging.info("<<- [%s] ACK %s" % (self.getCallId(data),oznam))
                logging.debug( "---\n<< server send [%d]:\n%s\n---" % (len(text),text))

    #metoda na spracovanie NonInvite spravy teda BYE,CANCEL,OPTIONS,INFO,MESSAGE,REFER,PRACK alebo UPDATE
    #a jej preposlanie druhemu klientovi ktoremu je mierena, preposlana sprava je zostavena z pôvodnej
    def processNonInvite(self):
        logging.debug("----------------------")
        logging.debug(" NonInvite received   ")
        logging.debug("----------------------")
        origin = self.getOrigin() #SIP URL z pola From: z prijatej nonivite spravy
        destination = self.getDestination() #SIP URL z pola To: z prijatej nonivite spravy
        callid = self.getCallId(self.data) #hodnota CallID z prijatej noninvite spravy

        oznam = ""
        method = self.data[0]
        if rx_bye.search(method):
            method = "BYE"
            #ak ide o správu BYE tak oznam v denniku hovorov že ide o ukončenie hovoru
            oznam = "- ukoncenie hovoru "
            if callid in callIDs:
                callIDs.remove(callid)

        logging.info("->> [%s] %s %s| From:%s -> To:%s" % (callid,method,oznam,origin,destination))
        if len(origin) == 0 or origin not in registrar: #ak konto/uživatel ktory poslal noninvite nieje zaregistrovany
            # odpovedame klientovi (od ktoreho prisiel noninvite) 400 Zla poziadavka
            self.sendResponse("400 Zla poziadavka")
            return
        if len(destination) > 0:
            #ak je konto zaregistrovane a je validne teda nema vypršanu expiraciu
            #tak sa môže zostaviť sprava z prijatej správy
            if destination in registrar and self.checkValidity(destination): 
                socket,claddr = self.getSocketInfo(destination) #socket info o klientovy ktoremu je noninvite mierený
                #self.changeRequestUri()
                self.data = self.addTopVia() #pridanie dalsieho vlastneho Via: do obsahu pôvodnej spravy
                data = self.removeRouteHeader() #odstranenie Route: pola z obsahu prijatej spravy
                #insert Record-Route
                data.insert(1,recordroute) #pridanie vlastnej record route tejto SIP proxy na začiatok message headeru
                text = "\r\n".join(data) 
                #odoslanie zostavenej noninvite spravy na destination socket
                socket.sendto(text.encode("utf-8"), claddr) #preposlanie noninvite spravy na destination klienta
                showtime()
                logging.info("<<- [%s] %s %s| From:%s -> To:%s " % (self.getCallId(data),method,oznam,origin,destination))
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))    
            else:
                # odpovedame klientovi (od ktoreho prisiel noninvite) spravu s kodom 406 
                self.sendResponse("406 Neakceptovatelne")
        else:
            # odpovedame klientovi (od ktoreho prisiel noninvite) spravu s kodom 500
            self.sendResponse("500 Interny error servera")

    #metoda na spracovanie spravy od klienta zo stavovým kodom 
    #a preposlanie dalej druhemu klientovy ktoremu bola mierená.
    #odosielana sprava je zostavena z obsahu prijatej spravy + nejake upravy
    def processCode(self):
        origin = self.getOrigin() #SIP URL z pola From: (napr. alice@192.168.0.12) 
        callid = self.getCallId(self.data) #CallID prijatej správy
        logging.info("->> [%s] %s" % (callid,self.data[0]))
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if origin in registrar:  #kontrola či je uživatel konto (z danou SIP URL) zaregistrovany
                socket,claddr = self.getSocketInfo(origin) #socket info o konte/uživatelovy ktoremu je sprava mierená
                self.data = self.removeRouteHeader() #odstranenie Route: pola z obsahu prijatej spravy
                data = self.removeTopVia()  #odstranenie najvrchnejšieho pola Via: z prijatej spravy

                #pridane podmienoky na upravu SIP stavových kodov
                if "Trying" in data[0]:
                    data[0] = data[0].replace("Trying","Skusam")

                if "Ringing" in data[0]:
                    data[0] = data[0].replace("Ringing","Zvoni")
                    if callid not in ringing:
                        ringing.append(callid)

                if "Decline" in data[0]:
                    data[0] = data[0].replace("Decline","Odmietnutie")

                if "Ok" in data[0]:
                    data[0] = data[0].replace("Ok","Vsetko okey")

                if "Request terminated" in data[0]:
                    data[0] = data[0].replace("Request terminated","Ziadost odmietnuta")

                if "Method not allowed" in data[0]:
                    data[0] = data[0].replace("Method not allowed","Metoda nieje povolena")
                
                if (callid in ringing) and ("Zvoni" not in data[0]) and ("Vsetko okey" not in data[0]):
                    ringing.remove(callid)

                text = "\r\n".join(data)   
                #preposlanie spravy na socket na ktorý bola cielená - teda na konto ktore bolo v poli To:                 
                socket.sendto(text.encode("utf-8"),claddr) 
                showtime()
                logging.info("<<- [%s] %s" % (self.getCallId(data),data[0]))
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))

    #metoda na spracovanie prijatej SIP spravy od klienta
    #zavola prislušnu funkciu na spracovanie spravy podla toho o aky typ ide
    def processRequest(self):
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_register.search(request_uri): 
                self.processRegister()
            elif rx_invite.search(request_uri): 
                self.processInvite()
            elif rx_ack.search(request_uri): 
                self.processAck()
            elif rx_bye.search(request_uri): 
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            #ak ide o spravu SUBSCRIBE,PUBLISH,NOTIFY tak server odpoveda 200 Vsetko okey pomocou funckie sendResponce
            elif rx_subscribe.search(request_uri):
                logging.info(">>> %s" % request_uri)
                self.sendResponse("200 Vsetko okey")
            elif rx_publish.search(request_uri):
                logging.info(">>> %s" % request_uri)
                self.sendResponse("200 Vsetko okey")
            elif rx_notify.search(request_uri):
                logging.info(">>> %s" % request_uri)
                self.sendResponse("200 Vsetko okey")
            #ak ide o responce spravu so stavovým kodom, zavola sa funckia na jej spracovanie a odpoved
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                logging.info(">>> %s" % request_uri)
                logging.error("request_uri %s" % request_uri)          
    
    #metoda ktora je zavolana ked server príjme SIP Spravu na porte 5060
    #metoda pristupuje k obsahu a info o prijatej sprave pomocou atributu request
    def handle(self):
        #nastavenie atributov triedy na prijatu sravu ktora sa ide spraovavať
        data = self.request[0].decode("utf-8")   #request[0] je cely obsah prijatej spravy - request/status line + message header + message body
        self.data = data.split("\r\n")           #pole kde je su všetky riadky obsahu spravy ako samostatne elementy
        self.socket = self.request[1]            #info o sockete
        request_uri = self.data[0]               #request/status line prijatej správy
        #ak je to request teda sprava s metodou alebo sprava so status kodom tak sa bude spracovávať
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri): 
            showtime()
            logging.debug("---\n>> server received [%d]:\n%s\n---" %  (len(data),data))
            logging.debug("Received from %s:%d" % self.client_address)
            self.processRequest() #tak sa zavola metoda na spracovanie správ
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data,' ',16)
                logging.warning("---")


if __name__ == "__main__":    
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s',filename='proxy.log',level=logging.INFO,datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    hostname = socket.gethostname()
    logging.info(hostname)
    ipaddress = socket.gethostbyname(hostname)
    if ipaddress == "127.0.0.1":
        ipaddress = sys.argv[1]
    logging.info(ipaddress)
    recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress,PORT)
    topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress,PORT)
    server = socketserver.UDPServer((HOST, PORT), UDPHandler)
    server.serve_forever()