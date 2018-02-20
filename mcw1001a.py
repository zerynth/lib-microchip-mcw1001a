"""
.. module:: mcw1001a

***************
MCW1001A Module
***************

This Zerynth module currently supports multiple concurrent udp and tcp sockets both in client and server mode (`datasheet <http://ww1.microchip.com/downloads/en/DeviceDoc/70671A.pdf>`_).

No select support is provided. No DNS service.
For WIFI security, only WPA2 is currently supported.

Usage example: ::

    import streams
    from wireless import wifi
    from microchip.mcw1001a import mcw1001a
    
    streams.serial()

    # connect to a wifi network
    try:
        mcw1001a.init(SERIAL1,D16) # specify which serial port will be used and which RST pin

        print("Establishing Link...")
        wifi.link("Network SSID",wifi.WIFI_WPA2,"Password")
        print("Ok!")        
    except Exception as e:
        print(e)


    """



import streams
import threading
import queue
import socket as socks

_ser = None
_serlock = threading.Lock()
_lk = threading.Lock()

# messages
__define(RESET_MSG,170)
__define(SET_CP_NETWORK_MODE_MSG,55)
__define(SET_CP_SSID_MSG,57)
__define(SET_CP_SECURITY_WPA_MSG,68)
__define(Wi_Fi_CONNECT_MSG,90)
__define(Wi_Fi_DISCONNECT_MSG,91)
__define(GET_NETWORK_STATUS,48)
__define(SOCKET_CREATE_MSG,110)
__define(SOCKET_CREATE_RESPONSE_MSG,23)
__define(SOCKET_CLOSE_MSG,111)
__define(SOCKET_BIND_MSG,112)
__define(SOCKET_BIND_RESPONSE_MSG,24)
__define(SOCKET_CONNECT_MSG,113)
__define(SOCKET_CONNECT_RESPONSE_MSG,25)
__define(SOCKET_LISTEN_MSG,114)
__define(SOCKET_LISTEN_RESPONSE_MSG,26)
__define(SOCKET_ACCEPT_MSG,115)
__define(SOCKET_ACCEPT_RESPONSE_MSG,27)
__define(SOCKET_SEND_MSG,116)
__define(SOCKET_SEND_RESPONSE_MSG,28)
__define(SOCKET_RECV_MSG,117)
__define(SOCKET_RECV_RESPONSE_MSG,29)
__define(SOCKET_SEND_TO_MSG,118)
__define(SOCKET_SEND_TO_RESPONSE_MSG,30)
__define(SOCKET_RECV_FROM_MSG,119)
__define(SOCKET_RECV_FROM_RESPONSE_MSG,31)




__define(HAS_ACK,1)
__define(WAIT_ACK,2)
__define(WAIT_RES,4)
__define(WAIT_FAIL,8)

q = queue.Queue(1)


def init(ser,rst):
    global _ser
    pinMode(rst,OUTPUT_PUSHPULL)
    _ser = streams.serial(ser,115200,stopbits=streams.STOPBIT_2,set_default=False)
    #_ser.write("\x55\x55\x55\x55")
    thread(_readloop)
    digitalWrite(rst,0)
    sleep(100)
    digitalWrite(rst,1)
    __builtins__.__default_net["wifi"] = __module__
    __builtins__.__default_net["sock"][0] = __module__
    #p = _packet(RESET_MSG)
    #_tohex(p,">>")
    #_ser.write(p)
    

def _packet(type,data=None):
    if data:
        sz = len(data)
    else:
        sz = 0
    p = bytearray(7+sz)
    # header
    p[0]=0x55
    p[1]=0xAA
    # little endian msg type
    p[2]=type&0xff
    p[3]=(type>>8)&0xff
    # little endian msg SIZE
    p[4]=sz&0xff
    p[5]=(sz>>8)&0xff
    # data
    if sz:
        p[6:-1]=data
    # trailer byte
    p[-1]=0x45
    return p

def _read_msg():
    hh = _ser.read(1)
    while hh[0]!=0x55:
        hh=_ser.read(1)
    hh = _ser.read(5)
    #_tohex(hh,"MSG")
    if hh[0]==0xAA:
        #msg header
        msgtype = hh[1]+(hh[2]<<8)
        msglen = hh[3]+(hh[4]<<8)
        if msglen:
            p = _ser.read(msglen)
        else:
            p = None
        # trailer will be skipped next msg if present
        #_tohex(p)
        return msgtype,p
    return -1,None

def _tohex(data,p="<<"):
    if data:
        print(p,"[",end="")
        for x in data:
            print(hex(x,""),end="")
        print("]")
    else:
        print(p,"[]")

_wait_ack = threading.Event()
_messages = {}
_sockets = {}
_wait_msg = threading.Event()
_last_msgs = [None,None]

def _writeloop():
    global _messages,_last_msgs
    while True:
        msg = q.get()
        #_tohex(msg.packet,">>")
        _last_msgs[msg.tp] = msg
        #print("--",msg.id)
        _wait_ack.clear()
        _ser.write(msg.packet)
        _wait_ack.wait()
        _wait_msg.set()
        _wait_msg.clear()

_linked = False

def _readloop():
    global _linked,_sockets
    while True:
        msgtype,msg = _read_msg()
        if msgtype == SOCKET_SEND_RESPONSE_MSG:
            _last_msg = _last_msgs[1]
        else:
            _last_msg = _last_msgs[0]
        #print("##",msgtype,_last_msg.id if _last_msg else -100)
        if msgtype == 1: #EVENT
            etype = msg[0]
            if etype==26: #PING
                pass
            elif etype==255: #ERROR
                if msg[2]==69: #recvfrom failed
                    _sockets[msg[3]]=False
                elif msg[2]==65:
                    _sockets[msg[3]]=False
            elif etype==27: #STARTUP
                thread(_writeloop)
            elif etype==9: #WIFI SCAN
                pass
            elif etype==8: #WIFI CONNECTION
                estatus = msg[1]
                if estatus==1 or estatus==4:
                    _linked=True
                    # msg will be released in ip assigned
                else:
                    _linked = False
                    if _last_msg.id == Wi_Fi_DISCONNECT_MSG and estatus==5:
                        _wait_ack.set()
            elif etype==16: #IP ASSIGNED
                if _last_msg.id == Wi_Fi_CONNECT_MSG:
                    _wait_ack.set()
                elif _last_msg.id == Wi_Fi_DISCONNECT_MSG:
                    _wait_ack.set()
        else:
            #piggyback msgs
            msgtype=msgtype&0x7fff
            if msgtype==0:
                if _last_msg.ack&WAIT_ACK or _last_msg.ack&WAIT_FAIL:
                    _wait_ack.set()
                #pass #ACK
            elif msgtype==GET_NETWORK_STATUS and _last_msg.id==GET_NETWORK_STATUS:
                m = _last_msg
                m.mac = msg[1:7]
                m.ip=(msg[7],msg[8],msg[9],msg[10])
                m.nm=(msg[23],msg[24],msg[25],msg[26])
                m.gw=(msg[39],msg[40],msg[41],msg[42])
                m.dns=(0,0,0,0)
                _wait_ack.set()
            elif msgtype==SOCKET_CREATE_RESPONSE_MSG and _last_msg.id==SOCKET_CREATE_MSG:
                m = _last_msg
                m.sock=msg[0]
                if m.sock<0xfe:
                    _sockets[m.sock] = True
                _wait_ack.set()
            elif msgtype==SOCKET_CONNECT_RESPONSE_MSG and _last_msg.id==SOCKET_CONNECT_MSG:
                m = _last_msg
                m.connected = msg[0]
                _wait_ack.set()
            elif msgtype==SOCKET_SEND_RESPONSE_MSG and _last_msg.id==SOCKET_SEND_MSG:
                m = _last_msg
                m.sent = msg[0]+(msg[1]<<8)
                #print("??",m.sent)
                _wait_ack.set()
            elif msgtype==SOCKET_SEND_TO_RESPONSE_MSG and _last_msg.id==SOCKET_SEND_TO_MSG:
                m = _last_msg
                m.sent = msg[0]+(msg[1]<<8)
                _wait_ack.set()
            elif msgtype==SOCKET_RECV_RESPONSE_MSG and _last_msg.id==SOCKET_RECV_MSG:
                m = _last_msg
                m.buflen = msg[2]+(msg[3]<<8)
                if m.buflen:
                    m.buffer = msg[4:4+m.buflen]
                _wait_ack.set()
            elif msgtype==SOCKET_RECV_FROM_RESPONSE_MSG and _last_msg.id==SOCKET_RECV_FROM_MSG:
                m = _last_msg
                m.address= ((msg[4],msg[5],msg[6],msg[7]),msg[2]+(msg[3]<<8))
                m.buflen = msg[20]+(msg[21]<<8)
                if m.buflen:
                    m.buffer = msg[22:22+m.buflen]
                _wait_ack.set()
            elif msgtype==SOCKET_BIND_RESPONSE_MSG and _last_msg.id==SOCKET_BIND_MSG:
                _last_msg.bound = msg[2]==0
                _wait_ack.set()
            elif msgtype==SOCKET_LISTEN_RESPONSE_MSG and _last_msg.id==SOCKET_LISTEN_MSG:
                _last_msg.bound = msg[0]==0
                _wait_ack.set()
            elif msgtype==SOCKET_ACCEPT_RESPONSE_MSG and _last_msg.id==SOCKET_ACCEPT_MSG:
                _last_msg.bound = msg[0]!=0xff
                _last_msg.sock = msg[0]
                _last_msg.address = ((msg[4],msg[5],msg[6],msg[7]),msg[2]+(msg[3]<<8))
                _wait_ack.set()


class Msg():
    def __init__(self,packet,ack,tp=0):
        self.packet = packet
        self.ack = ack
        self.id = packet[2]+(packet[3]<<8)
        #self.evt = threading.Event()
        self.evt = _wait_msg
        self.tp = tp


def link(ssid,security,password=""):
    #print("SET NET MODE")
    msg = Msg(_packet(SET_CP_NETWORK_MODE_MSG,b'\x01\x01'),HAS_ACK|WAIT_ACK)
    q.put(msg)
    msg.evt.wait()
    #print("SET SSID")
    data = bytearray(len(ssid)+2)
    data[0] = 1
    data[1] = len(ssid)
    for i in range(2,len(data)):
        data[i] = __byte_get(ssid,i-2)
    msg = Msg(_packet(SET_CP_SSID_MSG,data),HAS_ACK|WAIT_ACK)
    q.put(msg)
    msg.evt.wait()
    #print("SET SECURITY") #TODO: support all other security
    data = bytearray(len(password)+4)
    data[0]=1
    data[1]=6
    data[2]=0
    data[3]=len(password)
    for i in range(4,len(data)):
        data[i] = __byte_get(password,i-4)
    msg = Msg(_packet(SET_CP_SECURITY_WPA_MSG,data),HAS_ACK|WAIT_ACK)
    q.put(msg)
    msg.evt.wait()
    #print("Connecting")
    msg = Msg(_packet(Wi_Fi_CONNECT_MSG,b'\x01\x00'),HAS_ACK|WAIT_RES)
    q.put(msg)
    msg.evt.wait()
    if not _linked:
        raise IOError

def is_linked():
    return _linked
    # msg = Msg(_packet(GET_NETWORK_STATUS),WAIT_RES)
    # q.put(msg)
    # msg.evt.wait()
    # return msg.status!=0

def unlink():
    if _linked:
        msg = Msg(_packet(Wi_Fi_DISCONNECT_MSG),HAS_ACK|WAIT_RES)
        q.put(msg)
        msg.evt.wait()

    

def link_info():
    msg = Msg(_packet(GET_NETWORK_STATUS),WAIT_RES)
    q.put(msg)
    msg.evt.wait()
    return (msg.ip,msg.nm,msg.gw,msg.dns,msg.mac)



def socket(family,type,proto):
    global _sockets
    msg = Msg(_packet(SOCKET_CREATE_MSG,b'\x00\x00' if type==socks.SOCK_DGRAM else b'\x01\x00'),WAIT_RES)
    q.put(msg)
    msg.evt.wait()
    if msg.sock<0:
        raise IOError
    return msg.sock

def close(sock):
    global _sockets
    p = bytearray(2)
    p[0]=sock
    _sockets[sock] = False
    msg = Msg(_packet(SOCKET_CLOSE_MSG,p),HAS_ACK|WAIT_ACK)
    q.put(msg)
    msg.evt.wait()
    


def connect(sock,addr):
    p = bytearray(20)
    if type(addr[0])==PSTRING:
        ip = socks.ip_to_tuple(addr[0])
    else:
        ip = addr[0]
    p[0]=sock
    p[2]=addr[1]&0xff
    p[3]=(addr[1]>>8)&0xff
    p[4]=ip[0]
    p[5]=ip[1]
    p[6]=ip[2]
    p[7]=ip[3]
    while True:
        msg = Msg(_packet(SOCKET_CONNECT_MSG,p),WAIT_RES)
        q.put(msg)
        msg.evt.wait()
        if not msg.connected:
            return
        elif msg.connected==0xFF:
            raise IOError
        else:
            sleep(100)


def send(sock,buf,flags=0):
    tosend = len(buf)
    sent = 0
    #print("to send",tosend)
    while sent<tosend:
        tsnd = min(500,tosend-sent)  #max is 500
        #print("sending",tsnd)
        p = bytearray(4+tsnd)
        p[0]=sock
        p[2]=tsnd&0xff
        p[3]=(tsnd>>8)&0xff
        p[4:]=buf[sent:sent+tsnd]
        msg = Msg(_packet(SOCKET_SEND_MSG,p),WAIT_RES | WAIT_FAIL,tp=1)
        _lk.acquire()
        q.put(msg)
        #print("waiting for msg")
        msg.evt.wait()
        try:
            #print("!!",msg)
            sent+=msg.sent
        except Exception as e:
            _lk.release()
            #print("!!!!",e)
            raise IOError
        _lk.release()
    return sent

def sendall(sock,buf,flags=0):
    return send(sock,buf,flags)

def sendto(sock,buf,addr,flags=0):
    tsnd = min(500,len(buf))  #max is 500
    p = bytearray(22+tsnd)
    if type(addr[0])==PSTRING:
        ip = socks.ip_to_tuple(addr[0])
    else:
        ip = addr[0]
    p[0]=sock
    p[2]=addr[1]&0xff
    p[3]=(addr[1]>>8)&0xff
    p[4]=ip[0]
    p[5]=ip[1]
    p[6]=ip[2]
    p[7]=ip[3]
    p[20]=tsnd&0xff
    p[21]=(tsnd>>8)&0xff
    p[22:]=buf[:tsnd]
    msg = Msg(_packet(SOCKET_SEND_TO_MSG,p),WAIT_RES | WAIT_FAIL)
    q.put(msg)
    msg.evt.wait()
    try:
        return msg.sent
    except:
        raise IOError


def recv_into(sock,buf,bufsize,flags=0,ofs=0):
    rr = 0
    tbr=1
    p = bytearray(4)
    p[0]=sock
    while rr<bufsize:
        #print("eqq",tbr)
        toread = min(500,bufsize-rr)
        p[2]=toread&0xff
        p[3]=(toread>>8)&0xff
        msg = Msg(_packet(SOCKET_RECV_MSG,p),WAIT_RES | WAIT_FAIL)
        _lk.acquire()
        q.put(msg)
        msg.evt.wait()
        try:
            if msg.buflen:
                buf[ofs+rr:ofs+rr+msg.buflen]=msg.buffer
                rr+=msg.buflen
            else:
                _lk.release()
                #check error? sleep?
                sleep(50)
                _lk.acquire()
        except Exception as e:
            #print("?!?",e)
            _lk.release()
            raise IOError
        _lk.release()
    return rr

def bind(sock,addr):
    p = bytearray(4)
    p[0]=addr[1]&0xff
    p[1]=(addr[1]>>8)&0xff
    p[2]=sock
    msg = Msg(_packet(SOCKET_BIND_MSG,p),WAIT_RES | WAIT_FAIL)
    q.put(msg)
    msg.evt.wait()
    if not msg.bound:
        raise IOError


def listen(sock,maxlog=2):
    p = bytearray(2)
    p[0]=sock
    p[1]=maxlog
    msg = Msg(_packet(SOCKET_LISTEN_MSG,p),WAIT_RES | WAIT_FAIL)
    q.put(msg)
    msg.evt.wait()
    if not msg.bound:
        raise IOError
    

def accept(sock):
    p = bytearray(2)
    p[0]=sock
    while True:
        msg = Msg(_packet(SOCKET_ACCEPT_MSG,p),WAIT_RES | WAIT_FAIL)
        q.put(msg)
        msg.evt.wait()
        if msg.bound:
            return (msg.sock,msg.address)
        else:
            sleep(100)


def recvfrom_into(sock,buf,bufsize,flags=0):
    p = bytearray(4)
    p[0]=sock
    p[2]=bufsize&0xff
    p[3]=(bufsize>>8)&0xff
    while True:
        #print("eqq",tbr)
        toread = min(500,bufsize)
        msg = Msg(_packet(SOCKET_RECV_FROM_MSG,p),WAIT_RES | WAIT_FAIL)
        q.put(msg)
        msg.evt.wait()
        try:
            if msg.buflen:
                buf[:msg.buflen]=msg.buffer
                return (msg.buflen,msg.address)
            else:
                #check error? sleep?
                sleep(50)
        except:
            raise IOError





