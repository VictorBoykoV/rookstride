"""Bounded DNS A-response checks for disposable client probes.

AdGuard may block with NXDOMAIN, an empty answer, or a sink address. A sink
answer is not evidence that an advertisement resolved to a real destination.
"""
import ipaddress,struct

def name_end(data,pos):
    for _ in range(128):
        if pos>=len(data):raise ValueError('Truncated DNS name')
        size=data[pos];pos+=1
        if size==0:return pos
        if size&0xc0==0xc0:
            if pos>=len(data):raise ValueError('Truncated DNS pointer')
            return pos+1
        if size&0xc0 or pos+size>len(data):raise ValueError('Invalid DNS label')
        pos+=size
    raise ValueError('Oversized DNS name')

def response(data,ident):
    if len(data)<12:raise ValueError('Truncated DNS response')
    got,flags,questions,answers,_,_=struct.unpack('!6H',data[:12])
    if got!=ident or not flags&0x8000 or flags&0x200 or questions>50 or answers>100:raise ValueError('Unexpected DNS response')
    pos=12;addresses=[]
    for _ in range(questions):
        pos=name_end(data,pos)+4
        if pos>len(data):raise ValueError('Truncated DNS question')
    for _ in range(answers):
        pos=name_end(data,pos)
        if pos+10>len(data):raise ValueError('Truncated DNS record')
        kind,cls,_,size=struct.unpack('!HHIH',data[pos:pos+10]);pos+=10
        if pos+size>len(data):raise ValueError('Truncated DNS value')
        if kind==1 and cls==1:
            if size!=4:raise ValueError('Invalid DNS A record')
            addresses.append(ipaddress.IPv4Address(data[pos:pos+4]))
        pos+=size
    return {'rcode':flags&15,'answers':answers,'addresses':addresses}

def allowed(value):
    return value['rcode']==0 and bool(value['addresses']) and all(ip.is_global for ip in value['addresses'])

def blocked(value):
    return value['rcode']==3 or value['rcode']==0 and (value['answers']==0 or bool(value['addresses']) and all(ip.is_unspecified or ip.is_loopback for ip in value['addresses']))
