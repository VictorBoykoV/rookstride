"""Authentication capabilities: a connection label is not necessarily a username."""
import hashlib,hmac,re,secrets

PASSWORD_PROTOCOLS=('ikev2','openvpn','hysteria2','trusttunnel','naive')

def policy():return dict(minimum=1,maximum_utf8_bytes=127,recommended_minimum=8,generated_length=15,composition_required=False,advisory=True)

def login(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9._@-]{1,64}',value):
        raise ValueError('Use up to 64 letters, numbers, dots, @, underscores or hyphens for the username')
    return value

def password(value):
    if not isinstance(value,str) or not 1<=len(value)<=127 or any(ord(c)<32 or 127<=ord(c)<=159 or ord(c) in (0x2028,0x2029) or 0xd800<=ord(c)<=0xdfff for c in value):
        raise ValueError('Use a nonempty printable password of at most 127 UTF-8 bytes')
    if len(value.encode('utf-8'))>127:raise ValueError('Use at most 127 UTF-8 bytes for the VPN password')
    return value

def mode(req):
    value=req.get('access_mode','profile')
    if value not in ('profile','password') or value=='password' and req.get('protocol') not in PASSWORD_PROTOCOLS:
        raise ValueError('This protocol uses a connection file or key instead of a username and password')
    return value

def reusable(state):return state.get('access_mode')=='password' and state.get('protocol') in PASSWORD_PROTOCOLS

def hash_password(value):
    salt=secrets.token_hex(16)
    digest=hashlib.pbkdf2_hmac('sha256',password(value).encode(),bytes.fromhex(salt),310000).hex()
    return 'pbkdf2-sha256$310000$'+salt+'$'+digest

def verify(value,stored):
    try:
        scheme,rounds,salt,expected=stored.split('$')
        if scheme!='pbkdf2-sha256' or rounds!='310000' or not re.fullmatch('[a-f0-9]{32}',salt) or not re.fullmatch('[a-f0-9]{64}',expected):return False
        actual=hashlib.pbkdf2_hmac('sha256',value.encode(),bytes.fromhex(salt),int(rounds)).hex()
        return hmac.compare_digest(expected,actual)
    except (ValueError,TypeError,AttributeError):return False

def wire_password(state,user):
    return user['login']+':'+user['password'] if reusable(state) and state['protocol']=='hysteria2' else user['password']
