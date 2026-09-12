# Independent Gate-B check: own minimal implementation, no import of Emmy's reference code.
import json, hashlib, sys
R='/tmp/claude-1000/-home-martin-Projekte-Claude-OpenSSL-Fork/6f22a499-c749-43d5-95c3-537696cbf897/scratchpad/ed301pub'
par=json.load(open(f'{R}/provenance/phase-a/2026-09-09/parameter/ed301-v2.json'))
p=int(par['field']['p_decimal']); a=int(par['edwards']['a_decimal']); d=int(par['edwards']['d_decimal']); q=int(par['group']['q_decimal'])
A=int(par['montgomery']['A_decimal']); B=int(par['montgomery']['B_decimal']); Nt=int(par['twist']['order_decimal'])
Gx=int(par['basepoint']['G_edwards_x_decimal']); Gy=int(par['basepoint']['G_edwards_y_decimal']); G=(Gx,Gy)
inv=lambda z: pow(z%p,-1,p)
def on(P): x,y=P; return (a*x*x+y*y-1-d*x*x*y*y)%p==0
def eadd(P,Q):
    x1,y1=P; x2,y2=Q; k=d*x1*x2*y1*y2%p
    return ((x1*y2+y1*x2)*inv(1+k)%p,(y1*y2-a*x1*x2)*inv(1-k)%p)
def emul(n,P):
    Rr=(0,1)
    while n:
        if n&1: Rr=eadd(Rr,P)
        P=eadd(P,P); n>>=1
    return Rr
def fe_dec(b):
    if not isinstance(b,bytes) or len(b)!=38 or b[37]&0xe0: raise ValueError
    v=int.from_bytes(b,'little')
    if v>=p: raise ValueError
    return v
def fe_enc(v): return v.to_bytes(38,'little')
def pt_enc(P): e=bytearray(fe_enc(P[1])); e[37]|=(P[0]&1)<<7; return bytes(e)
def pt_dec(b):
    if not isinstance(b,bytes) or len(b)!=38 or b[37]&0x60: raise ValueError
    sign=b[37]>>7; yb=bytearray(b); yb[37]&=0x1f; y=int.from_bytes(yb,'little')
    if y>=p: raise ValueError
    den=(a-d*y*y)%p
    if den==0: raise ValueError
    x2=(1-y*y)*inv(den)%p; x=pow(x2,(p+1)//4,p)
    if x*x%p!=x2: raise ValueError
    if x&1: x=p-x
    if x==0 and sign: raise ValueError
    if (x&1)!=sign: x=p-x
    P=(x,y); assert on(P); return P
def sc_dec(b):
    if len(b)!=38: raise ValueError
    v=int.from_bytes(b,'little')
    if v>=q: raise ValueError
    return v
def shake(*parts):
    h=hashlib.shake_256()
    for x in parts: h.update(x)
    return h.digest(76)
def dom(C):
    if len(C)>255: raise ValueError
    return b"SigEd301-v2"+bytes([0,len(C)])+C
def expand(seed):
    h=shake(seed); lo=bytearray(h[:38]); lo[0]&=0xfc; lo[37]=(lo[37]&0x0f)|0x10
    return int.from_bytes(lo,'little'), h[38:], h, bytes(lo)
def sign(seed,M,C=b""):
    s,prefix,h,lo=expand(seed); Aenc=pt_enc(emul(s,G)); D=dom(C)
    nh=shake(D,prefix,M); r=int.from_bytes(nh,'little')%q; Renc=pt_enc(emul(r,G))
    ch=shake(D,Renc,Aenc,M); k=int.from_bytes(ch,'little')%q; S=(r+k*s)%q
    return dict(domain=D,expanded_hash=h,pruned_secret_scalar=lo,prefix=prefix,public_key=Aenc,nonce_hash=nh,nonce_scalar=r.to_bytes(38,'little'),commitment=Renc,challenge_hash=ch,challenge_scalar=k.to_bytes(38,'little'),response=S.to_bytes(38,'little'),signature=Renc+S.to_bytes(38,'little'))
def verify(Aenc,M,sig,C=b""):
    try:
        if len(sig)!=76: return False
        D=dom(C); Ap=pt_dec(Aenc)
        if Ap==(0,1) or emul(q,Ap)!=(0,1): return False
        Rp=pt_dec(sig[:38]); S=sc_dec(sig[38:])
    except ValueError: return False
    k=int.from_bytes(shake(D,sig[:38],Aenc,M),'little')%q
    return emul(4*S,G)==eadd(emul(4,Rp),emul(4*k,Ap))
# ---- Ed301 vectors
V=json.load(open(f'{R}/vectors/ed301-eddsa-v2.json')); bad=[]
for c in V['signing']:
    t=sign(bytes.fromhex(c['seed_hex']),bytes.fromhex(c['message_hex']),bytes.fromhex(c['context_hex']))
    for k,v in c['trace'].items():
        key=k[:-4] if k.endswith('_hex') else k
        if key in t and t[key].hex()!=v: bad.append(('signing',c['id'],k))
    # also verify own signature
    if not verify(t['public_key'],bytes.fromhex(c['message_hex']),t['signature'],bytes.fromhex(c['context_hex'])): bad.append(('selfverify',c['id']))
print("signing cases:",len(V['signing']),"trace keys compared per case:",len(V['signing'][0]['trace']),"mismatches:",bad)
nv=0
for c in V['verification']:
    got=verify(bytes.fromhex(c['public_key_hex']),bytes.fromhex(c['message_hex']),bytes.fromhex(c['signature_hex']),bytes.fromhex(c['context_hex']))
    if got!=c['accepted']: bad.append(('verify',c['id'],got)); 
    nv+=1
print("verification cases:",nv,"mismatches so far:",len(bad))
for c in V['point_decoding']:
    try: pt_dec(bytes.fromhex(c['encoded_hex'])); got=True
    except ValueError: got=False
    if got!=c['accepted']: bad.append(('pointdec',c['id']))
for c in V['scalar_decoding']:
    try: sc_dec(bytes.fromhex(c['encoded_hex'])); got=True
    except ValueError: got=False
    if got!=c['accepted']: bad.append(('scalardec',c['id']))
for c in V['signing_errors']:
    try: sign(bytes.fromhex(c['seed_hex']),bytes.fromhex(c['message_hex']),bytes.fromhex(c['context_hex'])); bad.append(('signerr-accepted',c['id']))
    except ValueError: pass
for c in V['domain_controls']:
    pass
print("Ed301 total mismatches:",bad)
# v1 fixtures must be rejected by my v2 verifier
V1=json.load(open(f'{R}/tests/fixtures/v1/ed301-eddsa-v1.json'))
def walk(o):
    if isinstance(o,dict):
        if 'signature_hex' in o and 'public_key_hex' in o: yield o
        for v in o.values(): yield from walk(v)
    elif isinstance(o,list):
        for v in o: yield from walk(v)
n1=0; acc=0
for f in walk(V1):
    n1+=1
    if verify(bytes.fromhex(f['public_key_hex']),bytes.fromhex(f.get('message_hex','')),bytes.fromhex(f['signature_hex']),bytes.fromhex(f.get('context_hex',''))): acc+=1
print("v1 fixtures seen:",n1,"accepted by v2 verifier (must be 0):",acc)
# ---- X301 via affine Montgomery/twist arithmetic (different method from the ladder)
def mont_mul(k,u,Bc):
    # affine chord-tangent on Bc*v^2 = u^3+A u^2+u ; returns u-coordinate of [k]P or None for infinity
    rhs=(u*u*u+A*u*u+u)%p
    v2=rhs*inv(Bc)%p; v=pow(v2,(p+1)//4,p); assert v*v%p==v2
    P=(u,v); Rr=None
    def add(P1,P2):
        if P1 is None: return P2
        if P2 is None: return P1
        u1,v1=P1; u2,v2_=P2
        if u1==u2:
            if (v1+v2_)%p==0: return None
            lam=(3*u1*u1+2*A*u1+1)*inv(2*Bc*v1)%p
        else: lam=(v2_-v1)*inv(u2-u1)%p
        u3=(Bc*lam*lam-A-u1-u2)%p; v3=(lam*(u1-u3)-v1)%p; return (u3,v3)
    Q_=P
    while k:
        if k&1: Rr=add(Rr,Q_)
        Q_=add(Q_,Q_); k>>=1
    return None if Rr is None else Rr[0]
def leg(z): return pow(z%p,(p-1)//2,p)
def x301(secret,ub):
    u=fe_dec(ub)
    if len(secret)!=38: raise ValueError
    c=bytearray(secret); c[0]&=0xfc; c[37]=(c[37]&0x0f)|0x10; c=bytes(c)
    if c==Nt.to_bytes(38,'little'): raise ValueError('weak')
    k=int.from_bytes(c,'little')
    rhs=(u*u*u+A*u*u+u)%p
    Bc = B if (rhs==0 or leg(rhs*inv(B))==1) else 2*B%p   # curve or z=2 twist
    r=mont_mul(k,u,Bc)
    if r is None or r==0: raise ValueError('zero')
    return fe_enc(r)
X=json.load(open(f'{R}/vectors/x301-v2.json')); xb=[]
Ub=bytes.fromhex(par['basepoint']['G_montgomery_u_little_endian_hex'])
keys={}
for c in X['keys']:
    s=bytes.fromhex(c['secret_hex']); cl=bytearray(s); cl[0]&=0xfc; cl[37]=(cl[37]&0x0f)|0x10
    if bytes(cl).hex()!=c['clamped_hex']: xb.append(('clamp',c['id']))
    pub=x301(s,Ub)
    if pub.hex()!=c['public_hex']: xb.append(('public',c['id']))
    keys[c['id']]=(s,pub)
for c in X['dh']:
    sa,pa=keys[c['a']]; sb,pb=keys[c['b']]
    if x301(sa,pb).hex()!=c['shared_hex'] or x301(sb,pa).hex()!=c['shared_hex']: xb.append(('dh',c['id']))
for c in X['evaluations']:
    s,_=keys[c['key']]
    if x301(s,bytes.fromhex(c['u_hex'])).hex()!=c['result_hex']: xb.append(('eval',c['id'],c['classification']))
for c in X['errors']:
    try: x301(bytes.fromhex(c['secret_hex']),bytes.fromhex(c['u_hex'])); xb.append(('error-accepted',c['id'],c['stage']))
    except ValueError: pass
for c in X['weak_secrets']:
    try: x301(bytes.fromhex(c['secret_hex']),Ub); xb.append(('weak-accepted',c['id']))
    except ValueError as e:
        if str(e)!='weak': xb.append(('weak-wrongstage',c['id']))
print("X301 keys/dh/evals/errors/weak checked:",len(X['keys']),len(X['dh']),len(X['evaluations']),len(X['errors']),len(X['weak_secrets']),"mismatches:",xb)
print("iteration rule:",X['iteration']['rule']); print("checkpoints keys:",[c if not isinstance(c,dict) else list(c.keys()) for c in X['iteration']['checkpoints']][:1])
sys.stdout.flush()
# iteration chain with my affine implementation
cps={c['count']:c for c in X['iteration']['checkpoints']}
k=Ub; u=Ub; ok=True
for i in range(1,1001):
    k,u = x301(k,u), k
    if i in cps and (k.hex()!=cps[i]['k_hex'] or u.hex()!=cps[i]['u_hex']): ok=False; print("iteration mismatch at",i)
print("iteration checkpoints",sorted(cps),"match:",ok)
