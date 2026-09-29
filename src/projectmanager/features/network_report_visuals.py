from __future__ import annotations
from pathlib import Path
from collections import defaultdict
import math
from PIL import Image, ImageDraw, ImageFont

W,H=1600,900
BG="#f3f6f9"; INK="#172536"; MUTED="#617083"; NAVY="#17365d"; BLUE="#245b88"
GREEN="#2f855a"; ORANGE="#c47a20"; RED="#b63d3d"; LINE="#b8c7d5"; CYAN="#2a8fa3"

def _font(size=20,bold=False):
    candidates=[
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
    for p in candidates:
        try:return ImageFont.truetype(p,size)
        except Exception:pass
    return ImageFont.load_default()

def _v(a,n,d=None): return a.get(n,d) if isinstance(a,dict) else getattr(a,n,d)
def _id(a): return str(_v(a,"asset_id","") or _v(a,"id",""))
def _name(a): return str(_v(a,"name","") or _v(a,"hostname","") or _v(a,"ip","") or _id(a))
def _risk(a): return int(_v(a,"risk_score",0) or 0)
def _services(a): return list(_v(a,"services",[]) or [])
def _vulns(a): return list(_v(a,"vulnerabilities",[]) or [])
def _exposures(a): return list(_v(a,"exposures",[]) or [])
def _gateway(a): return bool(_v(a,"is_gateway",False)) or any(x in str(_v(a,"role","")).lower() for x in ("gateway","router","firewall"))
def _online(a): return str(_v(a,"online_status","") or "").lower()=="online"

def _header(title,subtitle):
    im=Image.new("RGB",(W,H),BG); d=ImageDraw.Draw(im)
    d.rectangle((0,0,W,115),fill=NAVY); d.rectangle((0,108,W,115),fill=CYAN)
    d.text((55,28),title,fill="white",font=_font(34,True))
    d.text((57,73),subtitle,fill="#d9edf4",font=_font(18))
    return im,d

def _positions(assets):
    assets=list(assets); n=max(1,len(assets))
    cx,cy=W//2,H//2+45
    if n<=20:
        radius=min(330,120+20*n)
        return {_id(a):(cx+int(math.cos(2*math.pi*i/n)*radius),cy+int(math.sin(2*math.pi*i/n)*radius)) for i,a in enumerate(assets)}
    cols=math.ceil(math.sqrt(n*1.7)); gapx=(W-180)/max(1,cols-1); rows=math.ceil(n/cols); gapy=(H-250)/max(1,rows-1)
    return {_id(a):(90+int((i%cols)*gapx),180+int((i//cols)*gapy)) for i,a in enumerate(assets)}

def _edge_ids(r):
    return (str(_v(r,"source_asset_id","") or _v(r,"source","")),str(_v(r,"target_asset_id","") or _v(r,"target","")))

def _node(d,a,x,y,mode="topology"):
    risk=_risk(a); vul=len(_vulns(a)); exp=len(_exposures(a))
    if mode=="risk": fill=RED if risk>=70 else ORANGE if risk>=40 else GREEN
    elif mode=="cve": fill=RED if vul else "#9aa8b5"
    elif mode=="exposure": fill=ORANGE if exp else "#9aa8b5"
    elif mode=="entry": fill=RED if _gateway(a) else "#9aa8b5"
    else: fill=GREEN if _online(a) else ORANGE
    r=34 if _gateway(a) else 27
    d.ellipse((x-r,y-r,x+r,y+r),fill=fill,outline="white",width=4)
    if _gateway(a): d.ellipse((x-r-5,y-r-5,x+r+5,y+r+5),outline=NAVY,width=3)
    label=_name(a)[:22]; ip=str(_v(a,"ip","") or "")
    d.text((x-d.textlength(label,font=_font(16,True))/2,y+r+8),label,fill=INK,font=_font(16,True))
    if ip:d.text((x-d.textlength(ip,font=_font(14))/2,y+r+29),ip,fill=MUTED,font=_font(14))
    if mode=="risk": d.text((x-12,y-10),str(risk),fill="white",font=_font(15,True))
    elif mode=="cve" and vul:d.text((x-7,y-10),str(vul),fill="white",font=_font(15,True))
    elif mode=="exposure" and exp:d.text((x-7,y-10),str(exp),fill="white",font=_font(15,True))

def network_map(path,assets,rels,title,subtitle,mode="topology"):
    im,d=_header(title,subtitle); pos=_positions(assets)
    for r in rels:
        s,t=_edge_ids(r)
        if s in pos and t in pos:d.line((*pos[s],*pos[t]),fill=LINE,width=3)
    for a in assets:
        if _id(a) in pos:_node(d,a,*pos[_id(a)],mode)
    im.save(path)

def exposure_summary(path,assets):
    im,d=_header("Service Exposure Overview","Geobserveerde blootstelling per service/poort")
    counts=defaultdict(int)
    for a in assets:
        for e in _exposures(a):
            key=f"{_v(e,'port','?')}/{_v(e,'protocol','tcp')} {_v(e,'title','exposure')}"
            counts[key]+=1
    rows=sorted(counts.items(),key=lambda x:(-x[1],x[0]))[:12]
    if not rows:
        d.text((80,190),"Geen service-exposure findings in dit analysis snapshot.",fill=MUTED,font=_font(28))
    else:
        maxv=max(v for _,v in rows)
        for i,(label,val) in enumerate(rows):
            y=175+i*52; bw=int(1050*val/maxv)
            d.text((70,y),label[:48],fill=INK,font=_font(18))
            d.rounded_rectangle((470,y,470+bw,y+28),radius=8,fill=ORANGE)
            d.text((485+bw,y+2),str(val),fill=INK,font=_font(18,True))
    im.save(path)

def kpi_overview(path,assets):
    im,d=_header("Risk / Coverage Overview","Managementoverzicht van hetzelfde Network Asset Intelligence snapshot")
    vals=[
        ("Assets",len(assets)),("Online",sum(_online(a) for a in assets)),
        ("Gateways",sum(_gateway(a) for a in assets)),("Services",sum(len(_services(a)) for a in assets)),
        ("CVE candidates",sum(len(_vulns(a)) for a in assets)),("Exposures",sum(len(_exposures(a)) for a in assets)),
        ("High risk",sum(_risk(a)>=70 for a in assets))]
    for i,(label,val) in enumerate(vals):
        col=i%3; row=i//3; x=85+col*500; y=185+row*190
        d.rounded_rectangle((x,y,x+430,y+140),radius=18,fill="white",outline="#d7e2ec",width=2)
        d.text((x+25,y+22),label,fill=MUTED,font=_font(22,True))
        d.text((x+25,y+62),str(val),fill=NAVY,font=_font(46,True))
    im.save(path)

def generate_network_asset_report_visuals(output_dir,assets,relationships):
    output_dir=Path(output_dir);output_dir.mkdir(parents=True,exist_ok=True)
    assets=list(assets);relationships=list(relationships)
    specs=[
        ("01_network_topology.png",network_map,(assets,relationships,"Network Topology","Actuele canonieke NetMap-topologie","topology")),
        ("02_risk_network_map.png",network_map,(assets,relationships,"Risk Network Map","Risicoscore per asset: groen <40, oranje 40–69, rood ≥70","risk")),
        ("03_service_exposure_map.png",network_map,(assets,relationships,"Service Exposure Map","Oranje nodes bevatten exposure findings","exposure")),
        ("04_cve_candidate_map.png",network_map,(assets,relationships,"CVE Candidate Map","Rode nodes bevatten één of meer CVE-kandidaten","cve")),
        ("05_entry_points.png",network_map,(assets,relationships,"Entry Points / Gateways","Gateways, routers en firewalls als potentiële netwerk-entry points","entry")),
    ]
    result=[]
    for name,fn,args in specs:
        p=output_dir/name;fn(p,*args);result.append(p)
    p=output_dir/"06_service_exposure_overview.png";exposure_summary(p,assets);result.append(p)
    p=output_dir/"07_risk_coverage_overview.png";kpi_overview(p,assets);result.append(p)
    return result
