from __future__ import annotations

def canonical_device_type(value: str) -> str:
    v=(value or "").strip().casefold().replace("_"," ").replace("-"," ")
    rules=(
        (("domain controller","active directory"," dc"),"server"),
        (("engineering workstation","workstation","desktop","endpoint","client"," pc"),"pc"),
        (("laptop","notebook"),"laptop"),
        (("firewall","utm"),"firewall"),
        (("router","gateway"),"router"),
        (("switch",),"switch"),
        (("access point","wifi","wireless"),"access_point"),
        (("vpn",),"vpn"),
        (("database","sql","historian"),"database"),
        (("storage","nas","san"),"storage"),
        (("server","scada","hmi server","webserver"),"server"),
        (("printer",),"printer"),
        (("camera","cctv"),"camera"),
        (("plc",),"plc"),
        (("rtu",),"rtu"),
        (("hmi",),"hmi"),
        (("sensor",),"sensor"),
        (("iot",),"iot"),
        (("cloud","internet"),"cloud"),
    )
    for terms,result in rules:
        if any(term in f" {v}" for term in terms): return result
    return "device"

def draw_device_icon(canvas,x,y,device_type,*,outline,fill,accent,tag=(),scale=1.0):
    """Draw recognizable network/OT equipment using Tk vector primitives."""
    kind=canonical_device_type(device_type)
    tags=tag if isinstance(tag,tuple) else (tag,)
    # Permit real Mini/Auto rendering. Previous 0.65 floor made .28/.30/.42
    # requests render at exactly the same 0.65 size.
    s=max(.20,min(1.5,float(scale)))
    def rect(x1,y1,x2,y2,**kw): return canvas.create_rectangle(x+x1*s,y+y1*s,x+x2*s,y+y2*s,tags=tags,**kw)
    def line(*pts,**kw): return canvas.create_line(*[v for pair in zip(pts[::2],pts[1::2]) for v in (x+pair[0]*s,y+pair[1]*s)],tags=tags,**kw)
    def oval(x1,y1,x2,y2,**kw): return canvas.create_oval(x+x1*s,y+y1*s,x+x2*s,y+y2*s,tags=tags,**kw)
    def text(dx,dy,value,size=7):
        # Internal icon text would dominate very small symbols; hide it in Mini.
        if s < .38: return None
        return canvas.create_text(x+dx*s,y+dy*s,text=value,fill=accent,font=("Segoe UI Semibold",max(5,int(size*s))),tags=tags)
    if kind in {"pc","hmi"}:
        rect(-22,-18,22,10,fill=fill,outline=outline,width=2); rect(-4,10,4,17,fill=outline,outline=outline); line(-13,18,13,18,fill=outline,width=3)
        if kind=="hmi": text(0,-4,"HMI",7)
    elif kind=="laptop":
        rect(-21,-18,21,8,fill=fill,outline=outline,width=2); canvas.create_polygon(x-27*s,y+12*s,x+27*s,y+12*s,x+20*s,y+18*s,x-20*s,y+18*s,fill=fill,outline=outline,tags=tags)
    elif kind in {"server","database","storage"}:
        for yy in (-19,-6,7): rect(-18,yy,18,yy+10,fill=fill,outline=outline,width=1); oval(10,yy+3,14,yy+7,fill=accent,outline="")
        if kind=="database": text(0,-1,"DB",7)
        elif kind=="storage": text(0,-1,"NAS",6)
    elif kind=="firewall":
        for row,yy in enumerate((-18,-7,4)):
            offset=-22 if row%2==0 else -15
            for xx in range(offset,22,14): rect(xx,yy,min(xx+13,22),yy+10,fill=fill,outline=outline,width=1)
    elif kind=="router":
        oval(-23,-12,23,12,fill=fill,outline=outline,width=2); text(0,0,"↔",11)
    elif kind=="switch":
        rect(-25,-12,25,12,fill=fill,outline=outline,width=2)
        for xx in (-17,-7,3,13): rect(xx,-4,xx+6,2,fill=accent,outline="")
    elif kind=="access_point":
        oval(-5,-5,5,5,fill=accent,outline=""); canvas.create_arc(x-18*s,y-18*s,x+18*s,y+18*s,start=30,extent=120,style="arc",outline=outline,width=2,tags=tags); canvas.create_arc(x-27*s,y-27*s,x+27*s,y+27*s,start=35,extent=110,style="arc",outline=outline,width=2,tags=tags)
    elif kind=="vpn":
        rect(-18,-4,18,17,fill=fill,outline=outline,width=2); canvas.create_arc(x-13*s,y-22*s,x+13*s,y+6*s,start=0,extent=180,style="arc",outline=outline,width=3,tags=tags); text(0,7,"VPN",6)
    elif kind in {"plc","rtu","iot"}:
        rect(-19,-20,19,20,fill=fill,outline=outline,width=2); text(0,-3,kind.upper(),7)
        for yy in (9,14): oval(-12,yy,-8,yy+4,fill=accent,outline=""); oval(-3,yy,1,yy+4,fill=accent,outline=""); oval(6,yy,10,yy+4,fill=accent,outline="")
    elif kind=="printer":
        rect(-18,-20,18,-7,fill=fill,outline=outline,width=2); rect(-24,-7,24,13,fill=fill,outline=outline,width=2); rect(-15,8,15,21,fill=fill,outline=outline,width=1)
    elif kind=="camera":
        rect(-20,-12,13,10,fill=fill,outline=outline,width=2); oval(2,-7,11,4,fill=accent,outline=outline); line(13,-4,24,-11,24,8,13,3,fill=outline,width=2)
    elif kind=="sensor":
        oval(-7,-7,7,7,fill=accent,outline=outline); canvas.create_arc(x-18*s,y-18*s,x+18*s,y+18*s,start=-45,extent=90,style="arc",outline=outline,width=2,tags=tags); canvas.create_arc(x-27*s,y-27*s,x+27*s,y+27*s,start=-40,extent=80,style="arc",outline=outline,width=2,tags=tags)
    elif kind=="cloud":
        for dx,dy,r in ((-13,3,11),(0,-5,15),(14,3,10)): oval(dx-r,dy-r,dx+r,dy+r,fill=fill,outline=outline,width=1)
    else:
        rect(-20,-17,20,17,fill=fill,outline=outline,width=2); text(0,0,"DEV",7)
    return kind
