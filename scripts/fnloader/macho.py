#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fnloader/macho.py — محلل Mach-O 64 + مفسك أوامر ربط dyld"""
import struct

LC_SEGMENT_64=0x19; LC_SYMTAB=0x2; LC_DYSYMTAB=0xB; LC_LOAD_DYLIB=0xC
LC_MAIN=0x80000028; LC_UNIXTHREAD=0x5; LC_ENCRYPTION_INFO_64=0x2C
LC_BUILD_VERSION=0x32; LC_UUID=0x1B
LC_DYLD_INFO=0x22; LC_DYLD_INFO_ONLY=0x80000022

class Segment:
    def __init__(s,name,vmaddr,vmsize,fileoff,filesize,initprot,maxprot):
        s.name=name; s.vmaddr=vmaddr; s.vmsize=vmsize; s.fileoff=fileoff
        s.filesize=filesize; s.initprot=initprot; s.maxprot=maxprot

class Section:
    def __init__(s,name,seg,addr,size,offset,flags,res1,res2):
        s.name=name; s.seg=seg; s.addr=addr; s.size=size; s.offset=offset
        s.flags=flags; s.res1=res1; s.res2=res2

class MachO:
    def __init__(s, path):
        s.data=open(path,"rb").read(); d=s.data
        magic,cputype,cpusub,ftype,ncmds,szcmds,flags,res=struct.unpack_from("<IiiIIIII",d,0)
        if magic!=0xFEEDFACF: raise ValueError("ليس Mach-O 64 LE")
        s.cputype=cputype; s.filetype=ftype
        s.segments=[]; s.sections={}; s.dylibs=[]
        s.entry_main=None; s.entry_thread=None; s.encryption=None; s.dyld_info=None
        s.indirectsymoff=s.nindirectsyms=0
        s.symoff=s.nsyms=s.stroff=s.strsize=0
        off=32
        for _ in range(ncmds):
            cmd,cmdsize=struct.unpack_from("<II",d,off)
            if cmd==LC_SEGMENT_64:
                segname=d[off+8:off+24].rstrip(b"\0").decode()
                vmaddr,vmsize,fileoff,filesize=struct.unpack_from("<QQQQ",d,off+24)
                maxprot,initprot,nsects,_fl=struct.unpack_from("<IIII",d,off+56)
                s.segments.append(Segment(segname,vmaddr,vmsize,fileoff,filesize,initprot,maxprot))
                so=off+72
                for _s in range(nsects):
                    sname=d[so:so+16].rstrip(b"\0").decode("utf-8","replace")
                    sseg=d[so+16:so+32].rstrip(b"\0").decode("utf-8","replace")
                    saddr,ssize=struct.unpack_from("<QQ",d,so+32)
                    soffset,_al,_ro,_nr=struct.unpack_from("<IIII",d,so+48)
                    sflags,sres1,sres2=struct.unpack_from("<III",d,so+64)
                    s.sections[sname]=Section(sname,sseg,saddr,ssize,soffset,sflags,sres1,sres2)
                    so+=80
            elif cmd==LC_SYMTAB:
                s.symoff,s.nsyms,s.stroff,s.strsize=struct.unpack_from("<IIII",d,off+8)
            elif cmd==LC_DYSYMTAB:
                v=struct.unpack_from("<18I",d,off+8)
                s.indirectsymoff,s.nindirectsyms=v[12],v[13]
            elif cmd==LC_LOAD_DYLIB:
                doff=struct.unpack_from("<I",d,off+8)[0]
                end=d.index(b"\0",off+doff)
                s.dylibs.append(d[off+doff:end].decode())
            elif cmd==LC_MAIN:
                s.entry_main=struct.unpack_from("<Q",d,off+8)[0]
            elif cmd==LC_UNIXTHREAD:
                fl,_c=struct.unpack_from("<II",d,off+8)
                if fl==6: s.entry_thread=struct.unpack_from("<Q",d,off+16+256)[0]
            elif cmd==LC_ENCRYPTION_INFO_64:
                s.encryption=struct.unpack_from("<III",d,off+8)
            elif cmd in (LC_DYLD_INFO,LC_DYLD_INFO_ONLY):
                s.dyld_info=struct.unpack_from("<12I",d,off+8)
            off+=cmdsize
        t=s.seg("__TEXT"); s.text_vm=t.vmaddr if t else 0x100000000
        s.entry=s.text_vm+s.entry_main if s.entry_main is not None else s.entry_thread
        s.symtab=[]
        for i in range(s.nsyms or 0):
            o=s.symoff+i*16
            strx,typ,sect,desc,val=struct.unpack_from("<IBBHQ",d,o)
            e=d.index(b"\0",s.stroff+strx)
            s.symtab.append((d[s.stroff+strx:e].decode("utf-8","replace"),typ,val))
        s.bind_records=[]
        if s.dyld_info:
            for o,sz in ((s.dyld_info[2],s.dyld_info[3]),
                         (s.dyld_info[6],s.dyld_info[7]),
                         (s.dyld_info[8],s.dyld_info[9])):
                if o and sz: s.bind_records+=s.parse_bind(o,sz)
        # الجدول غير المباشر الكامل (للربط الاحتياطي الشامل)
        s.indirect=[]
        for i in range(s.nindirectsyms or 0):
            (v,)=struct.unpack_from("<I",s.data,s.indirectsymoff+i*4)
            s.indirect.append(v)

    def seg(s,name):
        for g in s.segments:
            if g.name==name: return g
        return None

    def vm2off(s,addr):
        for g in s.segments:
            if g.vmaddr<=addr<g.vmaddr+g.filesize:
                return g.fileoff+addr-g.vmaddr
        return None

    def read_u64(s,addr):
        o=s.vm2off(addr)
        return struct.unpack("<Q",s.data[o:o+8])[0] if o is not None else None

    def read_cstr(s,addr,maxlen=1024):
        o=s.vm2off(addr)
        if o is None: return None
        e=s.data.find(b"\0",o,min(o+maxlen,len(s.data)))
        if e<0: return None
        return s.data[o:e].decode("utf-8","replace")

    def parse_bind(s,off,size):
        """مفسك أوامر ربط dyld → [(عنوان، رمز، إضافة)]"""
        d=s.data; recs=[]
        seg_index=0; seg_offset=0; name=None; addend=0; i=off; end=off+size
        def uleb():
            nonlocal i
            r=0; sh=0
            while True:
                b=d[i]; i+=1; r|=(b&0x7F)<<sh; sh+=7
                if not b&0x80: return r
        def sleb():
            nonlocal i
            r=0; sh=0
            while True:
                b=d[i]; i+=1; r|=(b&0x7F)<<sh; sh+=7
                if not b&0x80:
                    if b&0x40: r-=1<<sh
                    return r
        def do_bind():
            nonlocal seg_offset
            if name and seg_index<len(s.segments):
                recs.append((s.segments[seg_index].vmaddr+seg_offset,name,addend))
            seg_offset+=8
        while i<end:
            op=d[i]; i+=1; imm=op&0x0F; oc=op&0xF0
            if oc==0x00: break
            elif oc==0x10: pass
            elif oc==0x20: uleb()
            elif oc==0x30: pass
            elif oc==0x40:
                e=d.index(b"\0",i); name=d[i:e].decode("utf-8","replace"); i=e+1
            elif oc==0x50: pass
            elif oc==0x60: addend=sleb()
            elif oc==0x70: seg_index=imm; seg_offset=uleb()
            elif oc==0x80: seg_offset+=uleb()
            elif oc==0x90: do_bind()
            elif oc==0xA0: do_bind(); seg_offset+=uleb()
            elif oc==0xB0: do_bind(); seg_offset+=imm*8
            elif oc==0xC0:
                n=uleb(); skip=uleb()
                for _ in range(n):
                    do_bind(); seg_offset+=skip
        return recs
