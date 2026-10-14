#!/usr/bin/env python3
"""Convert our small, code-native SVG helper set to Android VectorDrawables.
Unsupported SVG features fail the build rather than silently dropping artwork.
"""
from pathlib import Path
from xml.etree import ElementTree as E
import re
ROOT=Path(__file__).resolve().parents[1]
A='http://schemas.android.com/apk/res/android';E.register_namespace('android',A)
def attr(key):return '{'+A+'}'+key

def convert(source,target):
    svg=E.parse(source).getroot();x,y,w,h=map(float,svg.attrib['viewBox'].split())
    if x or y:raise ValueError('Nonzero origin')
    vector=E.Element('vector',{attr('width'):f'{int(w)}dp',attr('height'):f'{int(h)}dp',attr('viewportWidth'):str(w),attr('viewportHeight'):str(h)})
    def walk(node,parent,inherited):
        tag=node.tag.rsplit('}',1)[-1];a=dict(inherited);a.update(node.attrib)
        if tag in ('title','desc'):return
        if tag in ('g','svg'):
            into=parent
            if tag=='g':
                group={}
                if 'transform' in node.attrib:
                    match=re.fullmatch(r'translate\(([-\d.]+)[ ,]+([-\d.]+)\)',node.attrib['transform'])
                    if not match:raise ValueError('Unsupported transform')
                    group={attr('translateX'):match[1],attr('translateY'):match[2]}
                into=E.SubElement(parent,'group',group)
            for child in node:walk(child,into,a)
            return
        if tag=='path':d=a['d']
        elif tag in ('circle','ellipse'):
            cx,cy=float(a['cx']),float(a['cy']);rx=float(a.get('rx',a.get('r',0)));ry=float(a.get('ry',a.get('r',0)))
            d=f'M {cx-rx} {cy} A {rx} {ry} 0 1 0 {cx+rx} {cy} A {rx} {ry} 0 1 0 {cx-rx} {cy} Z'
        elif tag=='rect':
            x,y,w,h=map(float,(a['x'],a['y'],a['width'],a['height']));rx=float(a.get('rx','0'));ry=float(a.get('ry',str(rx)))
            d=f'M{x+rx} {y} H{x+w-rx} Q{x+w} {y} {x+w} {y+ry} V{y+h-ry} Q{x+w} {y+h} {x+w-rx} {y+h} H{x+rx} Q{x} {y+h} {x} {y+h-ry} V{y+ry} Q{x} {y} {x+rx} {y} Z'
        else:raise ValueError('Unsupported element '+tag)
        out={attr('pathData'):d,attr('fillColor'):a.get('fill','#000000').replace('none','#00000000')}
        if a.get('stroke','none')!='none':out.update({attr('strokeColor'):a['stroke'],attr('strokeWidth'):a.get('stroke-width','1'),attr('strokeLineCap'):a.get('stroke-linecap','butt'),attr('strokeLineJoin'):a.get('stroke-linejoin','miter')})
        if a.get('opacity'):out.update({attr('fillAlpha'):a['opacity'],attr('strokeAlpha'):a['opacity']})
        E.SubElement(parent,'path',out)
    walk(svg,vector,{})
    target.write_text('<?xml version="1.0" encoding="utf-8"?>\n<!-- Original Rookstride helper; GPL-3.0-or-later. Generated from '+source.relative_to(ROOT).as_posix()+'. -->\n'+E.tostring(vector,encoding='unicode')+'\n')

if __name__=='__main__':
    for source in (ROOT/'website/brand/poses').glob('rook-*.svg'):convert(source,ROOT/'android/overlay/res/drawable'/source.name.replace('-','_').replace('.svg','.xml'))
    print('Prepared six original Rook helper drawables')
