package org.strongswan.android.rookstride;

import java.util.*;

/** Phone-local server order; all protocol records of the moved server travel together. */
public final class ServerOrder {
    private ServerOrder(){}
    private static boolean belongs(Gateway server,Gateway node){return server.get("id").equals(node.get("id"))||ServerProtocols.sameServer(server,node);}
    public static boolean move(ArrayList<Gateway> nodes,Gateway moved,Gateway target,boolean after){
        if(belongs(moved,target))return false;
        ArrayList<Gateway> block=new ArrayList<>();for(Gateway node:nodes)if(belongs(moved,node))block.add(node);
        if(block.isEmpty())return false;
        boolean found=false;for(Gateway node:nodes)if(belongs(target,node))found=true;if(!found)return false;
        ArrayList<Gateway> reordered=new ArrayList<>(nodes);reordered.removeAll(block);int index=-1;
        for(int i=0;i<reordered.size();i++)if(belongs(target,reordered.get(i))){if(index<0||after)index=i+(after?1:0);}
        reordered.addAll(index,block);if(reordered.equals(nodes))return false;nodes.clear();nodes.addAll(reordered);return true;
    }
}
