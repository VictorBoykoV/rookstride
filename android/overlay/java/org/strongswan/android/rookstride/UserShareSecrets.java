package org.strongswan.android.rookstride;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/** Bounded, memory-only credentials for accounts created/shared during this screen session. */
public final class UserShareSecrets {
    private static final int LIMIT=32;
    private final LinkedHashMap<Key,char[]> values=new LinkedHashMap<>(16,0.75f,true);
    private static final class Key {
        final String node,instance,login;
        Key(String node,String instance,String login){this.node=node;this.instance=instance;this.login=login;}
        @Override public boolean equals(Object other){if(!(other instanceof Key))return false;Key k=(Key)other;return node.equals(k.node)&&instance.equals(k.instance)&&login.equals(k.login);}
        @Override public int hashCode(){return java.util.Objects.hash(node,instance,login);}
    }
    public synchronized void remember(String node,String instance,String login,String password){
        if(node==null||node.isEmpty()||instance==null||instance.isEmpty()||!InputRules.username(login)||!InputRules.vpnPassword(password))return;
        char[] previous=values.put(new Key(node,instance,login),password.toCharArray());if(previous!=null)Arrays.fill(previous,'\0');
        while(values.size()>LIMIT){Iterator<char[]> it=values.values().iterator();Arrays.fill(it.next(),'\0');it.remove();}
    }
    public synchronized String get(String node,String instance,String login){
        if(node==null||instance==null||login==null)return "";
        char[] value=values.get(new Key(node,instance,login));return value==null?"":new String(value);
    }
    public synchronized void forget(String node){
        Iterator<Map.Entry<Key,char[]>> it=values.entrySet().iterator();
        while(it.hasNext()){Map.Entry<Key,char[]> entry=it.next();if(entry.getKey().node.equals(node)){Arrays.fill(entry.getValue(),'\0');it.remove();}}
    }
    public synchronized void forget(String node,String instance,String login){
        char[] value=values.remove(new Key(node,instance,login));if(value!=null)Arrays.fill(value,'\0');
    }
    public synchronized void clear(){for(char[] value:values.values())Arrays.fill(value,'\0');values.clear();}
}
