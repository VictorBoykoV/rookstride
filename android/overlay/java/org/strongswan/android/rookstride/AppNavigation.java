package org.strongswan.android.rookstride;

import java.util.ArrayList;
import java.util.Arrays;

/** UI destinations only. Server jobs and credentials never belong in this stack. */
public final class AppNavigation {
    private static final java.util.List<String> ROUTES=Arrays.asList("Home","Servers","Add","Setup","Import","Protocols","VPN","Settings","PairServer","ServerSettings","AppSettings","Activity","Routing","People","Sessions","Guide","Stories","Progress","FAQ","Administrators");
    private final ArrayList<String> history=new ArrayList<>();
    private static final java.util.List<String> MAIN=Arrays.asList("Home","Servers","Routing","Stories","AppSettings");
    private String current="Home";
    public String current(){return current;}
    public void go(String route){if(!ROUTES.contains(route))throw new IllegalArgumentException("Unknown screen");if(!current.equals(route)){history.add(current);current=route;}}
    public void root(String route){if(!MAIN.contains(route))throw new IllegalArgumentException("Not a main destination");history.clear();if(!route.equals("Home"))history.add("Home");current=route;}
    public boolean back(){if(history.isEmpty())return false;current=history.remove(history.size()-1);return true;}
    public void ancestor(String route){if(!ROUTES.contains(route))throw new IllegalArgumentException("Unknown screen");if(current.equals(route))return;int index=history.lastIndexOf(route);if(index<0){history.clear();if(!route.equals("Home"))history.add("Home");current=route;return;}while(history.size()>index)history.remove(history.size()-1);current=route;}
    public void main(String route){if(!MAIN.contains(route))throw new IllegalArgumentException("Not a main destination");if(route.equals("Home"))root(route);else go(route);}
    public String mainDestination(){if(MAIN.contains(current))return current;for(int i=history.size()-1;i>=0;i--)if(MAIN.contains(history.get(i)))return history.get(i);return "Home";}
    public ArrayList<String> saved(){ArrayList<String> value=new ArrayList<>(history);value.add(current);return value;}
    public void restore(ArrayList<String> value){history.clear();current="Home";if(value==null||value.isEmpty())return;for(String route:value)if(!ROUTES.contains(route))return;history.addAll(value);current=history.remove(history.size()-1);}
    public static boolean serverOnly(String route){return Arrays.asList("Settings","PairServer","ServerSettings","Administrators","People","Sessions").contains(route);}
}
