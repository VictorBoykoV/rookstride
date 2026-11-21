package org.strongswan.android.rookstride;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
public class AppRoutingTest {
 @Test public void onlyCannotSilentlyBecomeAll(){try{new AppRouting.Policy("only",Collections.emptyList());fail();}catch(IllegalArgumentException expected){}try{new AppRouting.Policy("invalid",Collections.emptyList());fail();}catch(IllegalArgumentException expected){}}
 @Test public void preservesDistinctAppsAndRejectsMalformedIdentifiers(){AppRouting.Policy p=new AppRouting.Policy("exclude",Arrays.asList("com.example.one","com.example.one","org.example.two"));assertEquals(2,p.packages.size());for(String s:Arrays.asList("../secret","a b","com;evil"))try{new AppRouting.Policy("only",Arrays.asList(s));fail();}catch(IllegalArgumentException expected){}}
}
