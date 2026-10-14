package org.strongswan.android.rookstride;

import android.content.Context;
import android.content.res.Configuration;
import android.os.Build;
import android.app.LocaleManager;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.os.LocaleListCompat;
import org.strongswan.android.R;
import java.util.Locale;

/** Presentation only: never changes server requests, typed values or persisted phase IDs. */
public final class RookText {
    private RookText() {}
    public static final String[] TAGS={"","en","ru","fa","ar","zh-Hans"};
    public static final String[] NAMES={"","English","Русский","فارسی","العربية","简体中文"};
    private static String supported(Locale l) {
        String language=l.getLanguage();
        if(language.equals("zh")&&!l.getScript().equals("Hant")&&(l.getScript().equals("Hans")||(!l.getCountry().equals("TW")&&!l.getCountry().equals("HK")&&!l.getCountry().equals("MO"))))return "zh-Hans";
        return language.equals("en")||language.equals("ru")||language.equals("ar")||language.equals("fa")?language:null;
    }
    public static String firstSupported(Locale... locales){for(Locale locale:locales){String tag=supported(locale);if(tag!=null)return tag;}return "en";}
    public static String tag(Context c){String tag=supported(c.getResources().getConfiguration().getLocales().get(0));return tag==null?"en":tag;}
    public static Context localized(Context c) {
        LocaleListCompat locales=AppCompatDelegate.getApplicationLocales();
        if(Build.VERSION.SDK_INT>=33){LocaleManager manager=(LocaleManager)c.getSystemService(Context.LOCALE_SERVICE);if(manager!=null)locales=LocaleListCompat.wrap(manager.getApplicationLocales());}
        if(locales.isEmpty()){
            android.os.LocaleList system=android.content.res.Resources.getSystem().getConfiguration().getLocales();
            Locale[] ordered=new Locale[system.size()];for(int i=0;i<ordered.length;i++)ordered[i]=system.get(i);
            locales=LocaleListCompat.forLanguageTags(firstSupported(ordered));
        }
        Configuration config=new Configuration(c.getResources().getConfiguration());
        config.setLocale(locales.get(0));return c.createConfigurationContext(config);
    }
    public static String detail(Context c,String source){return RookStrings.SOURCE.containsKey(source)?t(c,source):get(c,"app.server_detail")+"\n"+source;}
    public static String t(Context c,String source){Integer id=RookStrings.SOURCE.get(source);return id==null?source:c.getString(id);}
    public static String get(Context c,String key){Integer id=RookStrings.KEYS.get(key);if(id==null)throw new IllegalArgumentException("Unknown translation key: "+key);return c.getString(id);}
    public static String format(Context c,String key,String... pairs){String result=get(c,key);for(int i=0;i<pairs.length;i+=2)result=result.replace("{"+pairs[i]+"}",pairs[i+1]);return result;}
    public static String[] labels(Context c,String[] source){String[] labels=source.clone();for(int i=0;i<labels.length;i++)labels[i]=t(c,labels[i]);return labels;}
    public static String remaining(Context c,InstallationProgress p){int count=p.steps().length-p.completed;return c.getResources().getQuantityString(R.plurals.rs_checkpoints_remaining,count,count);}
    public static String elapsed(Context c,InstallationProgress p,long now){long seconds=Math.max(0,(now-p.started)/1000);return format(c,"app.elapsed","minutes",Long.toString(seconds/60),"seconds",Long.toString(seconds%60));}
    public static String estimate(Context c,InstallationProgress p){String value=p.estimate();String prefix="Planning range: about ";if(value.startsWith(prefix))return format(c,"app.estimate","range","\u2066"+value.substring(prefix.length(),value.indexOf(" min for remaining stages"))+"\u2069");return t(c,value);}
    public static String summary(Context c,InstallationProgress p){String recipe=t(c,p.kind.equals("pair")?"Two-server":p.kind.equals("enroll")?"Enrollment":"Single-server");return format(c,"app.progress_summary","recipe",recipe,"done","\u2066"+Integer.toString(p.completed),"total",Integer.toString(p.steps().length)+"\u2069","state",get(c,"app.state."+p.state));}
}
