package org.strongswan.android.rookstride;
import org.json.*;import org.junit.Test;import static org.junit.Assert.*;
public class FilterPresetsTest {
 @Test public void selectedComesFromEnabledServerStateNotTheLastTappedChoice()throws Exception{for(String[] option:FilterPresets.OPTIONS){JSONArray filters=new JSONArray();for(String[] other:FilterPresets.OPTIONS)filters.put(new JSONObject().put("name",other[2]).put("enabled",other[0].equals(option[0])));assertEquals(option[0],FilterPresets.selected(new JSONObject().put("filters",filters)));}}
 @Test public void mixedMissingOrUnknownFiltersAreNotMisrepresentedAsAPreset()throws Exception{assertEquals("custom",FilterPresets.selected(new JSONObject()));assertEquals("custom",FilterPresets.selected(new JSONObject().put("filters",new JSONArray().put(new JSONObject().put("name","Unknown filter").put("enabled",true)))));JSONArray filters=new JSONArray();for(String[] option:FilterPresets.OPTIONS)filters.put(new JSONObject().put("name",option[2]).put("enabled",true));assertEquals("custom",FilterPresets.selected(new JSONObject().put("filters",filters)));}
}
