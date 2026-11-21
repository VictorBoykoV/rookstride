package org.strongswan.android.rookstride;

import android.app.Activity;
import android.content.Context;
import android.graphics.Rect;
import android.os.Build;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.*;
import android.widget.*;
import androidx.appcompat.app.AlertDialog;
import java.util.*;

/** Searchable draft selection. Cancel never changes the caller's policy. */
public final class AppSelectionDialog {
    public interface Result { void selected(Set<String> packages); }
    private AppSelectionDialog() {}
    public static void show(Activity activity, Map<String,String> candidates, Collection<String> selected, Result result) {
        Set<String> draft=new TreeSet<>(selected);
        PickerBody body=new PickerBody(activity);int pad=dp(activity,16);body.setPadding(pad,0,pad,0);
        EditText search=new EditText(activity);search.setHint("Search apps");search.setContentDescription("Search apps");search.setSingleLine(true);search.setInputType(android.text.InputType.TYPE_CLASS_TEXT);body.addView(search);
        TextView count=new TextView(activity);count.setPadding(0,dp(activity,8),0,dp(activity,8));body.addView(count);
        ListView list=new ListView(activity);list.setTag("app-picker-list");list.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE);body.addView(list,new LinearLayout.LayoutParams(-1,0,1));
        ArrayList<String> ordered=new ArrayList<>(candidates.keySet());ordered.sort(Comparator.comparing((String id)->candidates.get(id).toLowerCase(Locale.ROOT)).thenComparing(id->id));
        android.content.pm.PackageManager packages=activity.getPackageManager();
        android.util.LruCache<String,android.graphics.drawable.Drawable> icons=new android.util.LruCache<>(32);
        ArrayList<String> visible=new ArrayList<>();
        Runnable updateCount=()->count.setText(draft.size()+" selected");
        Runnable filter=()->{String query=search.getText().toString().trim().toLowerCase(Locale.ROOT);visible.clear();ArrayList<String> labels=new ArrayList<>();for(String id:ordered)if(candidates.get(id).toLowerCase(Locale.ROOT).contains(query)||id.toLowerCase(Locale.ROOT).contains(query)){visible.add(id);labels.add(candidates.get(id));}list.setAdapter(new ArrayAdapter<String>(activity,android.R.layout.simple_list_item_multiple_choice,labels){@Override public View getView(int position,View convert,ViewGroup parent){
            CheckedTextView view=(CheckedTextView)super.getView(position,convert,parent);String id=visible.get(position);view.setMinimumHeight(dp(activity,56));view.setContentDescription("Route app "+id);view.setSingleLine(false);view.setPadding(dp(activity,12),dp(activity,8),dp(activity,12),dp(activity,8));
            // Only visible rows load icons; the bounded cache is scoped to this picker.
            android.graphics.drawable.Drawable icon=icons.get(id);
            if(icon==null){try{icon=packages.getApplicationIcon(id);}catch(android.content.pm.PackageManager.NameNotFoundException unavailable){icon=packages.getDefaultActivityIcon();}icons.put(id,icon);}
            icon.setBounds(0,0,dp(activity,32),dp(activity,32));view.setCompoundDrawablesRelative(icon,null,null,null);view.setCompoundDrawablePadding(dp(activity,12));return view;
        }});list.clearChoices();for(int i=0;i<visible.size();i++)list.setItemChecked(i,draft.contains(visible.get(i)));updateCount.run();};
        list.setOnItemClickListener((parent,view,position,id)->{String name=visible.get(position);if(list.isItemChecked(position))draft.add(name);else draft.remove(name);updateCount.run();});
        search.addTextChangedListener(new TextWatcher(){public void beforeTextChanged(CharSequence s,int start,int count,int after){}public void onTextChanged(CharSequence s,int start,int before,int count){filter.run();}public void afterTextChanged(Editable text){}});
        AlertDialog dialog=new AlertDialog.Builder(activity).setTitle("Choose apps").setView(body).setNegativeButton("Cancel",null).setPositiveButton("Done",(d,w)->result.selected(new TreeSet<>(draft))).create();
        dialog.setOnShowListener(d->{dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE|WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);for(int action:new int[]{AlertDialog.BUTTON_POSITIVE,AlertDialog.BUTTON_NEGATIVE}){Button button=dialog.getButton(action);button.setAllCaps(false);button.setMinHeight(dp(activity,48));}body.setFocusableInTouchMode(true);body.requestFocus();});
        filter.run();dialog.show();
    }
    private static int dp(Context c,int n){return Math.round(n*c.getResources().getDisplayMetrics().density);}
    private static final class PickerBody extends LinearLayout {
        private int visibleHeight;
        private final android.view.ViewTreeObserver.OnGlobalLayoutListener resize=()->{Rect frame=new Rect();getWindowVisibleDisplayFrame(frame);if(frame.height()!=visibleHeight){visibleHeight=frame.height();requestLayout();}};
        PickerBody(Context c){super(c);setOrientation(VERTICAL);setTag("app-picker-body");}
        @Override protected void onAttachedToWindow(){super.onAttachedToWindow();getViewTreeObserver().addOnGlobalLayoutListener(resize);}
        @Override protected void onDetachedFromWindow(){getViewTreeObserver().removeOnGlobalLayoutListener(resize);super.onDetachedFromWindow();}
        @Override protected void onMeasure(int width,int height){Rect frame=new Rect();getWindowVisibleDisplayFrame(frame);int available=frame.height()>0?frame.height():getResources().getDisplayMetrics().heightPixels;int limit=Math.min(dp(getContext(),380),Math.max(dp(getContext(),100),available-dp(getContext(),180)));if(MeasureSpec.getMode(height)!=MeasureSpec.UNSPECIFIED)limit=Math.min(limit,MeasureSpec.getSize(height));super.onMeasure(width,MeasureSpec.makeMeasureSpec(limit,MeasureSpec.EXACTLY));}
    }
}
