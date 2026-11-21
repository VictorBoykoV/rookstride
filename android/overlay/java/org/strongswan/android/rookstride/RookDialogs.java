package org.strongswan.android.rookstride;

import android.app.Activity;
import android.content.Context;
import android.graphics.Rect;
import android.util.TypedValue;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.ViewTreeObserver;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;

/** A bounded body and consistent native actions. Callers retain button semantics. */
public final class RookDialogs {
    public static final String BODY_TAG="rookstride.dialog.body";
    private RookDialogs(){}
    public static AlertDialog.Builder builder(Activity activity){return new Builder(activity);}
    public static ScrollView scrolling(Activity activity,View content){
        if(content instanceof Body)return (Body)content;
        Body scroll=new Body(activity);scroll.setClipToPadding(false);scroll.addView(content);return scroll;
    }
    private static int dp(Context context,float value){return Math.round(value*context.getResources().getDisplayMetrics().density);}
    private static final class Builder extends AlertDialog.Builder {
        private final Activity activity;
        Builder(Activity activity){super(activity);this.activity=activity;}
        @Override public AlertDialog.Builder setView(View view){return super.setView(scrolling(activity,view));}
        @Override public AlertDialog create(){
            AlertDialog dialog=super.create();
            dialog.setOnShowListener(ignored->{
                Window window=dialog.getWindow();
                if(window!=null)window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
                TextView title=dialog.findViewById(androidx.appcompat.R.id.alertTitle);
                if(title!=null){
                    // AppCompat otherwise caps a native title at two lines,
                    // losing the actual task name at large system text sizes.
                    title.setSingleLine(false);title.setMaxLines(Integer.MAX_VALUE);title.setEllipsize(null);
                }
                for(int which:new int[]{AlertDialog.BUTTON_POSITIVE,AlertDialog.BUTTON_NEGATIVE,AlertDialog.BUTTON_NEUTRAL}){
                    Button button=dialog.getButton(which);
                    if(button!=null){
                        // Keep native positive/negative/neutral order and callbacks.
                        // Sentence case is both quieter and shorter than all-caps;
                        // SP continues to follow the phone's accessibility setting.
                        button.setAllCaps(false);
                        button.setTextSize(TypedValue.COMPLEX_UNIT_SP,15);
                        button.setMinHeight(dp(activity,48));
                        button.setMinimumHeight(dp(activity,48));
                        button.setMinWidth(dp(activity,64));
                        button.setMinimumWidth(dp(activity,64));
                    }
                }
            });
            return dialog;
        }
    }
    private static final class Body extends ScrollView {
        private int lastVisibleHeight;
        private Boolean titleWasVisible;
        private final ViewTreeObserver.OnGlobalLayoutListener usableWindow=()->{
            Rect frame=new Rect();getWindowVisibleDisplayFrame(frame);
            if(frame.height()>0&&frame.height()!=lastVisibleHeight){lastVisibleHeight=frame.height();requestLayout();}
        };
        Body(Context context){super(context);setTag(BODY_TAG);}
        @Override protected void onAttachedToWindow(){super.onAttachedToWindow();getViewTreeObserver().addOnGlobalLayoutListener(usableWindow);}
        @Override protected void onDetachedFromWindow(){getViewTreeObserver().removeOnGlobalLayoutListener(usableWindow);super.onDetachedFromWindow();}
        @Override protected void onMeasure(int width,int height){
            Rect frame=new Rect();getWindowVisibleDisplayFrame(frame);
            int available=frame.height()>0?frame.height():getResources().getDisplayMetrics().heightPixels;
            View root=getRootView(),title=root.findViewById(androidx.appcompat.R.id.topPanel),actions=root.findViewById(androidx.appcompat.R.id.buttonPanel);
            boolean keyboard=getResources().getDisplayMetrics().heightPixels-frame.bottom>dp(getContext(),100);
            // On short keyboard viewports the field and native actions take priority.
            // Restore the title when the keyboard closes; untitled dialogs stay untitled.
            if(title!=null){
                if(titleWasVisible==null)titleWasVisible=title.getVisibility()==View.VISIBLE;
                if(titleWasVisible)title.setVisibility(keyboard&&available<dp(getContext(),240)?View.GONE:View.VISIBLE);
            }
            int chrome=(title==null||title.getVisibility()==View.GONE?0:title.getMeasuredHeight())+(actions==null?0:actions.getMeasuredHeight())+dp(getContext(),keyboard?24:56);
            int reserve=Math.max(dp(getContext(),keyboard?80:176),chrome);
            int limit=Math.max(dp(getContext(),24),Math.min(Math.round(available*.60f),available-reserve));
            if(MeasureSpec.getMode(height)!=MeasureSpec.UNSPECIFIED)limit=Math.min(limit,MeasureSpec.getSize(height));
            super.onMeasure(width,MeasureSpec.makeMeasureSpec(limit,MeasureSpec.AT_MOST));
        }
    }
}
