package org.strongswan.android.rookstride;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.view.*;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.*;
import org.strongswan.android.R;

/** A swipe reveals an explicit action. A gesture can never submit a deletion. */
public final class SwipeRevealLayout extends FrameLayout {
    private final View content;
    private final ImageButton remove;
    private final int width,slop,edge;
    private float downX,downY,origin;
    private boolean dragging,opened;
    private Runnable moveUp,moveDown;
    public SwipeRevealLayout(Context context,View content,String label,Runnable action){
        super(context);this.content=content;if(content.getContentDescription()==null)content.setContentDescription(label);float d=getResources().getDisplayMetrics().density;
        // Keep blank card areas as touch targets after removing the old long-hold delete action.
        // Otherwise account cards drop ACTION_DOWN and never deliver a swipe to this parent.
        content.setClickable(true);
        width=(int)(72*d);edge=(int)(24*d);slop=ViewConfiguration.get(context).getScaledTouchSlop();
        remove=new ImageButton(context);remove.setImageResource(R.drawable.rook_delete);remove.setColorFilter(Color.WHITE);
        GradientDrawable red=new GradientDrawable();red.setColor(Color.rgb(185,28,43));red.setCornerRadius(16*d);remove.setBackground(red);
        remove.setContentDescription("Delete "+label);remove.setOnClickListener(v->action.run());
        remove.setVisibility(INVISIBLE);addView(remove,new LayoutParams(width,-1,Gravity.RIGHT));addView(content,new LayoutParams(-1,-2));
        setMinimumHeight((int)(56*d));
        content.setAccessibilityDelegate(new View.AccessibilityDelegate(){
            @Override public void onInitializeAccessibilityNodeInfo(View host,AccessibilityNodeInfo info){super.onInitializeAccessibilityNodeInfo(host,info);info.addAction(new AccessibilityNodeInfo.AccessibilityAction(AccessibilityNodeInfo.ACTION_DISMISS,"Show delete action"));if(moveUp!=null)info.addAction(new AccessibilityNodeInfo.AccessibilityAction(AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD,"Move server up"));if(moveDown!=null)info.addAction(new AccessibilityNodeInfo.AccessibilityAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD,"Move server down"));}
            @Override public boolean performAccessibilityAction(View host,int id,android.os.Bundle args){if(id==AccessibilityNodeInfo.ACTION_DISMISS){reveal(true);remove.requestFocus();return true;}if(id==AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD&&moveUp!=null){moveUp.run();return true;}if(id==AccessibilityNodeInfo.ACTION_SCROLL_FORWARD&&moveDown!=null){moveDown.run();return true;}return super.performAccessibilityAction(host,id,args);}
        });
    }
    public void reorderWith(Runnable begin,Runnable up,Runnable down){moveUp=up;moveDown=down;content.setOnLongClickListener(v->{reveal(false);begin.run();return true;});}
    public boolean isRevealed(){return opened;}
    private boolean inContent(float x){return x<getWidth()+content.getTranslationX();}
    @Override public boolean onInterceptTouchEvent(MotionEvent event){
        if(event.getActionMasked()==MotionEvent.ACTION_DOWN){downX=event.getX();downY=event.getY();origin=content.getTranslationX();dragging=false;}
        if(event.getActionMasked()==MotionEvent.ACTION_MOVE&&downX>edge&&inContent(downX)){
            float x=event.getX()-downX,y=event.getY()-downY;
            if(Math.abs(x)>slop&&Math.abs(x)>Math.abs(y)*1.5f&&(x<0||opened)){dragging=true;getParent().requestDisallowInterceptTouchEvent(true);return true;}
        }
        return false;
    }
    @Override public boolean onTouchEvent(MotionEvent event){
        if(!dragging)return super.onTouchEvent(event);
        switch(event.getActionMasked()){
            case MotionEvent.ACTION_MOVE:remove.setVisibility(VISIBLE);content.setTranslationX(Math.max(-width,Math.min(0,origin+event.getX()-downX)));return true;
            case MotionEvent.ACTION_UP:
                float travel=event.getX()-downX;float threshold=Math.min(getWidth()*.4f,width*1.65f);
                reveal(opened?travel<width*.5f:travel<-threshold);dragging=false;getParent().requestDisallowInterceptTouchEvent(false);performClick();return true;
            case MotionEvent.ACTION_CANCEL:reveal(opened);dragging=false;getParent().requestDisallowInterceptTouchEvent(false);return true;
        }return true;
    }
    @Override public boolean performClick(){super.performClick();return true;}
    private void reveal(boolean value){opened=value;content.animate().cancel();remove.setVisibility(VISIBLE);content.animate().translationX(value?-width:0).setDuration(android.provider.Settings.Global.getFloat(getContext().getContentResolver(),android.provider.Settings.Global.ANIMATOR_DURATION_SCALE,1)==0?0:160).withEndAction(()->{if(!opened)remove.setVisibility(INVISIBLE);}).start();}
}
