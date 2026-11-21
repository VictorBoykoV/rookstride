package org.strongswan.android.rookstride;
import android.graphics.*;
import android.graphics.drawable.*;
import android.os.SystemClock;
/** Small native progress feedback that stays on the triggering control. */
public final class LoadingArc extends Drawable implements Animatable,Runnable {
 private final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);private boolean running;private final boolean motion;
 public LoadingArc(int color,boolean animate){paint.setColor(color);paint.setStyle(Paint.Style.STROKE);paint.setStrokeCap(Paint.Cap.ROUND);paint.setStrokeWidth(2.5f);motion=animate;}
 @Override public void draw(Canvas c){Rect b=getBounds();float inset=Math.max(2,b.width()*.13f);c.drawArc(new RectF(b.left+inset,b.top+inset,b.right-inset,b.bottom-inset),motion?(SystemClock.uptimeMillis()%1000)*.36f:-90,265,false,paint);if(running&&motion)scheduleSelf(this,SystemClock.uptimeMillis()+32);}
 @Override public void setAlpha(int a){paint.setAlpha(a);}@Override public void setColorFilter(ColorFilter f){paint.setColorFilter(f);}@Override public int getOpacity(){return PixelFormat.TRANSLUCENT;}
 public boolean isRunning(){return running;}public void start(){running=true;invalidateSelf();}public void stop(){running=false;unscheduleSelf(this);}public void run(){invalidateSelf();}
}
