package org.strongswan.android.rookstride;

import android.content.Context;
import android.graphics.Bitmap;
import androidx.test.platform.app.InstrumentationRegistry;
import java.io.File;
import java.io.FileOutputStream;

/** Screenshots contain only the explicitly fictional UI fixtures. */
final class ScreenshotProof {
    static void save(Context context,String name)throws Exception {
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        java.util.concurrent.CountDownLatch frames=new java.util.concurrent.CountDownLatch(1);
        InstrumentationRegistry.getInstrumentation().runOnMainSync(()->android.view.Choreographer.getInstance().postFrameCallback(time->android.view.Choreographer.getInstance().postFrameCallback(next->frames.countDown())));
        if(!frames.await(5,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("No rendered frame for screenshot");
        // Allow closed-dialog/window fades to finish; continuous mascot animation is not an idle UI.
        Thread.sleep(400);
        Bitmap image=InstrumentationRegistry.getInstrumentation().getUiAutomation().takeScreenshot();
        if(image==null)throw new IllegalStateException("Could not capture UI proof");
        try(FileOutputStream out=new FileOutputStream(new File(context.getExternalFilesDir(null),"ui-proof-"+name+".png"))){image.compress(Bitmap.CompressFormat.PNG,100,out);}finally{image.recycle();}
    }
}
