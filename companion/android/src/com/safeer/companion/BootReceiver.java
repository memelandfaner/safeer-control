package com.safeer.companion;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * Prejemnik sistemskih oddaj za samodejni in zanesljiv zagon Companion storitve
 * po ponovnem zagonu naprave (reboot) ali po posodobitvi paketa.
 */
public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "SafeerBootReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        Log.i(TAG, "Prejet sistemski broadcast dogodek: " + action);

        if (Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)
                || "android.intent.action.QUICKBOOT_POWERON".equals(action)
                || "com.htc.intent.action.QUICKBOOT_POWERON".equals(action)) {

            Intent serviceIntent = new Intent(context, SafeerCompanionService.class);
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent);
                } else {
                    context.startService(serviceIntent);
                }
                Log.i(TAG, "SafeerCompanionService uspešno sprožen ob zagonu sistema.");
            } catch (Exception e) {
                Log.e(TAG, "Napaka pri zagonu SafeerCompanionService: " + e.getMessage(), e);
            }
        }
    }
}
