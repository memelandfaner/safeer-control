package com.safeer.companion;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Android Foreground Service za produkcijski življenjski cikel Safeer Companion-a.
 * Zagotavlja stalno delovanje, nadzor procesa (watchdog), samodejno okrevanje
 * ob sesutju ter zaščito pred zankami strmoglavljenja (crash loop quarantine).
 */
public class SafeerCompanionService extends Service {
    private static final String TAG = "SafeerCompanionSvc";
    private static final String CHANNEL_ID = "safeer_companion_channel";
    private static final int NOTIFICATION_ID = 1001;

    private volatile boolean isRunning = false;
    private Thread supervisorThread;
    private Process companionProcess;

    // Crash loop zaščita
    private final List<Long> crashTimestamps = new ArrayList<>();
    private static final int MAX_CRASHES_PER_WINDOW = 5;
    private static final long CRASH_WINDOW_MS = 60000; // 60 sekund

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "SafeerCompanionService se inicializira...");
        createNotificationChannel();
        startForeground(NOTIFICATION_ID, buildForegroundNotification());

        isRunning = true;
        supervisorThread = new Thread(new Runnable() {
            @Override
            public void run() {
                supervisorLoop();
            }
        }, "CompanionSupervisor");
        supervisorThread.setDaemon(true);
        supervisorThread.start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "SafeerCompanionService se zaustavlja...");
        isRunning = false;
        if (companionProcess != null) {
            companionProcess.destroy();
        }
        if (supervisorThread != null) {
            supervisorThread.interrupt();
        }
        super.onDestroy();
    }

    /**
     * Nadzorna zanka (Supervisor Loop): zažene in nadzoruje nativni Safeer Companion proces.
     */
    private void supervisorLoop() {
        long backoffMs = 1000;

        while (isRunning) {
            // 1. Ekstrahiraj ali preveri nativni binarni program
            File binFile = extractOrGetCompanionBinary();
            if (binFile == null || !binFile.exists()) {
                Log.e(TAG, "Nativnega programa safeer-companion ni bilo mogoče pripraviti. Čakam 10s...");
                sleepSafe(10000);
                continue;
            }

            // 2. Preveri crash-loop zaščito
            long now = System.currentTimeMillis();
            cleanOldCrashes(now);
            if (crashTimestamps.size() >= MAX_CRASHES_PER_WINDOW) {
                Log.w(TAG, "Zaznana zanka sesutij (> " + MAX_CRASHES_PER_WINDOW + " v 60s). Vstop v karanteno (60s)...");
                sleepSafe(60000);
                crashTimestamps.clear();
                backoffMs = 1000;
                continue;
            }

            // 3. Zaženi demon
            File secretFile = new File(getFilesDir(), "companion.key");
            List<String> cmd = new ArrayList<>();
            cmd.add(binFile.getAbsolutePath());
            cmd.add("-port=8995");
            cmd.add("-secret-file=" + secretFile.getAbsolutePath());
            cmd.add("-rish-path=/data/local/tmp/rish");

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.directory(getFilesDir());
            pb.redirectErrorStream(true);

            long startTime = System.currentTimeMillis();
            try {
                Log.i(TAG, "Zaganjam Safeer Companion demon: " + binFile.getAbsolutePath());
                companionProcess = pb.start();

                // Počakaj na konec procesa
                int exitCode = companionProcess.waitFor();
                long runtime = System.currentTimeMillis() - startTime;
                Log.w(TAG, "Companion proces se je zaključil (koda: " + exitCode + ", tek: " + runtime + " ms)");

                if (runtime < 5000) {
                    crashTimestamps.add(System.currentTimeMillis());
                } else {
                    // Uspešen tek več kot 5s ponastavi backoff
                    backoffMs = 1000;
                }
            } catch (InterruptedException e) {
                Log.i(TAG, "Nadzornik prekinjen.");
                break;
            } catch (Exception e) {
                Log.e(TAG, "Napaka pri zagonu Safeer Companion procesa: " + e.getMessage(), e);
                crashTimestamps.add(System.currentTimeMillis());
            }

            if (!isRunning) break;

            // Eksponentni odlog pred ponovnim zagonom (1s, 2s, 4s ... max 30s)
            Log.i(TAG, "Ponovni zagon procesa čez " + backoffMs + " ms...");
            sleepSafe(backoffMs);
            backoffMs = Math.min(backoffMs * 2, 30000);
        }
    }

    private synchronized void cleanOldCrashes(long now) {
        java.util.Iterator<Long> it = crashTimestamps.iterator();
        while (it.hasNext()) {
            if (now - it.next() > CRASH_WINDOW_MS) {
                it.remove();
            }
        }
    }

    private void sleepSafe(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {}
    }

    /**
     * Preveri obstoj ali ekstrahira nativni program safeer-companion iz assets mape
     * v varno interno mapo aplikacije s pravicami 0700.
     */
    private File extractOrGetCompanionBinary() {
        File bin = new File(getFilesDir(), "safeer-companion");
        try {
            if (!bin.exists()) {
                InputStream is = getAssets().open("safeer-companion");
                FileOutputStream fos = new FileOutputStream(bin);
                byte[] buf = new byte[8192];
                int len;
                while ((len = is.read(buf)) > 0) {
                    fos.write(buf, 0, len);
                }
                fos.flush();
                fos.close();
                is.close();
            }
            bin.setExecutable(true, true);
            bin.setReadable(true, true);
            bin.setWritable(true, true);
            return bin;
        } catch (Exception e) {
            // Če v assets še ni binarne datoteke, preveri morebitno že nameščeno datoteko
            if (bin.exists()) {
                bin.setExecutable(true, true);
                return bin;
            }
            Log.e(TAG, "Ekstrakcija binarne datoteke ni uspela: " + e.getMessage());
            return null;
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Safeer Companion Ozadnja Storitev",
                    NotificationManager.IMPORTANCE_MIN
            );
            channel.setDescription("Zagotavlja varno povezavo in nadzor privilegiranih zmožnosti Shizuku.");
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    private Notification buildForegroundNotification() {
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        return builder
                .setContentTitle("Safeer Companion")
                .setContentText("Stalna varna povezava Shizuku aktivna.")
                .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
                .setOngoing(true)
                .build();
    }
}
