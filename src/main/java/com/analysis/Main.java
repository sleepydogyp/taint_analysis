package com.analysis;


import patdroid.core.Scope;
import patdroid.smali.SmaliClassDetailLoader;
import com.analysis.taint.Controller;
import patdroid.util.ParseManifest;

import java.io.File;
import java.io.IOException;
import java.util.zip.ZipFile;

public class Main {
    private static final File FRAMEWORK_CLASSES_FOLDER = new File("E:\\Android\\Sdk\\platforms\\android-23");
    private static final int API_LEVEL = 23;

    /**
     * An example using the PATDroid APIs to print all classes
     * and containing methods in an APK file
     * @param args The first arg should be the path/to/apk
     * @throws IOException when the file is not OK
     */
    public static void main(String[] args) throws IOException {

        String apkPath= "F:\\testApks\\FlowDroid\\app-debug.apk";

        // 1. 解析Manifest,获取组件的Intent-filter
        ParseManifest parseManifest = new ParseManifest();
        parseManifest.parseManifest(apkPath);
        // 2. 解析dex
        ZipFile apkFile = new ZipFile(new File(apkPath));

        long startTime = System.currentTimeMillis();

        SmaliClassDetailLoader smaliClassDetailLoader = SmaliClassDetailLoader.fromApkFile(apkFile, API_LEVEL, true);

        if (smaliClassDetailLoader.dexCount() > 2) {
            smaliClassDetailLoader.loadDex();
        } else {
            Scope scope = new Scope();
            smaliClassDetailLoader.loadAll(scope);

            long endTime = System.currentTimeMillis();
            System.out.println("compile dex cost time: " + endTime + " - " + startTime + " = " + (endTime - startTime));


            Controller controller = new Controller();
            controller.analysisController(scope);
        }
    }
}
