package com.analysis.taint;

import java.io.*;
import java.util.ArrayList;

public class TaintAPIs {

    public static ArrayList<String> sources = new ArrayList<String>();

    public static ArrayList<String> sinks = new ArrayList<String>();

    public static ArrayList<String> httpSinks = new ArrayList<String>();


    private static TaintAPIs taintAPIs;

    private TaintAPIs() {
        String dir = "H:\\MyGithub\\taint_analysis\\config\\";
        String file = dir + "SourceAndSink.txt";
        String httpSinkFile = dir + "InfoSinks.txt";
        String sourcesFile = dir + "InfoLeakageSources.txt";
        initSourceAndSink(file);
        initSourceAndSink(httpSinkFile);
        initSourceAndSink(sourcesFile);
    }

    ;

    public static TaintAPIs getInstance() {
        if (taintAPIs == null) {
            taintAPIs = new TaintAPIs();

        }
        return taintAPIs;
    }

    public void initSourceAndSink(String filePath) {
        try {
            FileInputStream fileInputStream = new FileInputStream(new File(filePath));
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(fileInputStream, "UTF-8"));

            String str = null;
            StringBuffer stringBuffer = new StringBuffer();
            while ((str = bufferedReader.readLine()) != null) {
                if ("".equals(str)) {
                    continue;
                }
                if ((str.startsWith("SOURCE->")) && filePath.endsWith("InfoLeakageSources.txt")) {
                    sources.add(str.substring(8));
                } else if (str.startsWith("SINK->")) {
                    sinks.add(str.substring(6));
                } /*else if (filePath.endsWith("InfoSinks.txt")) {
                    httpSinks.add(str);
                }*/

            }

            fileInputStream.close();
            bufferedReader.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


}
