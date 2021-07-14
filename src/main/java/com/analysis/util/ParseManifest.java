package com.analysis.util;

import com.alibaba.fastjson.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;

public class ParseManifest {

    private static final Logger logger = LoggerFactory.getLogger(ParseManifest.class);

    public static HashMap<String, JSONArray> intentFilterMaps = new HashMap<String, JSONArray>();


    public void parseManifest(String apkPath) {
        String cmd = "aapt dump xmltree " + apkPath + " AndroidManifest.xml";
        CMDUtil cmdUtil = new CMDUtil();
        cmdUtil.excutor_windows(cmd);

        ArrayList<String> manifest = cmdUtil.getCmdResult();
        if ((manifest != null) && (manifest.size() != 0)) {
            boolean isComponent = false;
            boolean getCompName = false;
            String componentName = "";
            JSONArray intentFilters = null;
            for (int i = 0; i < manifest.size(); i++) {
                String line = manifest.get(i).trim();
                if (line.startsWith("E: activity") || line.startsWith("E: provider") || line.startsWith("E: service") || line.startsWith("E: receiver")) {
                    isComponent = true;
                    getCompName = false;
                    if((intentFilters != null) && (intentFilters.size() != 0)){
                        intentFilterMaps.put(componentName, intentFilters);
                    }
                    intentFilters = new JSONArray();
                    continue;
                } else if (isComponent && line.startsWith("A: android:name")) {
                    componentName = line.split("Raw: \"")[1].replace("\")", "");
                    isComponent = false;
                    getCompName = true;
                    continue;
                } else if (getCompName && line.startsWith("E: intent-filter")) {
                    i++;
                    if (manifest.get(i).trim().startsWith("E: action")) {
                        i++;
                        intentFilters.add( manifest.get(i).trim().split("Raw: \"")[1].replace("\")", ""));
                        i++;
                    }
                }
            }
        }

    }

}
