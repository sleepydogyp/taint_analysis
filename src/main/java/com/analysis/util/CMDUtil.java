package com.analysis.util;



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class CMDUtil {

    private static final Logger logger = LoggerFactory.getLogger(CMDUtil.class);

    public ArrayList<String> cmdResult;

    public int excutor_windows(String cmd) {
        try {
            Process process = Runtime.getRuntime().exec("cmd.exe /c " + cmd);
            InputStream stderr = process.getInputStream();
            InputStreamReader isr = new InputStreamReader(stderr);
            BufferedReader br = new BufferedReader(isr);
            String line;
            cmdResult = new ArrayList<String>();
            while ((line = br.readLine()) != null) {
                cmdResult.add(line);
//                logger.info(line);
            }
            int exitCode = process.waitFor();
            return exitCode;
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            logger.error("", e);
        }
        return -1;
    }

    public ArrayList<String> getCmdResult() {
        return cmdResult;
    }
}
