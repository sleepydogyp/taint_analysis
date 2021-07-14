package com.analysis.taint;

import com.alibaba.fastjson.JSONArray;
import com.analysis.core.MethodInfo;
import com.analysis.dalvik.Instruction;
import com.analysis.dalvik.Invocation;
import com.analysis.util.ParseManifest;

import java.util.HashMap;
import java.util.Map;

public class IntentTransmit {

    // 隐式Intent的category信息不必完全匹配, 只需匹配action就好
    public String implicitIntentComponent(MethodInfo m, int snstIndex){
        String implicitComponent = "";
        HashMap<String, JSONArray> intentFilterMaps = ParseManifest.intentFilterMaps;
        String action = "";
        // 1. 得到Intent的action
        for(int i = snstIndex ; i > 0; i--){
            Instruction inst = m.insns[i];
            if(inst.toString().contains("android.content.Intent/setAction[java.lang.String]:android.content.Intent")){
                Invocation extra = (Invocation) inst.extra;
                int[] args = extra.args;
                i--;
                if((i > 0) && (args.length > 1)){
                    short constArg = (short) args[1];
                    Instruction instConst = m.insns[i];
                    if(("MOV".equals(instConst.getOP())) && ("CONST".equals(instConst.getOpaux_name())) && (constArg == instConst.rdst)){
                        action = (String) instConst.extra;
                        break;
                    }
                }
            }
        }

        // 2. 匹配Manifest，得到目标组件
        if(!"".equals(action)){
            for(Map.Entry<String, JSONArray> entry : intentFilterMaps.entrySet()){
                JSONArray actions = entry.getValue();
                if(actions.contains(action)){
                    implicitComponent = entry.getKey();
                    break;
                }
            }
        }
        return implicitComponent;

    }

    // 找到显式Intent启动哪个组件
    public String explicitIntent(MethodInfo m, int snstIndex){


        return "";
    }


}
