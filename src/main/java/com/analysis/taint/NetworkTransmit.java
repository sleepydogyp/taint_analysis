package com.analysis.taint;

import com.analysis.callgraph.CGGraph;
import com.analysis.core.MethodInfo;
import com.analysis.dalvik.Instruction;
import com.analysis.dalvik.Invocation;

import java.util.ArrayList;
import java.util.List;

public class NetworkTransmit {

    public static List<ArrayList<Element>> httpSinkGraphs = new ArrayList<ArrayList<Element>>();

    public static List<String> netTransMethod = new ArrayList<String>();

    private CGGraph cgGraph = Controller.cgGraph;


    // 网络传输反向分析，默认为间接的调用
    public static void netTansmitReverseAnalysis(MethodInfo m, int snstIndex) {
        String methodFullName = m.toString();

        ArrayList<Element> taintGraph = new ArrayList<Element>();
        List<Short> taintRegs = new ArrayList<Short>();

        Instruction invokeInst = m.insns[snstIndex];
        if (invokeInst.toString().contains("com.android.volley.toolbox.JsonObjectRequest/<init>[int, java.lang.String, org.json.JSONObject, com.android.volley.Response$Listener, com.android.volley.Response$ErrorListener]:void")) {
            Invocation invoSt = (Invocation) invokeInst.extra;
            int[] args = invoSt.args;
            taintRegs.add((short) args[3]);

            netTransMethod.add(methodFullName);

        } else if (invokeInst.toString().contains("okhttp3.OkHttpClient/newCall[okhttp3.Request]:okhttp3.Call")) {
            netTransMethod.add(methodFullName);
        } else if (invokeInst.toString().contains("java.net.URL/openConnection[]:java.net.URLConnection")) {
            netTransMethod.add(methodFullName);
        } else if (invokeInst.toString().contains("org.apache.http.client.HttpClient/execute[org.apache.http.client.methods.HttpUriRequest]:org.apache.http.HttpResponse")) {
            netTransMethod.add(methodFullName);
        } else if (invokeInst.toString().contains("java.net.URL/<init>[java.net.URL,java.lang.String,java.net.URLStreamHandler]:void")) {
            netTransMethod.add(methodFullName);
        }

        for (int i = snstIndex - 1; i > 0; i--) {
            Instruction inst = m.insns[i];
            if ("MOV".equals(inst.getOP())) {
                if ("REG".equals(inst.getOpaux_name())) {
                    if(taintRegs.contains(inst.rdst)){
                        taintRegs.add(inst.r0);
                        taintRegs.remove(inst.rdst);    // 目的寄存器在此语句之后才被污染，在此之前未被污染
                        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                    }
                } else if ("CONST".equals(inst.getOpaux_name())) {
                    // 找到了源头
                    if(taintRegs.contains(inst.rdst)){
                        taintRegs.clear();
                        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                        break;
                    }

                } else if ("RESULT".equals(inst.getOpaux_name())) {
                    if(taintRegs.contains(inst.rdst)){
                        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                        // 方法调用的返回值被污染，则其上一句调用语句传入的某个参数被污染
                        i--;
                        Instruction lastInst = m.insns[i];
                        Invocation extra = (Invocation) lastInst.extra;
                        TaintGraphUtil.addElement(taintGraph, methodFullName, lastInst, i);
                        int[] args = extra.args;
                        // TODO: 路径爆炸问题
                        for(int j = 0; j < args.length; j++){
                            taintRegs.add((short)args[j]);
                        }

                    }

                }


            } else if (inst.getOpaux_name().contains("GET")) {
                if ("SGET".equals(inst.getOpaux_name())) {
                    if(taintRegs.contains(inst.r0)){
                        taintRegs.clear();
                        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                        break;
                    }
                } else if ("IGET".equals(inst.getOpaux_name())) {
                    if(taintRegs.contains(inst.r1)){
                        taintRegs.clear();
                        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                        break;
                    }
                }

            } else if(("NEW".equals(inst.getOP())) && ("INSTANCE".equals(inst.getOpaux_name()))) {
                // NEW INSTANCE语句
                if(taintRegs.contains(inst.rdst)){
                    taintRegs.clear();
                    TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                    break;
                }
            }
            else if("INVOKE".equals(inst.getOP())) {
                NetworkTransmit networkTransmit = new NetworkTransmit();
                networkTransmit.invokeReverseAnalyse(inst, taintGraph, m.insns[i +1], methodFullName, i, taintRegs);
            }
            else if ((i == 0) && (inst.opcode == 3) && (inst.opcode_aux == 7)) {    // 作为参数传进来
                int[] methodArgs = (int[]) inst.extra;
                for (int reg : methodArgs) {
                    if (taintRegs.contains((short) reg)) {
                        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                        // TODO：根据CG查找调用此方法m的方法
                    }
                }
            }

        }

        ArrayList<Element> newGraph = new ArrayList<Element>();
        newGraph.addAll(taintGraph);
        httpSinkGraphs.add(newGraph);
        taintGraph.clear();

    }



    private void invokeReverseAnalyse(Instruction inst, ArrayList<Element> taintGraph, Instruction nextInst, String methodFullName, int index, List<Short> taintRegs){
        // 对于没有返回值的方法调用，如果第一个参数，即某引用被污染，则将剩下的参数标记为被污染
        // TODO:
        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, index);
        Invocation extra = (Invocation) inst.extra;
        int[] args = extra.args;
        if((!"MOV".equals(nextInst)) && (!"RESULT".equals(nextInst))){
            if(taintRegs.contains(args[0])){
                if(args.length > 1){
                    for(int j = 1; j < args.length; j++){
                        taintRegs.add((short)args[j]);
                    }
                }
            }
        }
    }

}
