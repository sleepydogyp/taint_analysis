package com.analysis.taint;

import com.analysis.callgraph.CGGraph;
import com.analysis.controlFlowGraph.CFGStructure;
import com.analysis.core.ClassInfo;
import com.analysis.core.FieldInfo;
import com.analysis.core.MethodInfo;
import com.analysis.core.Scope;
import com.analysis.dalvik.Instruction;
import com.analysis.dalvik.Invocation;
import com.analysis.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Controller {

    private static final Logger logger = LoggerFactory.getLogger(Controller.class);

    List<CFGStructure> cfgNodeList = new ArrayList<CFGStructure>();
    public static CGGraph cgGraph = new CGGraph();

    private ArrayList<Element> tempSources = new ArrayList<Element>();
    private Set<String> taintFields = new HashSet<String>();   // 通过setXXX()方法被污染的全局变量

    List<ArrayList<Element>> taintGraphs = new ArrayList<ArrayList<Element>>();
    List<ArrayList<Element>> noSinkGraphs = new ArrayList<ArrayList<Element>>();

    String[] contentProviderUri = {"ContactUtil", "ContactsContract", "calendar", "sms"};

    public void analysisController(Scope scope) {
        // build Call Graph and CFG
//        buildCGAndCFG(scope, cgGraph);
//        cgGraph.outputCG();
//        outputCFG();


        long startTime = System.currentTimeMillis();

        // 污染源和陷入点初始化
        TaintAPIs.getInstance();


        // 1.先过滤一遍获取敏感信息的SOURCE，找到路径，并补充taintFields； 2.将上一遍得到的路径清空，再过滤一遍,加入taintFields
        int i = 1;
        while (i < 3){
            taintGraphs.clear();
            noSinkGraphs.clear();
            for (ClassInfo c : scope.getAllClasses()) {
                if (!c.isFrameworkClass()) {
                    if (c.getAllMethods().size() == 0) {
                        continue;
                    }
                    for (MethodInfo m : c.getAllMethods()) {
                        if (m.insns == null) continue;
                        analyseInMethod(m, i);
                    }
                }
            }
            i++;
        }

        long endTime = System.currentTimeMillis();
        System.out.println("build taintGraphs cost time: " + endTime + " - " + startTime + " = " + (endTime - startTime));
        System.out.println("taintGraphs.length = " + taintGraphs.size());
        System.out.println("noSinkGraphs.length = " + noSinkGraphs.size());
        // output
        for (ArrayList<Element> taintGraph : taintGraphs) {
            System.out.println("---------taintGraphs----------");
            for (Object eleObj : taintGraph) {
                System.out.println(eleObj.toString());
            }
        }
        for (ArrayList<Element> noSinkGraph : noSinkGraphs) {
            System.out.println("---------noSinkGraphs----------");
            for (Object eleObj : noSinkGraph) {
                System.out.println(eleObj.toString());
            }
        }

    }

    private void analyseInMethod(MethodInfo m, int times) {
        ArrayList<Element> taintGraph = new ArrayList<Element>();
        String methodFullName = m.toString();
        List<Short> taintRegs = new ArrayList<Short>();

        boolean lastInstBundle = false;     //表示上一个Sink是否为Bundle的putXXX
        for (int i = 0; i < m.insns.length; i++) {
            Instruction inst = m.insns[i];
            if ("INVOKE".equals(inst.getOP())) {
                Invocation invoSt = (Invocation) inst.extra;
                MethodInfo targetMethod = invoSt.target;
                String calledMethod = targetMethod.toString().replace(" ", "");

                // TODO： 多条污染路径同时开始，暂时采用路径不分离，混合存放的方法
                if (TaintAPIs.sources.contains(calledMethod)) {
                    // 污染源
                    // 一条污染线路的起始
                    TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                    i++;
                    Instruction instNext = m.insns[i];

                    if (("MOV".equals(instNext.getOP())) && ("RESULT".equals(instNext.getOpaux_name()))) {
                        taintRegs.add(instNext.rdst);

                    }
                } else if (TaintAPIs.sinks.contains(calledMethod)) {
                    // 陷入点，感染路径的终点
                    // 此路径结束
                    int[] args = invoSt.args;
                    for (int arg : args) {
                        if (taintRegs.contains((short) arg)) {

                            TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                            // 判断是否为Intent传值，Bundle.putXXX方法，如果不是，路径结束；如果是，将lastInstBundle置为true,
                            if (calledMethod.startsWith("android.os.Bundle/put")) {   // 把同一个Intent传值放在一条路径中
                                if (!lastInstBundle) {
                                    lastInstBundle = true;
                                }
                            } else {
                                lastInstBundle = false;
                                ArrayList<Element> newGraph = new ArrayList<Element>();
                                newGraph.addAll(taintGraph);
                                taintGraphs.add(newGraph);
                                taintGraph.clear();
                            }
                        }
                    }
                } else {
                    // 其他方法调用
                    // 判断是否是发送Intent的方法，如果是，则路径中加入节点，并lastInstBundle置为false;
                    if (lastInstBundle && (calledMethod.contains("/startActivity") || calledMethod.contains("/bindService") || calledMethod.contains("/sendBroadcast"))) {
                        // Intent隐式启动某组件，将被启动的组件加入路径末尾
                        IntentTransmit intentTransmit = new IntentTransmit();
                        String implicitComp = intentTransmit.implicitIntentComponent(m, i);
                        TaintGraphUtil.addElement(taintGraph, "start Component: " + implicitComp, m.insns[i], i);
                        lastInstBundle = false;
                        ArrayList<Element> newGraph = new ArrayList<Element>();
                        newGraph.addAll(taintGraph);
                        taintGraphs.add(newGraph);
                        taintGraph.clear();
                    }

                    // 其他方法调用
                    int[] args = invoSt.args;
                    for (int argIndex = 0; argIndex < args.length; argIndex++) {
                        // 如果参数被污染，则进入此方法；如果方法为native方法，则直接将此调用加入污染路径；如果是反射调用，需要分析调用的方法是否为sink点
                        if (taintRegs.contains((short) args[argIndex])) {
                            MethodInfo method = invoSt.target;
                            if ((method.insns == null) || (calledMethod.contains("getMethod"))) {   // Native方法或反射方法或其他底层方法的insns均为null，直接认为其返回值被污染了
                                boolean hasMovResult = addNullMethod(taintGraph, taintRegs, m, methodFullName, inst, i, (short) args[0]);
                                if(hasMovResult){
                                    i++;
                                }
                            } else {
                                ArrayList<Element> innerTaints = interproceduralAnalyse(method, argIndex);
                                taintGraph.addAll(innerTaints);
                            }
                            break;
                        }
                    }
                }
            } else if ("IF".equals(inst.getOP())) {
                // IF语句直接按顺序执行
                if (taintRegs.contains(inst.r0)) {
//                    TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                } else {
                    continue;
                }

            } else if ("MOV".equals(inst.getOP())) {
                if (taintGraph != null) {
                    Instruction lastInst = m.insns[i - 1];
                    MOVAnalyse(taintGraph, methodFullName, inst, i, taintRegs, lastInst, taintGraph);
                }
            } else if (inst.getOpaux_name().contains("GET")) {
                // 判断是否取出了被污染的全局变量
                Object extraStr = inst.extra;
                if ((times > 1) && (inst.extra != null) && (taintFields.size() > 0) && (taintFields.contains(inst.extra.toString()))) {
                    TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                    if ("SGET".equals(inst.getOpaux_name())) {
                        taintRegs.add(inst.r0);
                    } else if ("IGET".equals(inst.getOpaux_name())) {
                        taintRegs.add(inst.r1);
                    }
                } else {
                    // 被污染的值传入某全局变量，则将该全局变量加入taintFields
                    // <INSTANCE,IGET,r0=r1,r1=r0,type=java.lang.Object,extra=com.android.sparrow.collectInfoUtil.SMSUtil.smsArray>
                    // <INVOKE,VIRTUAL,extra=[org.json.JSONArray/put[java.lang.Object]:org.json.JSONArray, [0, 7]<NOT_RESOLVED>]>
                    if (("INSTANCE".equals(inst.getOP()) && (inst.getOpaux_name().contains("IGET"))) && (inst.extra instanceof FieldInfo)) {  // 普通全局变量
                        // 判断是否传入被污染的值
                        short fieldReg = inst.r1;
                        Instruction nextInst = m.insns[i + 1];
                        if ("INVOKE".equals(nextInst.getOP())) {
                            Invocation invoNext = (Invocation) nextInst.extra;
                            if (((invoNext.target.toString().contains("/put[")) || (invoNext.target.toString().contains("/add["))) && (invoNext.args.length > 1) && ((short)invoNext.args[0] == fieldReg) && (taintRegs.contains((short)invoNext.args[1]))) {
                                taintFields.add(inst.extra.toString());
                                i++;
                            }
                        }

                    }else if(("STATIC".equals(inst.getOP())) && ("SGET".equals(inst.getOpaux_name())) && (inst.extra instanceof Pair)){  // 静态全局变量
                        Instruction nextInst = m.insns[i + 1];
                        if ("INVOKE".equals(nextInst.getOP())) {
                            Invocation invo = (Invocation) nextInst.extra;
                            if (((invo.target.toString().contains("/put[")) || (invo.target.toString().contains("/add["))) && (invo.args.length > 1) && (taintRegs.contains((short)invo.args[1]))) {
                                taintFields.add(inst.extra.toString());
                                i++;
                            }
                        }

                    }


/*                    String instStr = inst.toString();
                    for (int uriIndex = 0; uriIndex < contentProviderUri.length; uriIndex++) {
                        if (instStr.contains(contentProviderUri[uriIndex])) {
                            TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
                            if ("SGET".equals(inst.getOpaux_name())) {
                                taintRegs.add(inst.r0);
                            } else if ("IGET".equals(inst.getOpaux_name())) {
                                taintRegs.add(inst.r1);
                            }
                        }
                    }*/
                }

            }
            // 还有一个 MOV EXCEPTION, 忽略
        }

        // 方法结束，如果taintGraph不为空，说明没找到Sink, 也加入路径
        if (taintGraph.size() != 0) {
            ArrayList<Element> newGraph = new ArrayList<Element>();
            newGraph.addAll(taintGraph);
            noSinkGraphs.add(newGraph);
        }

    }


    private int ifTrue() {
        return -1;
    }

    private int ifFalse() {
        return -1;
    }

    // 传入的参数被污染
    private ArrayList<Element> interproceduralAnalyse(MethodInfo m, int argIndex) {
        ArrayList<Element> taints = new ArrayList<Element>();
        List<Short> taintRegs = new ArrayList<Short>();
        String methodFullName = m.toString();
        // 判断是否为setXXX方法，如果是，则将被赋值的字段加入被污染字段
        if ((m.insns.length == 3) && (m.insns[0].toString().equals("<SPECIAL,ARGUMENT_SET,extra=[0, 1]>"))
                && ((m.insns[1].toString().startsWith("<INSTANCE,IPUT,r0=r0,r1=r1,type=java.lang.Object,")) || (m.insns[1].toString().startsWith("<STATIC,SPUT,r0=r1,type=java.lang.Object,")))
                && (m.insns[2].toString().equals("<RETURN,VOID>"))) {
            // 注意普通变量为FieldInfo类型，静态变量为Pair类型，两者的toString()格式不同
            taintFields.add(m.insns[1].extra.toString());
        } else {

            // 其他方法
            for (int i = 0; i < m.insns.length; i++) {
                Instruction inst = m.insns[i];
                if (i == 0) {
                    int[] argRegs = (int[]) inst.extra;
                    taintRegs.add((short) argRegs[argIndex]);
                } else {
                    if ("INVOKE".equals(inst.getOP())) {
                        Invocation invoSt = (Invocation) inst.extra;
                        MethodInfo targetMethod = invoSt.target;
                        String calledMethod = targetMethod.toString();
                        int[] args = invoSt.args;
                        if (TaintAPIs.sinks.contains(calledMethod)) {
                            // 陷入点，感染路径的终点
                            // 此路径结束
                            for (int arg : args) {
                                if (taintRegs.contains((short) arg)) {
                                    TaintGraphUtil.addElement(taints, methodFullName, inst, i);
                                    break;
                                }
                            }

                        } else {
                            for (int index = 0; argIndex < args.length; argIndex++) {
                                if (taintRegs.contains((short) args[index])) {
                                    MethodInfo method = invoSt.target;
                                    if (method.insns == null) {
                                        boolean hasMovResult = addNullMethod(taints, taintRegs, m, methodFullName, inst, i, (short) args[0]);
                                        if(hasMovResult){
                                            i++;
                                        }
                                    } else {
                                        if (!method.toString().equals(methodFullName)) {         // 防止死循环
                                            ArrayList<Element> innerTaints = interproceduralAnalyse(method, index);
                                            taints.addAll(innerTaints);
                                        }
                                    }
                                    break;
                                }
                            }
                        }


                    } else if ("MOV".equals(inst.getOP())) {
                        Instruction lastInst = m.insns[i - 1];
                        MOVAnalyse(taints, methodFullName, inst, i, taintRegs, lastInst, taints);

                    } else if ("IF".equals(inst.getOP())) {
                        // IF语句直接按顺序执行
                        if (taintRegs.contains(inst.r0)) {
                            TaintGraphUtil.addElement(taints, methodFullName, inst, i);
                        } else {
                            continue;
                        }

                    }
                }
            }
        }


        return taints;
    }

    private void MOVAnalyse(ArrayList<Element> taintGraph, String methodFullName, Instruction inst, int insnIndex, List<Short> taintRegs, Instruction lastInst, ArrayList<Element> taints) {
        if ("REG".equals(inst.getOpaux_name())) {
            if (taintRegs.contains(inst.r0)) {
                taintRegs.add(inst.rdst);
                TaintGraphUtil.addElement(taintGraph, methodFullName, inst, insnIndex);
            } else if (taintRegs.contains(inst.rdst)) {
                taintRegs.remove(taintRegs.indexOf(inst.rdst));
            }
        } else if ("CONST".equals(inst.getOpaux_name())) {
            String instStr = inst.toString();
            if (instStr.contains("sms") || instStr.contains("contact") || instStr.contains("calendar")) {
                TaintGraphUtil.addElement(taintGraph, methodFullName, inst, insnIndex);
                taintRegs.add(inst.rdst);
            } else if (taintRegs.contains(inst.rdst)) {
                taintRegs.remove(taintRegs.indexOf(inst.rdst));
            }
        } else if ("RESULT".equals(inst.getOpaux_name())) {
            // 如果上一句为INVOKE，且在taintGraph中，则需要将这个返回值的寄存器加入taintRegs
            boolean lastInsnIsTaint = false;
            if (lastInst.opcode == 12) {
                for (Object elementObj : taints) {
                    Element element = (Element) elementObj;
                    if (lastInst.toString().equals(element.getInsn())) {
                        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, insnIndex);
                        taintRegs.add(inst.rdst);
                        lastInsnIsTaint = true;
                        break;
                    }
                }

            }

            // 如果不是陷入点的返回值，而是某函数或指令返回值占用了此寄存器，就需要将此寄存器从taintRegs中移出
            if ((!lastInsnIsTaint) && taintRegs.contains(inst.rdst)) {
                taintRegs.remove(taintRegs.indexOf(inst.rdst));
            }
        }
    }

    private Boolean addNullMethod(ArrayList<Element> taintGraph, List<Short> taintRegs, MethodInfo m, String methodFullName, Instruction inst, int i, short arg) {
        boolean hasMovResult = false;
        TaintGraphUtil.addElement(taintGraph, methodFullName, inst, i);
        Instruction instNext = m.insns[i + 1];
        if (("MOV".equals(instNext.getOP())) && ("RESULT".equals(instNext.getOpaux_name()))) {
            if (!taintRegs.contains(instNext.rdst)) {
                taintRegs.add(instNext.rdst);
            }
            hasMovResult = true;
        } else {
            if (!taintRegs.contains(arg)) {
                taintRegs.add(arg);
            }

        }
        return hasMovResult;
    }


    public void buildCGAndCFG(Scope scope, CGGraph cgGraph) {
        long startTime = System.currentTimeMillis();
        // 一边遍历一边添加顶点和边
        for (ClassInfo c : scope.getAllClasses()) {
            if (!c.isFrameworkClass()) {
                for (MethodInfo m : c.getAllMethods()) {
                    if (m.insns == null) continue;
                    int source = cgGraph.getVertexIndex(m);
                    if (source == -1) {
                        cgGraph.insertVertex(m);
                        source = cgGraph.getVertexIndex(m);
                    }
                    for (int i = 0; i < m.insns.length; i++) {
                        if ("INVOKE".equals(m.insns[i].getOP())) {
                            Invocation invoSt = (Invocation) m.insns[i].extra;
                            MethodInfo targetMethod = invoSt.target;
                            if (targetMethod.insns == null) continue;
                            MethodInfo calledMethod = targetMethod;
                            int des = cgGraph.getVertexIndex(calledMethod);
                            if (des == -1) {
                                cgGraph.insertVertex(calledMethod);
                                des = cgGraph.getVertexIndex(calledMethod);
                            }

                            cgGraph.addEdge(source, des);
                        }
                        // CFG
                        buildCFG(m, m.insns[i], i);
                    }

                }
            }
        }
        long endTime = System.currentTimeMillis();
        System.out.println("buildCG1 cost time: " + endTime + " - " + startTime + " = " + (endTime - startTime));
    }

    // 生成CFG，合并入生成CG的过程
    public void buildCFG(MethodInfo m, Instruction insn, int i) {
        if ("IF".equals(insn.getOP())) {
            int controlInsIndex = i;
            int TDesIndex = (Integer) insn.extra;
            int FDesIndex = i + 1;

            CFGStructure cfgStructure = new CFGStructure(m, controlInsIndex, TDesIndex, FDesIndex);
            cfgNodeList.add(cfgStructure);
        }
    }

    public void outputCFG() {
        for (CFGStructure cfgStructure : cfgNodeList) {
            System.out.println(cfgStructure.getMethod().toString() + " -> " + "if Ins: " + cfgStructure.getControlInsIndex()
                    + " , T index : " + cfgStructure.getTDesIndex() + " , F index: " + cfgStructure.getFDesIndex());
        }
    }

    public List<CFGStructure> getCfgNodeList() {
        return cfgNodeList;
    }


    public CGGraph getCgGraph() {
        return cgGraph;
    }
}
