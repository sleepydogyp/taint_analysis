package com.analysis.callgraph;

import patdroid.core.ClassInfo;
import patdroid.core.MethodInfo;
import patdroid.core.Scope;
import patdroid.dalvik.Instruction;
import patdroid.dalvik.Invocation;

public class CGController {

    public void buildCG(Scope scope, CGGraph cgGraph) {
        long startTime = System.currentTimeMillis();
        System.out.println();
        // 1. 初始化顶点
        for (ClassInfo c : scope.getAllClasses()) {
            if (!c.isFrameworkClass()) {
                for (MethodInfo m : c.getAllMethods()) {
                    if (m.insns == null) continue;
                    cgGraph.insertVertex(m);
                }
            }
        }

        // 2. 遍历每一句话，添加边
        for (ClassInfo c : scope.getAllClasses()) {
            if (!c.isFrameworkClass()) {
                for (MethodInfo m : c.getAllMethods()) {
                    if (m.insns == null) continue;
                    int source = cgGraph.getVertexIndex(m);
                    if (source == -1) {
                        continue;
                    }
                    for (Instruction i : m.insns) {
                        if ("INVOKE".equals(i.getOP())) {
                            Invocation invoSt = (Invocation) i.extra;
                            int des = cgGraph.getVertexIndex(invoSt.target);
                            if (des == -1) {
                                continue;
                            }
                            cgGraph.addEdge(source, des);
                        }
                    }
                }
            }
        }
        long endTime = System.currentTimeMillis();
        System.out.println("buildCG cost time: " + endTime + " - " + startTime + " = " + (endTime - startTime));
    }





}
