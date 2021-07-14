package com.analysis.controlFlowGraph;

import patdroid.core.MethodInfo;

public class CFGStructure {

    MethodInfo method;        // 方法全称

    int controlInsIndex;   //控制语句在方法中的索引

    int TDesIndex;   //判断结果为true,跳转目标语句索引

    int FDesIndex;    // 判断结果为false,跳转目标语句索引

    public CFGStructure(MethodInfo method, int controlInsIndex, int TDesIndex, int FDesIndex){
        this.method = method;
        this.controlInsIndex = controlInsIndex;
        this.TDesIndex = TDesIndex;
        this.FDesIndex = FDesIndex;
    }

    public MethodInfo getMethod() {
        return method;
    }

    public int getControlInsIndex() {
        return controlInsIndex;
    }

    public int getTDesIndex() {
        return TDesIndex;
    }

    public int getFDesIndex() {
        return FDesIndex;
    }
}
