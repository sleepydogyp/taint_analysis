package com.analysis.taint;

import com.alibaba.fastjson.JSONObject;
import com.analysis.core.ClassInfo;
import com.analysis.dalvik.Instruction;

public class Element {

    String methodFullName = "";
    Instruction insn;
    int insnIndex = 0;


    public String getMethodFullName() {
        return methodFullName;
    }

    public void setMethodFullName(String methodFullName) {
        this.methodFullName = methodFullName;
    }

    public Instruction getInsn() {
        return insn;
    }

    public void setInsn(Instruction insn) {
        this.insn = insn;
    }

    public int getInsnIndex() {
        return insnIndex;
    }

    public void setInsnIndex(int insnIndex) {
        this.insnIndex = insnIndex;
    }


    public Element parseElement(String str){
        Element element = new Element();
        String[] tmps = str.split("->");
        if(tmps.length != 3){
            return null;
        }
        element.methodFullName = tmps[0];
        JSONObject instJSON = JSONObject.parseObject(tmps[1]);
        Instruction instruction = new Instruction();
        instruction.opcode = instJSON.getByte("opcode");
        instruction.opcode_aux = instJSON.getByte("opcode_aux");
        instruction.rdst = instJSON.getShort("rdst");
        instruction.r0 = instJSON.getShort("r0");
        instruction.r1 = instJSON.getShort("r1");
        instruction.type = (ClassInfo)instJSON.get("type");
        instruction.extra = instJSON.get("extra");
        element.insn = instruction;
        element.insnIndex = Integer.getInteger(tmps[2]);
        return element;
    }

    public String toString(){
        return methodFullName + " -> " + insn.toString() + " -> index: " + insnIndex;
    }

}
