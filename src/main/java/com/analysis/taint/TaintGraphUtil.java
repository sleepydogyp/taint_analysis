package com.analysis.taint;

import com.analysis.AbstractGraph;
import com.analysis.dalvik.Instruction;

import java.util.ArrayList;
import java.util.List;


public class TaintGraphUtil {


    public static void addElement(ArrayList<Element> taintGraph, String methodFullName, Instruction inst, int insnIndex) {
        Element element = new Element();
        element.setMethodFullName(methodFullName);
        element.setInsn(inst);
        element.setInsnIndex(insnIndex);
        taintGraph.add(element);
    }

    public static void outputTaintG(List<ArrayList<Element>> taintGraphs) {
        for (ArrayList<Element> taintGraph : taintGraphs) {
            System.out.println("-------------------");
            for (Element eleObj : taintGraph) {
                System.out.println(eleObj.toString());
            }
        }
    }
}
