package com.analysis.callgraph;


import com.analysis.AbstractGraph;
import patdroid.core.MethodInfo;

import java.util.*;

public class CGGraph extends AbstractGraph {

    public void outputG(){
        int size = vertexes.size();
        for(int i = 0; i < size; i ++){
            Set<Integer> desSet = edges.get(i);
            if(desSet != null){
                MethodInfo source = (MethodInfo) vertexes.get(i);
                for(Integer desIndex : desSet){
                    MethodInfo des = (MethodInfo) vertexes.get(desIndex);
                    System.out.println(source.toString() + " -> " + des.toString());
                }
            }
        }
    }

}
