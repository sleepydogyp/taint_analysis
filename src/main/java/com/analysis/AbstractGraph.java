package com.analysis;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public abstract class AbstractGraph {

    public ArrayList<Object> vertexes = new ArrayList<Object>();  //存储顶点
    public HashMap<Integer, Set<Integer>> edges = new HashMap<Integer, Set<Integer>>();        // 存储边


    public void insertVertex(Object object){
        vertexes.add(object);
    }

    public void addEdge(int source, int des){
        if(edges.containsKey(source)){
            Set<Integer> desSet = edges.get(source);
            desSet.add(des);
        }else {
            Set<Integer> desSet = new HashSet<Integer>();
            desSet.add(des);
            edges.put(source, desSet);
        }
    }


    public int getVertexIndex(Object object){
        return vertexes.indexOf(object);
    }

    public Object getVertex(int index){
        if((index >= 0) && (index < vertexes.size())){
            return vertexes.get(index);
        }
        return null;
    }

    public abstract void outputG();
}
