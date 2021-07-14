/*
* Copyright 2014 Mingyuan Xia (http://mxia.me) and contributors
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* Contributors:
*   Mingyuan Xia
*/

package com.analysis.permission;

import com.analysis.core.*;
import com.google.common.collect.ImmutableList;

import java.io.*;

/**
 * A parser for the output file of PScout from UToronto.
 * See http://pscout.csl.toronto.edu/ for more details
 */
public class PScoutParser {
    private final Scope scope;

    private PScoutParser(Scope scope) {
        this.scope = scope;
    }

    public APIMapping parse(File f) throws IOException {
        final APIMapping r = new APIMapping();
        final BufferedReader br = new BufferedReader(new FileReader(f));
        String perm = "", line = br.readLine();
        while (line != null) {
            perm = line.replace("Permission:", "");
            br.readLine(); // skip a line telling how many callers in total
            do {
                line = br.readLine();
                if (line == null || !line.startsWith("<")) {
                    break;
                }
                MethodInfo m = parseMethod(line);
                r.add(m, perm);
            } while (true);
        }
        br.close();
        return r;
    }

    private MethodInfo parseMethod(String line) {
        // example: <android.net.wifi.WifiManager: boolean reassociate()>
        String className, returnType, methodName;
        String[] paramTypes;
        String s = line.substring(1, line.length() - 1);
        String[] a = s.split(":"); // class, rest
        className = a[0];
        s = a[1];
        int pos = s.indexOf('(');
        a[0] = s.substring(0, pos); // ret methodName
        a[1] = s.substring(pos + 1, s.length() - 1); // params
        returnType = a[0].trim().split(" ")[0];
        methodName = a[0].trim().split(" ")[1];
        paramTypes = a[1].replace(" ", "").split(",");
        final MethodSignature signature = new MethodSignature(methodName, findOrCreateClasses(paramTypes));
        ClassInfo ci = scope.findOrCreateClass(className);
        return (ci == null ? null : ci.findMethod(new FullMethodSignature(findOrCreateClass(returnType), signature)));
    }

    /**
     * Convert PSCout-style type name to canonical form
     *
     * @param t PSCout-style type name
     * @return a ClassInfo
     */
    private ClassInfo findOrCreateClass(String t) {
        if (!t.endsWith("[]")) {
            return scope.findOrCreateClass(t);
        } else {
            String baseType = t.substring(0, t.indexOf("[]"));
            int level = (t.length() - t.indexOf("[]")) / 2;
            String s = "";
            for (int i = 0; i < level; ++i)
                s += "[";
            // TODO: map all primitive types to short form
            if (baseType.equals("int"))
                s += "I";
            else if (baseType.equals("boolean"))
                s += "B";
            else
                s += "L" + baseType + ";";
            return scope.findOrCreateClass(s);
        }
    }

    public ImmutableList<ClassInfo> findOrCreateClasses(String[] fullNames) {
        ImmutableList.Builder<ClassInfo> builder = ImmutableList.builder();
        for (String fullName : fullNames) {
            builder.add(findOrCreateClass(fullName));
        }
        return builder.build();
    }
}
