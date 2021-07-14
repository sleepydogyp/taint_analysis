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
*   Lu Gong
*/

package patdroid.core;

import java.lang.reflect.Modifier;

import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkState;

/**
 * The class representation. Each class is uniquely identified by its full name.
 * So given a class full name, there is exactly one ClassInfo representing it.
 * ClassInfo works in a late-bind manner with ClassDetail.
 * A ClassInfo could just refer to a type without any details about its methods, fields, etc.
 * Then later on, when the class details become available, a ClassDetail iobject is created and
 * attached to the ClassInfo.
 * <p>
 * ClassInfos are obtained by find-series functions not created by constructors.
 */
public final class ClassInfo {

    private static final Logger logger = LoggerFactory.getLogger(ClassInfo.class);

    private static final ClassDetail MISSING_DETAIL = new ClassDetail.Builder().build();
    public final FullMethodSignature STATIC_INITIALIZER;
    public final FullMethodSignature DEFAULT_CONSTRUCTOR;

    public final Scope scope;
    public final String fullName;
    public ClassDetail mutableDetail = MISSING_DETAIL;

    /**
     * @param scope the scope that this ClassInfo belongs to
     * @param fullName the full name of the class
     */
    public ClassInfo(Scope scope, String fullName) {
        this.scope = scope;
        this.fullName = fullName;
        this.DEFAULT_CONSTRUCTOR = new FullMethodSignature(scope.primitiveVoid, MethodInfo.CONSTRUCTOR, this);
        this.STATIC_INITIALIZER = new FullMethodSignature(scope.primitiveVoid, MethodInfo.STATIC_INITIALIZER);
    }

    /**
     * A framework class is a class that is not found in the apk being parsed
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @return if the class is a framework class
     */
    public boolean isFrameworkClass() {
        return mutableDetail.isFrameworkClass;
    }

    /**
     * Sometimes the apk has missing classes. A missing class is not
     * a framework class and cannot be found in the apk
     * @return if this class is missing
     */
    public boolean isMissing() {
        return mutableDetail == MISSING_DETAIL;
    }

    /**
     * Get the type of a non-static field. This functions will look into the base class.
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @param fieldName the name of the field.
     * @return the type, or null if not found or the class is missing
     */
    public ClassInfo getFieldType(String fieldName) {
        return mutableDetail.getFieldType(fieldName);
    }

    /**
     * Get the type of a static field. This functions might look into its base class.
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @param fieldName the name of the static field
     * @return the type of the static field, or null if not found or the class is missing
     */
    public ClassInfo getStaticFieldType(String fieldName) {
        return mutableDetail.getStaticFieldType(fieldName);
    }

    /**
     * Get all the fields declared in this class.
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @return a key-value store mapping field name to their types
     */
    public ImmutableMap<String, ClassInfo> getAllFieldsHere() {
        return mutableDetail.fields;
    }

    /**
     * Get all the static fields declared in this class.
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @return a key-value store mapping static field name to their types
     */
    public ImmutableMap<String, ClassInfo> getAllStaticFieldsHere() {
        return mutableDetail.staticFields;
    }

    /**
     *
     * @return all methods in the class
     */
    public ImmutableCollection<MethodInfo> getAllMethods() {
        return mutableDetail.methods.values();
    }

    /**
     * Find a method declared in this class
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @param signature the method signature
     * @return the method in this class, or null if not found or the class is missing
     */
    public MethodInfo findMethodHere(FullMethodSignature signature) {
        return mutableDetail.methods.get(signature);
    }

    /**
     * Find all methods that have the give name and are declared in this class
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @param name the method name
     * @return an array of methods, or null if the class is missing.
     * An empty array will be returned in case of not finding any method
     */
    public MethodInfo[] findMethodsHere(String name) {
        return mutableDetail.findMethodsHere(name);
    }

    /**
     * Find all methods that have the give name. This might need to look into base classes
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @param name the method name
     * @return an array of methods, or null if the class is missing.
     * An empty array will be returned in case of not finding any method
     */
    public MethodInfo[] findMethods(String name) {
        return mutableDetail.findMethods(name);
    }

    /**
     * Find a method with given function prototype. This might need to look into base classes
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @param signature the method signature
     * @return  the method representation, or null if not found or the class is missing
     */
    public MethodInfo findMethod(FullMethodSignature signature) {
        return mutableDetail.findMethod(signature);
    }

    /**
     * TypeA is convertible to TypeB if and only if TypeB is an indirect
     * base type or an indirect interface of TypeA.
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @param type type B
     * @return if this class can be converted to the other.
     */
    public boolean isConvertibleTo(ClassInfo type) {
        if (type.isPrimitive()) {
            return (type == scope.primitiveVoid || isPrimitive());
        } else {
            return mutableDetail.isConvertibleTo(type);
        }
    }

    @Override
    public String toString() {
        return fullName;
    }

    /**
     * @return if this class is an array type
     */
    public boolean isArray() {
        return fullName.startsWith("[");
    }

    /**
     * Return the element type given this class as an array type.
     * @return the element type
     */
    public ClassInfo getElementClass() {
        checkState(isArray(), "Try getting the element class of a non-array class " + this);
        final char first = fullName.charAt(1);
        switch (first) {
        case 'C': return scope.primitiveChar;
        case 'I': return scope.primitiveInt;
        case 'B': return scope.primitiveByte;
        case 'Z': return scope.primitiveBoolean;
        case 'F': return scope.primitiveFloat;
        case 'D': return scope.primitiveDouble;
        case 'S': return scope.primitiveShort;
        case 'J': return scope.primitiveLong;
        case 'V': return scope.primitiveVoid;
        case 'L': return scope.findOrCreateClass(fullName.substring(2, fullName.length() - 1));
        case '[': return scope.findOrCreateClass(fullName.substring(1));
        default:
            logger.error("unknown element type for:" + fullName);
            return null;
        }
    }

    /**
     *
     * <b>Note:</b> this might cause class loading if the class is not loaded yet
     * @return the base type, or null if this class is java.lang.Object
     */
    public ClassInfo getBaseType() {
        return mutableDetail.baseType;
    }

    /**
     * Get the interfaces that the current class implements
     * @return interfaces
     */
    public ImmutableList<ClassInfo> getInterfaces() { return mutableDetail.interfaces; }

    /**
     * Change the super class of this class to a new super class, the
     * derivedClasses will be updated accordingly.
     * @param baseType new super class for this class
     */
    public void setBaseType(ClassInfo baseType) {
        ClassDetail origDetails = mutableDetail;
        origDetails.removeDerivedClasses(this);
        mutableDetail = origDetails.changeBaseType(baseType);
        mutableDetail.updateDerivedClasses(this);
    }

    /**
     * @return if this class is an inner class
     */
    public boolean isInnerClass() {
        return fullName.lastIndexOf('$') != -1;
    }

    /**
     * @return the outer class
     */
    public ClassInfo getOuterClass() {
        checkState(isInnerClass(), "Try getting the outer class from a non-inner class" + this);
        return scope.findOrCreateClass(fullName.substring(0, fullName.lastIndexOf('$')));
    }

    /**
     * @return true if the class is a primitive type
     */
    public boolean isPrimitive() {
        return scope.primitives.contains(this);
    }

    /**
     * @return if the class is final
     */
    public boolean isFinal() {
        return Modifier.isFinal(mutableDetail.accessFlags);
    }

    /**
     * @return if the class is an interface
     */
    public boolean isInterface() {
        return Modifier.isInterface(mutableDetail.accessFlags);
    }

    public boolean isAbstract() {
        return Modifier.isAbstract(mutableDetail.accessFlags);
    }

    /**
     * Get the default constructor
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @return the default constructor, or null if not found
     */
    public MethodInfo getDefaultConstructor() {
        return findMethodHere(DEFAULT_CONSTRUCTOR);
    }

    /**
     * Find the static initializer method of the class
     * <p>
     * <b>Note:</b> this might start class loading if the class is not loaded yet
     * @return the static initializer or null if not found
     */
    public MethodInfo getStaticInitializer() {
        return findMethod(STATIC_INITIALIZER);
    }

    /**
     * Get the short name of the class. The short name is the part after the last
     * '.' in the full name of the class
     * @return the short name
     */
    public String getShortName() {
        final int idx = fullName.lastIndexOf('.');
        if (idx == -1) {
            return fullName;
        } else {
            return fullName.substring(idx+1, fullName.length());
        }
    }

    /**
     * An almost final class has no derived classes in the current class tree
     * @return if a class is "almost final"
     */
    public boolean isAlmostFinal() {
        return mutableDetail.derivedClasses.isEmpty();
    }
}
