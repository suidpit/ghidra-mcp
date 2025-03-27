/*
* Copyright 2024 - 2024 the original author or authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* https://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.suidpit;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Service;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

@Service
public class GhidraService {
    private final GhidraMCPPlugin plugin;

    public GhidraService(GhidraMCPPlugin plugin) {
        this.plugin = plugin;
    }

    @Tool(description = "List all functions")
    public List<String> listFunctions() {
        var functionNames = new ArrayList<String>();
        for (Function function : plugin.getCurrentProgram()
                .getFunctionManager()
                .getFunctions(true)) {
            functionNames.add(function.getName());
        }
        return functionNames;
    }

    @Tool(description = "Get function address by name")
    public String getFunctionAddressByName(String name) {
        var functions = plugin.getCurrentProgram().getFunctionManager().getFunctions(true);
        for (Function function : functions) {
            if (function.getName().equals(name)) {
                return function.getEntryPoint().toString();
            }
        }
        return null;
    }


    private Function getFunctionByName(String name) {
        var functions = plugin.getCurrentProgram().getFunctionManager().getFunctions(true);
        for (Function function : functions) {
            if (function.getName().equals(name)) {
                return function;
            }
        }
        return null;
    }


    @Tool(description = "Decompile function by name")
    public String decompileFunctionByName(String name) {
        var function = getFunctionByName(name);
        if (function == null) {
            throw new IllegalArgumentException("Function not found");
        }
        var decompInterface = new DecompInterface();
        decompInterface.openProgram(plugin.getCurrentProgram());
        var decompiled = decompInterface.decompileFunction(function, 30, null);
        if (decompiled == null || !decompiled.decompileCompleted()) {
            Msg.error(plugin, "Decompilation failed");
            return null;
        }
        return decompiled.getDecompiledFunction().getC();
    }


    @Tool(description = "Rename function")
    public void renameFunction(String functionName, String newName) {
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = plugin.getCurrentProgram().startTransaction("Rename function");
                try {
                    var function = getFunctionByName(functionName);
                    if (function == null) {
                        throw new IllegalArgumentException("Function not found");
                    }
                    function.setName(newName, SourceType.USER_DEFINED);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(plugin, "Failed to rename function", e);
                } finally {
                    plugin.getCurrentProgram().endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(plugin, "Failed to rename function", e);
        }
        if (!success.get()) {
            Msg.error(plugin, "Failed to rename function");
        }
    }

    @Tool(description = "Add comment to function")
    public void addCommentToFunction(String functionName, String comment) {
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = plugin.getCurrentProgram().startTransaction("Add comment to function");
                try {
                    var function = getFunctionByName(functionName);
                    if (function == null) {
                        throw new IllegalArgumentException("Function not found");
                    }
                    function.setComment(comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(plugin, "Failed to add comment to function", e);
                } finally {
                    plugin.getCurrentProgram().endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(plugin, "Failed to add comment to function", e);
        }
        if (!success.get()) {
            Msg.error(plugin, "Failed to add comment to function");
        }
    }


    @Tool(description = "Rename local variable in function")
    public void renameLocalVariableInFunction(String functionName, String variableName,
            String newName) {
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = plugin.getCurrentProgram().startTransaction("Rename local variable in function");
                try {
                    var function = getFunctionByName(functionName);
                    if (function == null) {
                        throw new IllegalArgumentException("Function not found");
                    }
                    // In case I need to commit
                    for (Variable var : function.getAllVariables()) {
                        if (var.getName().equals(variableName)) {
                                var.setName(newName, SourceType.USER_DEFINED);
                                success.set(true);
                        }
                    }
                } catch (Exception e) {
                    Msg.error(plugin, "Failed to rename local variable in function", e);
                } finally {
                    plugin.getCurrentProgram().endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(plugin, "Failed to rename local variable in function", e);
        }
        if (!success.get()) {
            Msg.error(plugin, "Failed to rename local variable in function");
        }
    }
}