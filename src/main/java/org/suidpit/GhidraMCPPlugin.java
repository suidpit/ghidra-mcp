/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.suidpit;

import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "MCP Plugin for Ghidra",
	description = "This plugin exposes many Ghidra functionalities – such as decompiling, disassembling, and renaming – to LLMs via the Model Context Protocol (MCP)"
)
//@formatter:on
public class GhidraMCPPlugin extends ProgramPlugin {

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();
		startMcpServer();
	}
	private void startMcpServer() {
		McpServerApplication.startServer(this);
	}


	@Override
	public void dispose() {
		McpServerApplication.stopServer();
		super.dispose();
	}
}
