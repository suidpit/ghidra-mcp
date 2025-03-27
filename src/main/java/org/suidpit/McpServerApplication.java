package org.suidpit;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;


@SpringBootApplication
public class McpServerApplication {
    private static ConfigurableApplicationContext context;
    private static GhidraMCPPlugin pluginInstance;

    public static void startServer(GhidraMCPPlugin plugin) {
        pluginInstance = plugin;
        context = SpringApplication.run(McpServerApplication.class, new String[] {});
    }

    @Bean
    public GhidraMCPPlugin ghidaMCPPlugin() {
        return pluginInstance;
    }

    @Bean
    public ToolCallbackProvider ghidraTools(GhidraService ghidraService) {
        return MethodToolCallbackProvider.builder().toolObjects(ghidraService).build();
    }

    public static void stopServer() {
        context.close();
    }
}