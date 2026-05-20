package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager

@Suppress("unused")
class ExtensionBase : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server")

        val config = McpConfig(api.persistence().extensionData(), api.logging())
        applyBootstrapConfig(config, api)
        applyProxyBootstrapConfig(api)
        val serverManager = KtorServerManager(api)

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            config = config, providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        api.userInterface().registerSuiteTab("MCP", configUi.component)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()
            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }

    private fun applyBootstrapConfig(config: McpConfig, api: MontoyaApi) {
        readBootstrapValue("enabled")?.toBootstrapBoolean()?.let { config.enabled = it }
        readBootstrapValue("host")?.takeIf { it.isNotBlank() }?.let { config.host = it.trim() }
        readBootstrapValue("port")?.trim()?.toIntOrNull()?.let { port ->
            if (port in 1024..65535) {
                config.port = port
            } else {
                api.logging().logToError("Ignoring invalid MCP bootstrap port: $port")
            }
        }
        readBootstrapValue("config_editing_tooling")?.toBootstrapBoolean()?.let {
            config.configEditingTooling = it
        }
        readBootstrapValue("require_http_request_approval")?.toBootstrapBoolean()?.let {
            config.requireHttpRequestApproval = it
        }
        readBootstrapValue("require_history_access_approval")?.toBootstrapBoolean()?.let {
            config.requireHistoryAccessApproval = it
        }
        readBootstrapValue("auto_approve_targets")?.let { targets ->
            config.autoApproveTargets = targets.split(",", "\n")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .joinToString("\n")
        }

        api.logging().logToOutput("MCP bootstrap config: ${config.host}:${config.port}")
    }

    private fun applyProxyBootstrapConfig(api: MontoyaApi) {
        val port = readProxyBootstrapValue("port")?.trim()?.toIntOrNull() ?: return
        if (port !in 1024..65535) {
            api.logging().logToError("Ignoring invalid proxy bootstrap port: $port")
            return
        }

        val host = readProxyBootstrapValue("host")
            ?.trim()
            ?.takeIf { it.matches(Regex("[A-Za-z0-9._:-]+")) }
            ?: "127.0.0.1"
        val listenMode = readProxyBootstrapValue("listen_mode")
            ?.trim()
            ?.takeIf { it in setOf("loopback_only", "all_interfaces") }
            ?: "loopback_only"
        if (host != "127.0.0.1" && host != "localhost") {
            api.logging().logToError(
                "Proxy bootstrap host '$host' is not directly represented in Burp 2026.4 listener schema; using listen_mode=$listenMode"
            )
        }

        val proxyConfig = """
            {
              "proxy": {
                "request_listeners": [
                  {
                    "running": true,
                    "listener_port": $port,
                    "listen_mode": "$listenMode",
                    "certificate_mode": "per_host",
                    "enable_http2": true,
                    "use_custom_tls_protocols": false,
                    "custom_tls_protocols": []
                  }
                ],
                "intercept_client_requests": {
                  "automatically_fix_missing_or_superfluous_new_lines_at_end_of_request": true,
                  "automatically_update_content_length_header_when_the_request_is_edited": true,
                  "do_intercept": false,
                  "rules": []
                },
                "intercept_server_responses": {
                  "automatically_update_content_length_header_when_the_response_is_edited": true,
                  "do_intercept": false,
                  "rules": []
                }
              }
            }
        """.trimIndent()

        try {
            api.burpSuite().importProjectOptionsFromJson(proxyConfig)
            api.logging().logToOutput("Proxy bootstrap config requested: $host:$port")
            try {
                val exported = api.burpSuite().exportProjectOptionsAsJson("project_options.proxy")
                api.logging().logToOutput("Proxy bootstrap exported project_options.proxy: ${exported.take(2000)}")
            } catch (e: Exception) {
                api.logging().logToError("Proxy bootstrap export failed: ${e.message}")
            }
        } catch (e: Exception) {
            api.logging().logToError("Proxy bootstrap import failed: ${e.message}")
        }
    }

    private fun readBootstrapValue(name: String): String? {
        val propertyName = "pentest.burp.mcp.$name"
        val envName = "PENTEST_BURP_MCP_${name.uppercase()}"
        return System.getProperty(propertyName)?.takeIf { it.isNotBlank() }
            ?: System.getenv(envName)?.takeIf { it.isNotBlank() }
    }

    private fun readProxyBootstrapValue(name: String): String? {
        val propertyName = "pentest.burp.proxy.$name"
        val envName = "PENTEST_BURP_PROXY_${name.uppercase()}"
        return System.getProperty(propertyName)?.takeIf { it.isNotBlank() }
            ?: System.getenv(envName)?.takeIf { it.isNotBlank() }
    }

    private fun String.toBootstrapBoolean(): Boolean? = when (trim().lowercase()) {
        "true", "1", "yes", "y" -> true
        "false", "0", "no", "n" -> false
        else -> null
    }
}
