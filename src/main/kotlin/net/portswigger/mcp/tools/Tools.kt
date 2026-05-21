package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.ScanTask
import burp.api.montoya.scanner.audit.Audit
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import java.awt.KeyboardFocusManager
import java.net.URI
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {
    val scannerTasks = ConcurrentHashMap<String, ScannerTaskRecord>()

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
            orderedPseudoHeaderNames.forEach { name ->
                val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                if (value != null) {
                    put(name, value)
                }
            }

            pseudoHeaders.forEach { (key, value) ->
                val properKey = if (key.startsWith(":")) key else ":$key"
                if (!containsKey(properKey)) {
                    put(properKey, value)
                }
            }
        }

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    mcpTool<GetCookieJar>(
        "Returns Burp cookie-jar entries. Values are sensitive; callers must redact before storing or showing them."
    ) {
        val allowed = runBlocking {
            HistoryAccessSecurity.checkHistoryAccessPermission(HistoryAccessType.HTTP_HISTORY, config)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP cookie jar access denied")
            return@mcpTool "Cookie jar access denied by Burp Suite"
        }

        val boundedOffset = offset.coerceAtLeast(0)
        val boundedCount = count.coerceIn(1, 500)
        val cookieEntries = api.http().cookieJar().cookies()
            .drop(boundedOffset)
            .take(boundedCount)
            .map { cookie ->
                CookieJarEntry(
                    name = cookie.name(),
                    value = cookie.value(),
                    domain = cookie.domain() ?: "",
                    path = cookie.path() ?: "",
                    expiration = cookie.expiration().map { it.toString() }.orElse(null),
                )
            }
        Json.encodeToString(cookieEntries)
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        mcpTool<StartBurpCrawl>(
            "Starts a scoped Burp Scanner crawl for the supplied seed URLs. Use get_burp_scan_task_status to poll the returned taskId."
        ) {
            val validSeeds = seedUrls.map { it.trim() }.filter { it.isNotBlank() }.distinct()
            if (validSeeds.isEmpty()) {
                return@mcpTool "No seed URLs supplied"
            }

            validSeeds.forEach { seedUrl ->
                val seedRequest = requestPreviewFromUrl(seedUrl)
                val allowed = runBlocking {
                    HttpRequestSecurity.checkHttpRequestPermission(
                        seedRequest.host,
                        seedRequest.port,
                        config,
                        seedRequest.rawRequest,
                        api
                    )
                }
                if (!allowed) {
                    api.logging().logToOutput("MCP crawl denied: $seedUrl")
                    return@mcpTool "Start crawl denied by Burp Suite for seed URL: $seedUrl"
                }
            }

            api.burpSuite().taskExecutionEngine().state = RUNNING
            val crawl = api.scanner().startCrawl(buildCrawlConfiguration(validSeeds))
            val taskId = scannerTasks.register("crawl", taskName, validSeeds, crawl)
            Json.encodeToString(scannerTasks.status(taskId)!!)
        }

        mcpTool<StartBurpAudit>(
            "Starts a Burp Scanner audit and adds the supplied in-scope raw HTTP requests. Use get_burp_scan_task_status to poll the returned taskId."
        ) {
            val validRequests = requests.filter { it.content.isNotBlank() }.take(20)
            if (validRequests.isEmpty()) {
                return@mcpTool "No audit requests supplied"
            }

            validRequests.forEach { requestSpec ->
                val allowed = runBlocking {
                    HttpRequestSecurity.checkHttpRequestPermission(
                        requestSpec.targetHostname,
                        requestSpec.targetPort,
                        config,
                        requestSpec.content,
                        api
                    )
                }
                if (!allowed) {
                    api.logging().logToOutput("MCP audit denied: ${requestSpec.targetHostname}:${requestSpec.targetPort}")
                    return@mcpTool "Start audit denied by Burp Suite for target: ${requestSpec.targetHostname}:${requestSpec.targetPort}"
                }
            }

            api.burpSuite().taskExecutionEngine().state = RUNNING
            val audit = api.scanner().startAudit(buildAuditConfiguration(auditConfiguration.toBuiltInAuditConfiguration()))
            validRequests.forEach { requestSpec ->
                val fixedContent = requestSpec.content.replace("\r", "").replace("\n", "\r\n")
                audit.addRequest(HttpRequest.httpRequest(requestSpec.toMontoyaService(), fixedContent))
            }

            val taskId = scannerTasks.register(
                "audit",
                taskName,
                validRequests.map { "${if (it.usesHttps) "https" else "http"}://${it.targetHostname}:${it.targetPort}" },
                audit
            )
            Json.encodeToString(scannerTasks.status(taskId)!!)
        }

        mcpTool<GetBurpScanTaskStatus>(
            "Returns status for one Burp crawl/audit task started by this MCP server, or all tracked scan tasks when taskId is omitted."
        ) {
            if (taskId.isNullOrBlank()) {
                Json.encodeToString(scannerTasks.statuses())
            } else {
                scannerTasks.status(taskId)
                    ?.let { Json.encodeToString(it) }
                    ?: "Unknown Burp scan task: $taskId"
            }
        }

        mcpTool<DeleteBurpScanTask>("Deletes a tracked Burp crawl/audit task by taskId.") {
            val deleted = scannerTasks.delete(taskId)
            if (deleted) {
                "Deleted Burp scan task: $taskId"
            } else {
                "Unknown Burp scan task: $taskId"
            }
        }

        mcpPaginatedTool<GetSiteMapRequestResponses>("Displays request/response pairs from Burp's site map") {
            val compiledRegex = regex?.takeIf { it.isNotBlank() }?.let { Pattern.compile(it) }
            api.siteMap().requestResponses().asSequence()
                .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
                .filter { item -> compiledRegex?.matcher(item)?.find() ?: true }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class GetCookieJar(
    val count: Int = 200,
    val offset: Int = 0
)

@Serializable
data class CookieJarEntry(
    val name: String,
    val value: String,
    val domain: String,
    val path: String,
    val expiration: String? = null
)

@Serializable
data class StartBurpCrawl(
    val seedUrls: List<String>,
    val taskName: String? = null
)

@Serializable
data class AuditRequest(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class StartBurpAudit(
    val requests: List<AuditRequest>,
    val auditConfiguration: String = "active",
    val taskName: String? = null
)

@Serializable
data class GetBurpScanTaskStatus(val taskId: String? = null)

@Serializable
data class DeleteBurpScanTask(val taskId: String)

@Serializable
data class GetSiteMapRequestResponses(
    override val count: Int,
    override val offset: Int,
    val regex: String? = null
) : Paginated

@Serializable
data class ScannerTaskStatus(
    val taskId: String,
    val taskName: String?,
    val taskType: String,
    val createdAt: String,
    val seedOrTargetCount: Int,
    val requestCount: Int,
    val errorCount: Int,
    val statusMessage: String,
    val insertionPointCount: Int? = null,
    val issueCount: Int? = null,
    val issues: List<net.portswigger.mcp.schema.IssueDetails>? = null,
)

private data class ScannerTaskRecord(
    val taskId: String,
    val taskName: String?,
    val taskType: String,
    val createdAt: String,
    val seedsOrTargets: List<String>,
    val task: ScanTask,
)

private fun ConcurrentHashMap<String, ScannerTaskRecord>.register(
    taskType: String,
    taskName: String?,
    seedsOrTargets: List<String>,
    task: ScanTask,
): String {
    val taskId = UUID.randomUUID().toString()
    this[taskId] = ScannerTaskRecord(
        taskId = taskId,
        taskName = taskName,
        taskType = taskType,
        createdAt = Instant.now().toString(),
        seedsOrTargets = seedsOrTargets,
        task = task,
    )
    return taskId
}

private fun ConcurrentHashMap<String, ScannerTaskRecord>.statuses(): List<ScannerTaskStatus> {
    return values.sortedBy { it.createdAt }.map { it.toStatus() }
}

private fun ConcurrentHashMap<String, ScannerTaskRecord>.status(taskId: String): ScannerTaskStatus? {
    return this[taskId]?.toStatus()
}

private fun ConcurrentHashMap<String, ScannerTaskRecord>.delete(taskId: String): Boolean {
    val record = remove(taskId) ?: return false
    record.task.delete()
    return true
}

private fun ScannerTaskRecord.toStatus(): ScannerTaskStatus {
    val audit = task as? Audit
    return ScannerTaskStatus(
        taskId = taskId,
        taskName = taskName,
        taskType = taskType,
        createdAt = createdAt,
        seedOrTargetCount = seedsOrTargets.size,
        requestCount = task.requestCount(),
        errorCount = task.errorCount(),
        statusMessage = task.statusMessage(),
        insertionPointCount = audit?.insertionPointCount(),
        issueCount = audit?.issues()?.size,
        issues = audit?.issues()?.map { it.toSerializableForm() },
    )
}

private data class SeedRequestPreview(
    val host: String,
    val port: Int,
    val rawRequest: String,
)

private fun requestPreviewFromUrl(seedUrl: String): SeedRequestPreview {
    val uri = URI(seedUrl)
    val scheme = uri.scheme?.lowercase()
    require(scheme == "http" || scheme == "https") { "seedUrl must be absolute http(s): $seedUrl" }
    val host = requireNotNull(uri.host) { "seedUrl host is required: $seedUrl" }
    val port = if (uri.port > 0) uri.port else if (scheme == "https") 443 else 80
    val path = buildString {
        append(if (uri.rawPath.isNullOrBlank()) "/" else uri.rawPath)
        if (!uri.rawQuery.isNullOrBlank()) {
            append("?")
            append(uri.rawQuery)
        }
    }
    return SeedRequestPreview(
        host = host,
        port = port,
        rawRequest = "GET $path HTTP/1.1\r\nHost: $host\r\n\r\n",
    )
}

private fun buildCrawlConfiguration(seedUrls: List<String>): CrawlConfiguration {
    return try {
        CrawlConfiguration.crawlConfiguration(*seedUrls.toTypedArray())
    } catch (_: NullPointerException) {
        object : CrawlConfiguration {
            override fun seedUrls(): List<String> = seedUrls
        }
    }
}

private fun buildAuditConfiguration(configuration: BuiltInAuditConfiguration): AuditConfiguration {
    return try {
        AuditConfiguration.auditConfiguration(configuration)
    } catch (_: NullPointerException) {
        object : AuditConfiguration {}
    }
}

private fun String.toBuiltInAuditConfiguration(): BuiltInAuditConfiguration {
    return when (lowercase()) {
        "passive", "legacy_passive_audit_checks" -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
        else -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
    }
}

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
