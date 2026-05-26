package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
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

private const val MAX_INVENTORY_ITEMS = 100
private const val MAX_INVENTORY_SAMPLE_REFERENCES = 5
private const val DEFAULT_LOOKUP_BODY_BYTES = 4096
private const val MAX_LOOKUP_BODY_BYTES = 20_000

private val sensitiveHeaderNames = setOf(
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
)

private val sensitiveParameterNames = setOf(
    "password",
    "pass",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "api_key",
    "apikey",
)

private val staticExtensions = setOf(
    "css",
    "js",
    "mjs",
    "map",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "svg",
    "ico",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "otf",
    "mp3",
    "mp4",
    "webm",
    "avi",
    "mov",
    "pdf",
)

private fun <T> safeValue(block: () -> T?): T? = try {
    block()
} catch (_: Exception) {
    null
}

private data class ObservedExchange(
    val reference: String,
    val source: String,
    val request: HttpRequest?,
    val response: HttpResponse?,
    val method: String,
    val url: String,
    val path: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
)

private fun requestedInventorySources(source: String): Set<String> {
    return when (source.trim().lowercase()) {
        "proxy", "proxy_history", "history" -> setOf("proxy_history")
        "site", "site_map", "sitemap" -> setOf("site_map")
        else -> setOf("proxy_history", "site_map")
    }
}

private fun collectObservedExchanges(api: MontoyaApi, source: String): List<ObservedExchange> {
    val sources = requestedInventorySources(source)
    val exchanges = mutableListOf<ObservedExchange>()
    if ("proxy_history" in sources) {
        safeValue { api.proxy().history() }.orEmpty().forEach { item ->
            val request = safeValue { item.request() }
            val response = safeValue { item.response() }
            exchanges.add(
                ObservedExchange(
                    reference = "proxy:${safeValue { item.id() } ?: exchanges.size}",
                    source = "proxy_history",
                    request = request,
                    response = response,
                    method = safeValue { item.method() } ?: safeValue { request?.method() } ?: "",
                    url = safeValue { item.url() } ?: safeValue { request?.url() } ?: "",
                    path = safeValue { item.path() } ?: safeValue { request?.pathWithoutQuery() } ?: "",
                    host = safeValue { item.host() } ?: safeValue { request?.httpService()?.host() } ?: "",
                    port = safeValue { item.port() } ?: safeValue { request?.httpService()?.port() } ?: 0,
                    secure = safeValue { item.secure() } ?: safeValue { request?.httpService()?.secure() } ?: false,
                )
            )
        }
    }
    if ("site_map" in sources) {
        safeValue { api.siteMap().requestResponses() }.orEmpty().forEachIndexed { index, item ->
            val request = safeValue { item.request() }
            val response = safeValue { item.response() }
            val service = safeValue { item.httpService() } ?: safeValue { request?.httpService() }
            exchanges.add(
                ObservedExchange(
                    reference = "site:$index",
                    source = "site_map",
                    request = request,
                    response = response,
                    method = safeValue { request?.method() } ?: "",
                    url = safeValue { item.url() } ?: safeValue { request?.url() } ?: "",
                    path = safeValue { request?.pathWithoutQuery() } ?: safeValue { request?.path() } ?: "",
                    host = safeValue { service?.host() } ?: "",
                    port = safeValue { service?.port() } ?: 0,
                    secure = safeValue { service?.secure() } ?: false,
                )
            )
        }
    }
    return exchanges
}

private fun matchesInventoryFilters(
    exchange: ObservedExchange,
    query: String?,
    regex: String?,
    methods: List<String>,
): Boolean {
    val methodSet = methods.map { it.uppercase() }.filter { it.isNotBlank() }.toSet()
    if (methodSet.isNotEmpty() && exchange.method.uppercase() !in methodSet) {
        return false
    }
    val haystack = buildString {
        append(exchange.method).append('\n')
        append(exchange.url).append('\n')
        append(exchange.path).append('\n')
        append(exchange.host).append('\n')
        append(parameterSummaries(exchange.request).joinToString("\n") { "${it.location}:${it.name}" })
        append('\n')
        append(contentType(exchange.response).orEmpty())
        append('\n')
        append(statusCode(exchange.response)?.toString().orEmpty())
    }
    val queryText = query?.trim()?.lowercase().orEmpty()
    if (queryText.isNotBlank() && !haystack.lowercase().contains(queryText)) {
        return false
    }
    if (!regex.isNullOrBlank() && !Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(haystack).find()) {
        return false
    }
    return true
}

private fun isStaticExchange(exchange: ObservedExchange): Boolean {
    val extension = safeValue { exchange.request?.fileExtension() }
        ?: exchange.path.substringAfterLast('.', missingDelimiterValue = "")
    if (extension.lowercase() in staticExtensions) {
        return true
    }
    val mime = safeValue { exchange.response?.mimeType()?.name }?.lowercase().orEmpty()
    return mime in setOf(
        "css",
        "script",
        "image_unknown",
        "image_jpeg",
        "image_gif",
        "image_png",
        "image_bmp",
        "image_tiff",
        "image_svg_xml",
        "font_woff",
        "font_woff2",
        "sound",
        "video",
    )
}

private fun endpointInventory(
    api: MontoyaApi,
    params: GetBurpEndpointInventory,
): EndpointInventoryResponse {
    val includeStatic = params.includeStatic
    val groups = linkedMapOf<String, EndpointInventoryItem>()
    for (exchange in collectObservedExchanges(api, params.source)) {
        if (exchange.url.isBlank() || exchange.method.isBlank()) continue
        if (!includeStatic && isStaticExchange(exchange)) continue
        if (!matchesInventoryFilters(exchange, params.query, params.regex, params.methods)) continue
        val pathTemplate = templatePath(exchange.path.ifBlank { pathFromUrl(exchange.url) })
        val key = listOf(exchange.method.uppercase(), exchange.host, exchange.port, exchange.secure, pathTemplate).joinToString("|")
        val existing = groups[key]
        val parameters = parameterSummaries(exchange.request)
        val next = if (existing == null) {
            EndpointInventoryItem(
                method = exchange.method.uppercase(),
                pathTemplate = pathTemplate,
                exampleUrl = inventoryExampleUrl(exchange.url, pathTemplate),
                host = exchange.host,
                port = exchange.port,
                secure = exchange.secure,
                sources = listOf(exchange.source),
                observedCount = 1,
                sampleReferences = listOf(exchange.reference),
                statusCodes = statusCode(exchange.response)?.let { listOf(it) }.orEmpty(),
                contentTypes = contentType(exchange.response)?.let { listOf(it) }.orEmpty(),
                queryParameters = parameters.filter { it.location == "URL" }.map { it.name }.distinct().sorted(),
                bodyParameters = parameters.filter { it.location != "URL" && it.location != "COOKIE" }.map { it.name }.distinct().sorted(),
                cookieParameters = parameters.filter { it.location == "COOKIE" }.map { it.name }.distinct().sorted(),
                requestHeaderNames = headerNames(safeValue { exchange.request?.headers() }).sorted(),
                responseHeaderNames = headerNames(safeValue { exchange.response?.headers() }).sorted(),
                hasRequestBody = bodyLength(exchange.request) > 0,
                hasResponseBody = bodyLength(exchange.response) > 0,
            )
        } else {
            existing.merge(exchange, parameters)
        }
        groups[key] = next
    }

    val items = groups.values
        .sortedWith(compareByDescending<EndpointInventoryItem> { it.observedCount }.thenBy { it.pathTemplate }.thenBy { it.method })
    val offset = params.offset.coerceAtLeast(0)
    val count = params.count.coerceIn(1, MAX_INVENTORY_ITEMS)
    return EndpointInventoryResponse(
        source = params.source,
        query = params.query,
        regex = params.regex,
        total = items.size,
        offset = offset,
        returned = items.drop(offset).take(count).size,
        items = items.drop(offset).take(count),
        note = "Compact endpoint inventory only. Use sampleReferences with get_burp_request_response_by_id for selected raw evidence.",
    )
}

private fun parameterInventory(
    api: MontoyaApi,
    params: GetBurpParameterInventory,
): ParameterInventoryResponse {
    val groups = linkedMapOf<String, ParameterInventoryItem>()
    for (exchange in collectObservedExchanges(api, params.source)) {
        if (exchange.url.isBlank() || exchange.method.isBlank()) continue
        if (!params.includeStatic && isStaticExchange(exchange)) continue
        if (!matchesInventoryFilters(exchange, params.query, params.regex, params.methods)) continue
        val pathTemplate = templatePath(exchange.path.ifBlank { pathFromUrl(exchange.url) })
        for (parameter in parameterSummaries(exchange.request)) {
            if (parameter.location == "COOKIE" && !params.includeCookies) continue
            val key = listOf(exchange.method.uppercase(), pathTemplate, parameter.location, parameter.name).joinToString("|")
            val existing = groups[key]
            groups[key] = if (existing == null) {
                ParameterInventoryItem(
                    name = parameter.name,
                    location = parameter.location,
                    method = exchange.method.uppercase(),
                    pathTemplate = pathTemplate,
                    exampleUrl = inventoryExampleUrl(exchange.url, pathTemplate),
                    sources = listOf(exchange.source),
                    observedCount = 1,
                    sampleReferences = listOf(exchange.reference),
                    valueShape = parameter.valueShape,
                    sensitiveName = parameter.name.lowercase() in sensitiveParameterNames,
                )
            } else {
                existing.merge(exchange, parameter)
            }
        }
    }
    val items = groups.values
        .sortedWith(compareByDescending<ParameterInventoryItem> { it.observedCount }.thenBy { it.pathTemplate }.thenBy { it.name })
    val offset = params.offset.coerceAtLeast(0)
    val count = params.count.coerceIn(1, MAX_INVENTORY_ITEMS)
    return ParameterInventoryResponse(
        source = params.source,
        query = params.query,
        regex = params.regex,
        total = items.size,
        offset = offset,
        returned = items.drop(offset).take(count).size,
        items = items.drop(offset).take(count),
        note = "Parameter names and value shapes only; raw values are intentionally omitted.",
    )
}

private fun findExchangeByReference(api: MontoyaApi, reference: String): ObservedExchange? {
    val trimmed = reference.trim()
    val source = trimmed.substringBefore(":", missingDelimiterValue = "").lowercase()
    val idText = trimmed.substringAfter(":", missingDelimiterValue = "")
    if (source == "proxy") {
        val id = idText.toIntOrNull() ?: return null
        return collectObservedExchanges(api, "proxy_history").firstOrNull { it.reference == "proxy:$id" }
    }
    if (source == "site") {
        val index = idText.toIntOrNull() ?: return null
        return collectObservedExchanges(api, "site_map").firstOrNull { it.reference == "site:$index" }
    }
    return null
}

private fun requestResponseLookup(
    api: MontoyaApi,
    params: GetBurpRequestResponseById,
): RequestResponseLookup {
    val exchange = findExchangeByReference(api, params.reference)
    if (exchange == null) {
        return RequestResponseLookup(
            reference = params.reference,
            source = null,
            found = false,
            request = null,
            response = null,
            note = "Reference not found. Use sampleReferences from get_burp_endpoint_inventory or get_burp_parameter_inventory.",
        )
    }
    val bodyMode = when (params.bodyMode.trim().lowercase()) {
        "none", "metadata" -> "metadata"
        "full" -> "full"
        else -> "preview"
    }
    val maxBodyBytes = params.maxBodyBytes.coerceIn(0, MAX_LOOKUP_BODY_BYTES)
        .takeIf { it > 0 } ?: DEFAULT_LOOKUP_BODY_BYTES
    return RequestResponseLookup(
        reference = exchange.reference,
        source = exchange.source,
        found = true,
        request = httpRequestEvidence(exchange.request, bodyMode, maxBodyBytes),
        response = httpResponseEvidence(exchange.response, bodyMode, maxBodyBytes),
        note = "Auth/cookie-like header values are redacted. Bodies are bounded by maxBodyBytes.",
    )
}

private fun EndpointInventoryItem.merge(
    exchange: ObservedExchange,
    parameters: List<ParameterSummary>,
): EndpointInventoryItem {
    return copy(
        sources = (sources + exchange.source).distinct().sorted(),
        observedCount = observedCount + 1,
        sampleReferences = (sampleReferences + exchange.reference).distinct().take(MAX_INVENTORY_SAMPLE_REFERENCES),
        statusCodes = (statusCodes + statusCode(exchange.response)).filterNotNull().distinct().sorted(),
        contentTypes = (contentTypes + contentType(exchange.response)).filterNotNull().distinct().sorted(),
        queryParameters = (queryParameters + parameters.filter { it.location == "URL" }.map { it.name }).distinct().sorted(),
        bodyParameters = (bodyParameters + parameters.filter { it.location != "URL" && it.location != "COOKIE" }.map { it.name }).distinct().sorted(),
        cookieParameters = (cookieParameters + parameters.filter { it.location == "COOKIE" }.map { it.name }).distinct().sorted(),
        requestHeaderNames = (requestHeaderNames + headerNames(safeValue { exchange.request?.headers() })).distinct().sorted(),
        responseHeaderNames = (responseHeaderNames + headerNames(safeValue { exchange.response?.headers() })).distinct().sorted(),
        hasRequestBody = hasRequestBody || bodyLength(exchange.request) > 0,
        hasResponseBody = hasResponseBody || bodyLength(exchange.response) > 0,
    )
}

private fun ParameterInventoryItem.merge(
    exchange: ObservedExchange,
    parameter: ParameterSummary,
): ParameterInventoryItem {
    return copy(
        sources = (sources + exchange.source).distinct().sorted(),
        observedCount = observedCount + 1,
        sampleReferences = (sampleReferences + exchange.reference).distinct().take(MAX_INVENTORY_SAMPLE_REFERENCES),
        valueShape = listOf(valueShape, parameter.valueShape).filter { it.isNotBlank() }.distinct().joinToString("|"),
        sensitiveName = sensitiveName || parameter.name.lowercase() in sensitiveParameterNames,
    )
}

private fun statusCode(response: HttpResponse?): Int? = safeValue { response?.statusCode()?.toInt() }

private fun contentType(response: HttpResponse?): String? {
    return safeValue { response?.headerValue("Content-Type") }
        ?: safeValue { response?.mimeType()?.name }
}

private fun bodyLength(message: burp.api.montoya.http.message.HttpMessage?): Int {
    return safeValue { message?.body()?.length() } ?: 0
}

private fun headerNames(headers: List<HttpHeader>?): List<String> {
    return headers.orEmpty()
        .mapNotNull { safeValue { it.name() }?.takeIf { name -> name.isNotBlank() } }
        .distinct()
        .take(80)
}

private fun redactedHeaders(headers: List<HttpHeader>?): Map<String, String> {
    return headers.orEmpty().take(80).mapNotNull { header ->
        val name = safeValue { header.name() } ?: return@mapNotNull null
        val value = safeValue { header.value() }.orEmpty()
        name to if (name.lowercase() in sensitiveHeaderNames) "[REDACTED]" else value.take(500)
    }.toMap()
}

private data class ParameterSummary(
    val name: String,
    val location: String,
    val valueShape: String,
)

private fun parameterSummaries(request: HttpRequest?): List<ParameterSummary> {
    val parsed = safeValue { request?.parameters() }.orEmpty()
        .mapNotNull { parameterSummary(it) }
    if (parsed.isNotEmpty()) {
        return parsed.distinctBy { "${it.location}:${it.name}" }
    }
    return queryParameterNamesFromUrl(safeValue { request?.url() }.orEmpty())
        .map { ParameterSummary(it, "URL", "unknown") }
}

private fun parameterSummary(parameter: ParsedHttpParameter): ParameterSummary? {
    val name = safeValue { parameter.name() }?.takeIf { it.isNotBlank() } ?: return null
    val location = safeValue { parameter.type().name } ?: "UNKNOWN"
    val value = safeValue { parameter.value() }.orEmpty()
    return ParameterSummary(
        name = name,
        location = location,
        valueShape = valueShape(value),
    )
}

private fun queryParameterNamesFromUrl(url: String): List<String> {
    val query = url.substringAfter('?', missingDelimiterValue = "")
    if (query.isBlank()) return emptyList()
    return query.split("&")
        .mapNotNull { part -> part.substringBefore("=", missingDelimiterValue = "").takeIf { it.isNotBlank() } }
        .distinct()
}

private fun valueShape(value: String): String {
    if (value.isBlank()) return "empty"
    if (value.length > 120) return "long_text"
    if (value.matches(Regex("-?\\d+(\\.\\d+)?"))) return "number"
    if (value.equals("true", true) || value.equals("false", true)) return "boolean"
    if (value.matches(Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*"))) return "jwt_like"
    if (value.matches(Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"))) return "uuid"
    if (value.contains("@") && value.length <= 120) return "email_like"
    return "short_text"
}

private fun pathFromUrl(url: String): String {
    return try {
        URI(url).rawPath?.takeIf { it.isNotBlank() } ?: "/"
    } catch (_: Exception) {
        url.substringAfter("://", url).substringAfter("/", "/").substringBefore("?").let { if (it.startsWith("/")) it else "/$it" }
    }
}

private fun inventoryExampleUrl(url: String, pathTemplate: String): String {
    return try {
        val uri = URI(url)
        val scheme = uri.scheme ?: return pathTemplate
        val authority = uri.rawAuthority?.substringAfter("@") ?: return pathTemplate
        "$scheme://$authority$pathTemplate"
    } catch (_: Exception) {
        pathTemplate
    }
}

private fun templatePath(path: String): String {
    val normalized = if (path.isBlank()) "/" else path.substringBefore("?")
    return normalized.split("/").joinToString("/") { segment ->
        when {
            segment.isBlank() -> segment
            segment.matches(Regex("\\d+")) -> "{int}"
            segment.matches(Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) -> "{uuid}"
            segment.length >= 16 && segment.matches(Regex("[0-9a-fA-F]+")) -> "{hex}"
            segment.length >= 24 && segment.matches(Regex("[A-Za-z0-9_-]+")) -> "{token}"
            else -> segment
        }
    }.ifBlank { "/" }
}

private fun httpRequestEvidence(
    request: HttpRequest?,
    bodyMode: String,
    maxBodyBytes: Int,
): HttpMessageEvidence? {
    if (request == null) return null
    val bodyBytes = bodyLength(request)
    val bodyPreview = if (bodyMode == "metadata") null else boundedBodyPreview(request, maxBodyBytes)
    return HttpMessageEvidence(
        startLine = listOfNotNull(
            safeValue { request.method() },
            safeValue { request.path() },
            safeValue { request.httpVersion() },
        ).joinToString(" ").takeIf { it.isNotBlank() },
        url = safeValue { request.url() },
        statusCode = null,
        headers = redactedHeaders(safeValue { request.headers() }),
        headerNames = headerNames(safeValue { request.headers() }),
        bodyBytes = bodyBytes,
        bodyPreview = bodyPreview,
        bodyTruncated = bodyMode != "metadata" && bodyBytes > maxBodyBytes,
    )
}

private fun httpResponseEvidence(
    response: HttpResponse?,
    bodyMode: String,
    maxBodyBytes: Int,
): HttpMessageEvidence? {
    if (response == null) return null
    val bodyBytes = bodyLength(response)
    val status = statusCode(response)
    val reason = safeValue { response.reasonPhrase() }.orEmpty()
    val bodyPreview = if (bodyMode == "metadata") null else boundedBodyPreview(response, maxBodyBytes)
    return HttpMessageEvidence(
        startLine = listOfNotNull(
            safeValue { response.httpVersion() },
            status?.toString(),
            reason.takeIf { it.isNotBlank() },
        ).joinToString(" ").takeIf { it.isNotBlank() },
        url = null,
        statusCode = status,
        headers = redactedHeaders(safeValue { response.headers() }),
        headerNames = headerNames(safeValue { response.headers() }),
        bodyBytes = bodyBytes,
        bodyPreview = bodyPreview,
        bodyTruncated = bodyMode != "metadata" && bodyBytes > maxBodyBytes,
    )
}

private fun boundedBodyPreview(
    message: burp.api.montoya.http.message.HttpMessage,
    maxBodyBytes: Int,
): String {
    val body = safeValue { message.body() } ?: return ""
    val length = safeValue { body.length() } ?: return ""
    if (length <= 0) return ""
    val previewBytes = minOf(length, maxBodyBytes)
    val preview = safeValue { body.subArray(0, previewBytes).toString() }.orEmpty()
    return redactSecretLikeText(preview.take(maxBodyBytes))
}

private fun redactSecretLikeText(value: String): String {
    return value
        .replace(Regex("(?i)(password|pass|passwd|token|access_token|refresh_token|id_token|secret|api_key|apikey)([\"'\\s:=]+)([^&\\s\"'}]+)")) {
            "${it.groupValues[1]}${it.groupValues[2]}[REDACTED]"
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

        mcpTool<GetBurpEndpointInventory>(
            "Returns compact grouped endpoint inventory from Burp proxy history and/or site map. " +
                "Use this before raw history reads to discover routes, status codes, content types, parameters, and sampleReferences."
        ) {
            if ("proxy_history" in requestedInventorySources(source)) {
                val allowed = runBlocking {
                    checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP endpoint inventory")
                }
                if (!allowed) {
                    return@mcpTool "HTTP history access denied by Burp Suite"
                }
            }
            Json.encodeToString(endpointInventory(api, this))
        }

        mcpTool<GetBurpParameterInventory>(
            "Returns compact grouped parameter inventory from Burp proxy history and/or site map. " +
                "Values are never returned; use sampleReferences with get_burp_request_response_by_id for selected evidence."
        ) {
            if ("proxy_history" in requestedInventorySources(source)) {
                val allowed = runBlocking {
                    checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP parameter inventory")
                }
                if (!allowed) {
                    return@mcpTool "HTTP history access denied by Burp Suite"
                }
            }
            Json.encodeToString(parameterInventory(api, this))
        }

        mcpTool<GetBurpRequestResponseById>(
            "Returns one bounded request/response selected by reference, such as proxy:123 or site:7. " +
                "Use metadata or preview first; request full only for final evidence."
        ) {
            if (reference.trim().lowercase().startsWith("proxy:")) {
                val allowed = runBlocking {
                    checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP request/response lookup")
                }
                if (!allowed) {
                    return@mcpTool "HTTP history access denied by Burp Suite"
                }
            }
            Json.encodeToString(requestResponseLookup(api, this))
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
data class GetBurpEndpointInventory(
    val count: Int = 50,
    val offset: Int = 0,
    val source: String = "all",
    val query: String? = null,
    val regex: String? = null,
    val methods: List<String> = emptyList(),
    val includeStatic: Boolean = false,
)

@Serializable
data class GetBurpParameterInventory(
    val count: Int = 50,
    val offset: Int = 0,
    val source: String = "all",
    val query: String? = null,
    val regex: String? = null,
    val methods: List<String> = emptyList(),
    val includeStatic: Boolean = false,
    val includeCookies: Boolean = false,
)

@Serializable
data class GetBurpRequestResponseById(
    val reference: String,
    val bodyMode: String = "preview",
    val maxBodyBytes: Int = DEFAULT_LOOKUP_BODY_BYTES,
)

@Serializable
data class EndpointInventoryResponse(
    val source: String,
    val query: String?,
    val regex: String?,
    val total: Int,
    val offset: Int,
    val returned: Int,
    val items: List<EndpointInventoryItem>,
    val note: String,
)

@Serializable
data class EndpointInventoryItem(
    val method: String,
    val pathTemplate: String,
    val exampleUrl: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val sources: List<String>,
    val observedCount: Int,
    val sampleReferences: List<String>,
    val statusCodes: List<Int> = emptyList(),
    val contentTypes: List<String> = emptyList(),
    val queryParameters: List<String> = emptyList(),
    val bodyParameters: List<String> = emptyList(),
    val cookieParameters: List<String> = emptyList(),
    val requestHeaderNames: List<String> = emptyList(),
    val responseHeaderNames: List<String> = emptyList(),
    val hasRequestBody: Boolean = false,
    val hasResponseBody: Boolean = false,
)

@Serializable
data class ParameterInventoryResponse(
    val source: String,
    val query: String?,
    val regex: String?,
    val total: Int,
    val offset: Int,
    val returned: Int,
    val items: List<ParameterInventoryItem>,
    val note: String,
)

@Serializable
data class ParameterInventoryItem(
    val name: String,
    val location: String,
    val method: String,
    val pathTemplate: String,
    val exampleUrl: String,
    val sources: List<String>,
    val observedCount: Int,
    val sampleReferences: List<String>,
    val valueShape: String,
    val sensitiveName: Boolean = false,
)

@Serializable
data class RequestResponseLookup(
    val reference: String,
    val source: String?,
    val found: Boolean,
    val request: HttpMessageEvidence?,
    val response: HttpMessageEvidence?,
    val note: String,
)

@Serializable
data class HttpMessageEvidence(
    val startLine: String?,
    val url: String?,
    val statusCode: Int?,
    val headers: Map<String, String>,
    val headerNames: List<String>,
    val bodyBytes: Int,
    val bodyPreview: String?,
    val bodyTruncated: Boolean,
)

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
