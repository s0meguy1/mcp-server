package net.portswigger.mcp.schema

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable

private const val MAX_TEXT_FIELD_CHARS = 4_000
private const val MAX_HEADER_CHARS = 4_000
private const val MAX_BODY_PREVIEW_BYTES = 2_048
private const val MAX_MESSAGE_CHARS = 8_000

private fun boundedText(value: String?, maxChars: Int = MAX_TEXT_FIELD_CHARS): String? {
    if (value == null || value.length <= maxChars) {
        return value
    }
    return value.take(maxChars) + "... (truncated, ${value.length} chars total)"
}

private fun boundedHeaders(headers: List<HttpHeader>): String {
    return boundedText(headers.joinToString("\r\n") { it.toString() }, MAX_HEADER_CHARS) ?: ""
}

private fun boundedBody(message: HttpMessage?): String {
    val body = message?.body() ?: return ""
    val bodyLength = body.length()
    if (bodyLength <= 0) {
        return ""
    }

    val previewBytes = minOf(bodyLength, MAX_BODY_PREVIEW_BYTES)
    val preview = boundedText(body.subArray(0, previewBytes).toString(), MAX_BODY_PREVIEW_BYTES) ?: ""
    if (bodyLength <= MAX_BODY_PREVIEW_BYTES) {
        return preview
    }
    return preview + "\r\n... (truncated body, $bodyLength bytes total)"
}

private fun boundedRequest(request: HttpRequest?): String {
    if (request == null) {
        return "<no request>"
    }

    val message = try {
        val body = boundedBody(request)
        buildString {
            append(request.method())
            append(" ")
            append(request.path())
            append(" ")
            append(request.httpVersion())
            append("\r\n")
            append(boundedHeaders(request.headers()))
            append("\r\n\r\n")
            append(body)
        }
    } catch (_: Exception) {
        request.toString()
    }
    return boundedText(message, MAX_MESSAGE_CHARS) ?: ""
}

private fun boundedResponse(response: HttpResponse?): String {
    if (response == null) {
        return "<no response>"
    }

    val message = try {
        val reason = response.reasonPhrase().takeIf { it.isNotBlank() }
        val body = boundedBody(response)
        buildString {
            append(response.httpVersion())
            append(" ")
            append(response.statusCode())
            if (reason != null) {
                append(" ")
                append(reason)
            }
            append("\r\n")
            append(boundedHeaders(response.headers()))
            append("\r\n\r\n")
            append(body)
        }
    } catch (_: Exception) {
        response.toString()
    }
    return boundedText(message, MAX_MESSAGE_CHARS) ?: ""
}

fun AuditIssue.toSerializableForm(): IssueDetails {
    return IssueDetails(
        name = name(),
        detail = boundedText(detail()),
        remediation = boundedText(remediation()),
        httpService = HttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl(),
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().map { it.toSerializableForm() },
        collaboratorInteractions = collaboratorInteractions().map {
            Interaction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = AuditIssueDefinition(
            id = definition().name(),
            background = boundedText(definition().background()),
            remediation = boundedText(definition().remediation()),
            typeIndex = definition().typeIndex(),
        )
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = boundedRequest(request()),
        response = boundedResponse(response()),
        notes = annotations().notes()
    )
}

fun ProxyHttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = boundedRequest(request()),
        response = boundedResponse(response()),
        notes = annotations().notes()
    )
}

fun ProxyWebSocketMessage.toSerializableForm(): WebSocketMessage {
    return WebSocketMessage(
        payload = payload()?.toString() ?: "<no payload>",
        direction =
            if (direction() == Direction.CLIENT_TO_SERVER)
                WebSocketMessageDirection.CLIENT_TO_SERVER
            else
                WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes()
    )
}

@Serializable
data class IssueDetails(
    val name: String?,
    val detail: String?,
    val remediation: String?,
    val httpService: HttpService?,
    val baseUrl: String?,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val requestResponses: List<HttpRequestResponse>,
    val collaboratorInteractions: List<Interaction>,
    val definition: AuditIssueDefinition
)

@Serializable
data class HttpService(
    val host: String,
    val port: Int,
    val secure: Boolean
)

@Serializable
enum class AuditIssueSeverity {
    HIGH,
    MEDIUM,
    LOW,
    INFORMATION,
    FALSE_POSITIVE;
}

@Serializable
enum class AuditIssueConfidence {
    CERTAIN,
    FIRM,
    TENTATIVE
}

@Serializable
data class HttpRequestResponse(
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class Interaction(
    val interactionId: String,
    val timestamp: String
)

@Serializable
data class AuditIssueDefinition(
    val id: String,
    val background: String?,
    val remediation: String?,
    val typeIndex: Int
)


@Serializable
enum class WebSocketMessageDirection {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}

@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?
)

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null),
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = boundedRequest(it.requestResponse()?.request()),
                response = boundedResponse(it.requestResponse()?.response())
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = it.conversation()
            )
        }
    )
}

@Serializable
data class CollaboratorInteractionDetails(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String?,
    val dnsDetails: CollaboratorDnsDetails?,
    val httpDetails: CollaboratorHttpDetails?,
    val smtpDetails: CollaboratorSmtpDetails?
)

@Serializable
data class CollaboratorDnsDetails(
    val queryType: String
)

@Serializable
data class CollaboratorHttpDetails(
    val protocol: String,
    val request: String?,
    val response: String?
)

@Serializable
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String
)
