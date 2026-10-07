package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.auth.SigV4RequestValidator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Verifies the SigV4 signature in the {@code Authorization} header of every request outside S3
 * when {@code floci.auth.validate-signatures} is enabled, so a request signed with the wrong
 * secret is refused by SQS, KMS, IAM, Scheduler and the rest as it already is by S3.
 *
 * <p>The canonical request is rebuilt from the request as it arrived, following the rules every
 * AWS signer applies outside S3: the wire path with each segment URI-encoded a second time, the
 * canonical query string, the headers named in {@code SignedHeaders}, and the SHA-256 of the body.
 * The signature is derived with the key's secret and the service the credential scope names, and
 * the two are compared in constant time.
 *
 * <p>Runs after matching, on the worker thread a blocking resource method runs on, because hashing
 * the body is a blocking read that the I/O thread a pre-matching filter runs on does not allow. By
 * then pre-matching filters may have rewritten the request, so the path and query come from the
 * Vert.x request as it arrived rather than from {@code UriInfo}. The one body rewrite, the
 * {@code QueueUrl} that {@link SqsQueueUrlRouterFilter} appends to an SDK v1 Query call sent to a
 * queue URL, is reported by that filter and left out of the hash and the {@code content-length}.
 * The one header rewrite, the CBOR {@code Content-Type} that {@link AwsCborContentTypeFilter}
 * normalizes, is read back from the header that filter preserves it in.
 *
 * <p>Two signing names are left to the verifiers that already own them: S3 (and S3 Express),
 * which does not double-encode its path and declares its payload hash in a header, goes through
 * {@code S3HeaderSignatureFilter}; {@code execute-api} goes through
 * {@code ExecuteApiSigV4Authorizer}, which decides per method whether IAM auth applies at all.
 *
 * <p>As with S3, signature verification is authentication only, and an unsigned request is let
 * through: whether a caller may act is IAM enforcement's decision. Presigned query-string
 * signatures and SigV4a ({@code AWS4-ECDSA-P256-SHA256}) are not verified here.
 *
 * <p>Errors follow the protocol the request used: a Query request receives an
 * {@code <ErrorResponse>}, a CBOR request a CBOR body, and everything else JSON, which REST-JSON
 * clients read through {@code X-Amzn-Errortype}. The codes are AWS's: {@code IncompleteSignature}
 * for a header that cannot be checked, {@code InvalidClientTokenId} /
 * {@code UnrecognizedClientException} for an access key Floci does not know, and
 * {@code SignatureDoesNotMatch} / {@code InvalidSignatureException} for a signature that does not
 * verify or falls outside the fifteen-minute clock-skew window.
 *
 * <p>Nothing here runs with the flag off: the filter returns before reading a single header.
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
@ApplicationScoped
public class SigV4HeaderSignatureFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(SigV4HeaderSignatureFilter.class);

    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String TERMINATOR = "aws4_request";
    private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(15);
    private static final DateTimeFormatter AMZ_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    /** Signing names whose signatures another verifier owns; see the class comment. */
    private static final Set<String> VERIFIED_ELSEWHERE = Set.of("s3", "s3express", "execute-api");

    /** The well-known local-dev pair, honoured as every other SigV4 check in Floci honours it. */
    private static final String LEGACY_ACCESS_KEY_ID = "test";
    private static final String LEGACY_SECRET_KEY = "test";

    private static final String MISMATCH_MESSAGE = "The request signature we calculated does not match "
            + "the signature you provided. Check your AWS Secret Access Key and signing method. "
            + "Consult the service documentation for details.";
    private static final String INVALID_TOKEN_MESSAGE = "The security token included in the request is invalid.";

    // Lazily resolved: JAX-RS providers are instantiated before runtime config mappings exist
    // (the AwsProtocolClaimFilter pattern).
    private final jakarta.inject.Provider<EmulatorConfig> configProvider;
    private final IamService iamService;
    private final CurrentVertxRequest currentVertxRequest;

    @Inject
    public SigV4HeaderSignatureFilter(jakarta.inject.Provider<EmulatorConfig> configProvider,
                                      IamService iamService, CurrentVertxRequest currentVertxRequest) {
        this.configProvider = configProvider;
        this.iamService = iamService;
        this.currentVertxRequest = currentVertxRequest;
    }

    @Override
    public void filter(ContainerRequestContext ctx) throws IOException {
        if (!configProvider.get().auth().validateSignatures()) {
            return;
        }
        String authorization = ctx.getHeaderString("Authorization");
        if (authorization == null || !authorization.startsWith(ALGORITHM + " ")) {
            return;
        }

        String credential = component(authorization, "Credential");
        String signedHeaders = component(authorization, "SignedHeaders");
        String signature = component(authorization, "Signature");
        String[] scope = credential == null ? new String[0] : credential.split("/", -1);
        if (scope.length == 5 && VERIFIED_ELSEWHERE.contains(scope[3])) {
            return;
        }
        if (signedHeaders == null || signature == null || scope.length != 5 || !TERMINATOR.equals(scope[4])) {
            incompleteSignature(ctx, "Authorization header requires 'Credential' (in the form "
                    + "<access key>/<date>/<region>/<service>/aws4_request), 'SignedHeaders' and "
                    + "'Signature' parameters.");
            return;
        }
        String accessKeyId = scope[0];
        String scopeDate = scope[1];
        String region = scope[2];
        String service = scope[3];

        if (!SigV4RequestValidator.containsHeader(signedHeaders, "host")) {
            incompleteSignature(ctx, "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization.");
            return;
        }
        Instant requestTime = requestTime(ctx);
        if (requestTime == null) {
            incompleteSignature(ctx, "Authorization header requires existence of either a 'X-Amz-Date' "
                    + "or a 'Date' header.");
            return;
        }

        Optional<String> secretKey = resolveSecretKey(accessKeyId, ctx.getHeaderString("X-Amz-Security-Token"));
        if (secretKey.isEmpty()) {
            LOG.debugv("Refusing {0} request signed with unknown access key {1}",
                    service, SigV4RequestValidator.sanitizeForLog(accessKeyId));
            abort(ctx, 403, "InvalidClientTokenId", "UnrecognizedClientException", INVALID_TOKEN_MESSAGE);
            return;
        }

        String amzDate = AMZ_DATE.format(requestTime);
        Instant now = Instant.now();
        if (Duration.between(requestTime, now).abs().compareTo(MAX_CLOCK_SKEW) > 0) {
            signatureDoesNotMatch(ctx, "Signature expired: " + amzDate + " is outside the "
                    + MAX_CLOCK_SKEW.toMinutes() + " minute window around the server time "
                    + AMZ_DATE.format(now) + ".");
            return;
        }
        if (!amzDate.startsWith(scopeDate)) {
            signatureDoesNotMatch(ctx, "Date in Credential scope does not match YYYYMMDD from ISO-8601 "
                    + "version of date from HTTP: '" + scopeDate + "' != '" + amzDate.substring(0, 8) + "'.");
            return;
        }

        byte[] body = signedBody(ctx);
        HeaderLookup headers = name -> "content-length".equals(name)
                && ctx.getProperty(SqsQueueUrlRouterFilter.APPENDED_BODY_BYTES_PROPERTY) != null
                ? String.valueOf(body.length)
                : headerValue(ctx, name);
        boolean matches;
        try {
            matches = signatureMatches(ctx.getMethod(), rawPath(ctx), rawQuery(ctx), signedHeaders, headers, body,
                    secretKey.get(), amzDate, scopeDate, region, service, signature);
        } catch (Exception e) {
            LOG.debugv(e, "SigV4 verification failed to complete for accessKey={0}",
                    SigV4RequestValidator.sanitizeForLog(accessKeyId));
            matches = false;
        }
        if (!matches) {
            LOG.debugv("Refusing {0} request: signature mismatch for accessKey={1}",
                    service, SigV4RequestValidator.sanitizeForLog(accessKeyId));
            signatureDoesNotMatch(ctx, MISMATCH_MESSAGE);
        }
    }

    /** Reads one signed header's value; package-private so tests can drive the canonicalization. */
    interface HeaderLookup {
        String value(String lowercaseName);
    }

    /**
     * Whether {@code signature} is the one the secret produces for this request under any canonical
     * URI a signer could have produced for {@code rawPath}.
     */
    static boolean signatureMatches(String method, String rawPath, String rawQuery, String signedHeaders,
                                    HeaderLookup headers, byte[] body, String secretKey, String amzDate,
                                    String scopeDate, String region, String service,
                                    String signature) throws Exception {
        String canonicalQuery = canonicalQueryString(rawQuery);
        String canonicalHeaders = canonicalHeaders(signedHeaders, headers);
        String payloadHash = payloadHash(headers, signedHeaders, body);
        byte[] signingKey = SigV4RequestValidator.deriveSigningKey(secretKey, scopeDate, region, service);
        String credentialScope = scopeDate + "/" + region + "/" + service + "/" + TERMINATOR;
        for (String canonicalUri : canonicalUriCandidates(rawPath)) {
            String canonicalRequest = method + "\n"
                    + canonicalUri + "\n"
                    + canonicalQuery + "\n"
                    + canonicalHeaders + "\n"
                    + signedHeaders + "\n"
                    + payloadHash;
            String stringToSign = ALGORITHM + "\n"
                    + amzDate + "\n"
                    + credentialScope + "\n"
                    + SigV4RequestValidator.sha256Hex(canonicalRequest);
            String expected = SigV4RequestValidator.hexEncode(SigV4RequestValidator.hmacSha256(signingKey, stringToSign));
            if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    signature.getBytes(StandardCharsets.UTF_8))) {
                return true;
            }
        }
        return false;
    }

    /**
     * The canonical URIs a signer could have produced. Outside S3 every AWS SDK URI-encodes each
     * segment of the already-encoded wire path a second time, so {@code /functions/a%3Ab} is signed
     * as {@code /functions/a%253Ab}. The wire path itself is kept as a second candidate, as
     * {@code ExecuteApiSigV4Authorizer} keeps it, for a signer that encodes only once. For a path
     * without escapes the two are the same string.
     */
    static List<String> canonicalUriCandidates(String rawPath) {
        String raw = rawPath == null || rawPath.isEmpty() ? "/" : rawPath;
        StringBuilder doubleEncoded = new StringBuilder();
        String[] segments = raw.split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                doubleEncoded.append('/');
            }
            doubleEncoded.append(uriEncode(segments[i]));
        }
        String encoded = doubleEncoded.toString();
        return encoded.equals(raw) ? List.of(encoded) : List.of(encoded, raw);
    }

    static String canonicalQueryString(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            return "";
        }
        List<String[]> pairs = new ArrayList<>();
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int equals = pair.indexOf('=');
            String name = decode(equals >= 0 ? pair.substring(0, equals) : pair);
            String value = decode(equals >= 0 ? pair.substring(equals + 1) : "");
            pairs.add(new String[]{uriEncode(name), uriEncode(value)});
        }
        pairs.sort(Comparator.<String[], String>comparing(pair -> pair[0]).thenComparing(pair -> pair[1]));
        StringBuilder canonical = new StringBuilder();
        for (String[] pair : pairs) {
            if (!canonical.isEmpty()) {
                canonical.append('&');
            }
            canonical.append(pair[0]).append('=').append(pair[1]);
        }
        return canonical.toString();
    }

    private static String canonicalHeaders(String signedHeaders, HeaderLookup headers) {
        StringBuilder canonical = new StringBuilder();
        for (String name : signedHeaders.split(";")) {
            canonical.append(name).append(':')
                    .append(SigV4RequestValidator.normalizeHeaderValue(headers.value(name))).append('\n');
        }
        return canonical.toString();
    }

    /**
     * The body's own hash, never a declared {@code x-amz-content-sha256} digest taken on trust, so a
     * replaced body is a signature mismatch. A sentinel such as {@code UNSIGNED-PAYLOAD} is honoured
     * only when the header carrying it is itself signed, as {@code ExecuteApiSigV4Authorizer} does.
     */
    private static String payloadHash(HeaderLookup headers, String signedHeaders, byte[] body) throws Exception {
        String declared = headers.value("x-amz-content-sha256");
        if (declared != null && !declared.isBlank()
                && SigV4RequestValidator.containsHeader(signedHeaders, "x-amz-content-sha256")
                && !SigV4RequestValidator.isSha256Hex(declared.trim())) {
            return declared.trim();
        }
        return SigV4RequestValidator.sha256Hex(body);
    }

    /**
     * The path as the client sent it, before any filter rewrote it or JAX-RS normalized it. Falls
     * back to the request URI when no Vert.x request is current.
     */
    private String rawPath(ContainerRequestContext ctx) {
        HttpServerRequest request = vertxRequest();
        if (request != null && request.path() != null && !request.path().isEmpty()) {
            return request.path();
        }
        return ctx.getUriInfo().getRequestUri().getRawPath();
    }

    /** The query string as the client sent it, with the same fallback as {@link #rawPath}. */
    private String rawQuery(ContainerRequestContext ctx) {
        HttpServerRequest request = vertxRequest();
        if (request != null) {
            return request.query();
        }
        return ctx.getUriInfo().getRequestUri().getRawQuery();
    }

    private HttpServerRequest vertxRequest() {
        RoutingContext routingContext = currentVertxRequest != null ? currentVertxRequest.getCurrent() : null;
        return routingContext != null ? routingContext.request() : null;
    }

    /**
     * A signed header's value as the client sent it, repeated values joined with commas as SigV4
     * specifies. {@code content-type} is the one {@link AwsCborContentTypeFilter} replaced, when it
     * replaced it. {@code host} falls back to the request URI's authority for a request that carried
     * no {@code Host} header (HTTP/2, or HTTP/1.0 handled by {@link MissingHostHeaderFilter}).
     */
    private static String headerValue(ContainerRequestContext ctx, String name) {
        if ("content-type".equals(name)) {
            return SigV4RequestValidator.normalizeHeaderValue(requestContentType(ctx));
        }
        List<String> values = null;
        for (Map.Entry<String, List<String>> entry : ctx.getHeaders().entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                values = entry.getValue();
                break;
            }
        }
        if (values != null && !values.isEmpty()) {
            List<String> normalized = new ArrayList<>(values.size());
            for (String value : values) {
                normalized.add(SigV4RequestValidator.normalizeHeaderValue(value));
            }
            return String.join(",", normalized);
        }
        if ("host".equals(name)) {
            URI requestUri = ctx.getUriInfo().getRequestUri();
            return RequestHost.of(null, requestUri);
        }
        return "";
    }

    /**
     * Reads the body and hands an identical stream back to the request, returning the part the
     * client signed: all of it, less any bytes {@link SqsQueueUrlRouterFilter} appended. The stream
     * is read directly rather than gated on {@code hasEntity()}, which is false for a request
     * without a {@code Content-Type}.
     */
    private static byte[] signedBody(ContainerRequestContext ctx) throws IOException {
        InputStream entity = ctx.getEntityStream();
        byte[] body = entity != null ? entity.readAllBytes() : new byte[0];
        ctx.setEntityStream(new ByteArrayInputStream(body));
        if (ctx.getProperty(SqsQueueUrlRouterFilter.APPENDED_BODY_BYTES_PROPERTY) instanceof Integer appended
                && appended <= body.length) {
            return Arrays.copyOf(body, body.length - appended);
        }
        return body;
    }

    private Optional<String> resolveSecretKey(String accessKeyId, String sessionToken) {
        if (LEGACY_ACCESS_KEY_ID.equals(accessKeyId)) {
            return Optional.of(LEGACY_SECRET_KEY);
        }
        return iamService.findSecretKey(accessKeyId, sessionToken);
    }

    /**
     * The request timestamp the client signed: {@code x-amz-date} in ISO 8601 basic form, or the
     * HTTP {@code Date} header when the client signed that instead.
     */
    private static Instant requestTime(ContainerRequestContext ctx) {
        String amzDate = ctx.getHeaderString("x-amz-date");
        try {
            if (amzDate != null && !amzDate.isBlank()) {
                return Instant.from(AMZ_DATE.parse(amzDate.trim()));
            }
            String httpDate = ctx.getHeaderString("Date");
            if (httpDate != null && !httpDate.isBlank()) {
                return Instant.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(httpDate.trim()));
            }
        } catch (DateTimeParseException e) {
            return null;
        }
        return null;
    }

    /** The value of one {@code Name=value} component of a SigV4 {@code Authorization} header. */
    private static String component(String authorization, String name) {
        String parameters = authorization.substring(ALGORITHM.length() + 1);
        for (String part : parameters.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith(name + "=")) {
                String value = trimmed.substring(name.length() + 1).trim();
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }

    private static void incompleteSignature(ContainerRequestContext ctx, String message) {
        abort(ctx, 400, "IncompleteSignature", "IncompleteSignatureException", message);
    }

    private static void signatureDoesNotMatch(ContainerRequestContext ctx, String message) {
        abort(ctx, 403, "SignatureDoesNotMatch", "InvalidSignatureException", message);
    }

    /**
     * Refuses the request in the encoding it used. Query services name these failures without the
     * {@code Exception} suffix and JSON services with it, the split {@code IamEnforcementFilter}
     * already makes for an unknown key. The protocol is read from the request's content type, as
     * {@code AccountContextFilter} reads it: a REST request carries no claim that names it.
     */
    private static void abort(ContainerRequestContext ctx, int status, String queryCode, String jsonCode,
                              String message) {
        String contentType = requestContentType(ctx);
        if (isCbor(ctx, contentType)) {
            ctx.abortWith(CborErrorResponses.of(new AwsException(jsonCode, message, status),
                    CborErrorResponses.mediaTypeFor(contentType)));
            return;
        }
        if (isFormEncoded(ctx.getMediaType())) {
            ctx.abortWith(AwsQueryResponse.error(queryCode, message, null, status));
            return;
        }
        ctx.abortWith(AwsProtocolClaimFilter.errorResponse(status, jsonCode, message));
    }

    /** The {@code Content-Type} the client sent, before {@link AwsCborContentTypeFilter} normalized it. */
    private static String requestContentType(ContainerRequestContext ctx) {
        String original = ctx.getHeaderString(AwsCborContentTypeFilter.ORIGINAL_CONTENT_TYPE_HEADER);
        return original != null ? original : ctx.getHeaderString("Content-Type");
    }

    private static boolean isCbor(ContainerRequestContext ctx, String contentType) {
        return (contentType != null && contentType.toLowerCase().contains("cbor"))
                || "rpc-v2-cbor".equalsIgnoreCase(ctx.getHeaderString("smithy-protocol"));
    }

    private static boolean isFormEncoded(MediaType mediaType) {
        return mediaType != null
                && "application".equalsIgnoreCase(mediaType.getType())
                && "x-www-form-urlencoded".equalsIgnoreCase(mediaType.getSubtype());
    }

    private static String decode(String value) {
        return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    /** RFC 3986 percent-encoding as SigV4 defines it: {@code /} is escaped, {@code -._~} are not. */
    private static String uriEncode(String value) {
        StringBuilder encoded = new StringBuilder(value.length());
        for (byte raw : value.getBytes(StandardCharsets.UTF_8)) {
            int b = raw & 0xFF;
            char ch = (char) b;
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
                    || ch == '-' || ch == '.' || ch == '_' || ch == '~') {
                encoded.append(ch);
            } else {
                encoded.append('%')
                        .append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16)))
                        .append(Character.toUpperCase(Character.forDigit(b & 0xF, 16)));
            }
        }
        return encoded.toString();
    }
}
