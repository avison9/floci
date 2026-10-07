package io.github.hectorvent.floci.testutil;

import io.restassured.filter.Filter;
import io.restassured.filter.FilterContext;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A RestAssured filter that header-signs a request for a service other than S3 the way an AWS SDK
 * does: each segment of the wire path URI-encoded a second time, no {@code x-amz-content-sha256}
 * header, and the body's SHA-256 as the payload hash. Signs {@code host}, {@code x-amz-date} and,
 * when present, {@code x-amz-security-token} and {@code x-amz-target}. {@code Content-Type} is
 * signed only on request ({@link #signingContentType()}), because RestAssured appends a charset to
 * text types after the filter runs.
 *
 * <p>Attach with {@code given().filter(AwsRequestSigner.signedAs("test", "test", "sqs"))}. The
 * {@code with*} methods return a copy that deliberately deviates for the rejection cases.
 */
public final class AwsRequestSigner implements Filter {

    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final DateTimeFormatter AMZ_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    private final String accessKeyId;
    private final String secretKey;
    private final String sessionToken;
    private final String service;
    private final Instant signedAt;
    private final boolean signContentType;

    private AwsRequestSigner(String accessKeyId, String secretKey, String sessionToken, String service,
                             Instant signedAt, boolean signContentType) {
        this.accessKeyId = accessKeyId;
        this.secretKey = secretKey;
        this.sessionToken = sessionToken;
        this.service = service;
        this.signedAt = signedAt;
        this.signContentType = signContentType;
    }

    public static AwsRequestSigner signedAs(String accessKeyId, String secretKey, String service) {
        return new AwsRequestSigner(accessKeyId, secretKey, null, service, null, false);
    }

    /** Signs as of a fixed instant instead of now; used to trip the clock-skew window. */
    public AwsRequestSigner signedAt(Instant instant) {
        return new AwsRequestSigner(accessKeyId, secretKey, sessionToken, service, instant, signContentType);
    }

    /** Signs with the same key but a different secret, as a client with a stale secret would. */
    public AwsRequestSigner withSecret(String otherSecret) {
        return new AwsRequestSigner(accessKeyId, otherSecret, sessionToken, service, signedAt, signContentType);
    }

    /** Also signs {@code content-type}, as the Java SDK and botocore do; for binary bodies only. */
    public AwsRequestSigner signingContentType() {
        return new AwsRequestSigner(accessKeyId, secretKey, sessionToken, service, signedAt, true);
    }

    @Override
    public Response filter(FilterableRequestSpecification request,
                           FilterableResponseSpecification response, FilterContext ctx) {
        try {
            sign(request);
        } catch (Exception e) {
            throw new IllegalStateException("could not sign the request", e);
        }
        return ctx.next(request, response);
    }

    private void sign(FilterableRequestSpecification request) throws Exception {
        URI uri = URI.create(request.getURI());
        String amzDate = AMZ_DATE.format(signedAt != null ? signedAt : Instant.now());
        String scopeDate = amzDate.substring(0, 8);
        String host = uri.getPort() > 0 && uri.getPort() != 80 && uri.getPort() != 443
                ? uri.getHost() + ":" + uri.getPort()
                : uri.getHost();

        List<String[]> headers = new ArrayList<>();
        if (signContentType) {
            headers.add(new String[]{"content-type", request.getContentType()});
        }
        headers.add(new String[]{"host", host});
        headers.add(new String[]{"x-amz-date", amzDate});
        if (sessionToken != null) {
            headers.add(new String[]{"x-amz-security-token", sessionToken});
        }
        String target = request.getHeaders().getValue("X-Amz-Target");
        if (target != null) {
            headers.add(new String[]{"x-amz-target", target});
        }
        String signedHeaders = headers.stream().map(h -> h[0]).collect(Collectors.joining(";"));
        String canonicalHeaders = headers.stream().map(h -> h[0] + ":" + h[1] + "\n").collect(Collectors.joining());

        String canonicalRequest = request.getMethod() + "\n"
                + doubleEncodedPath(uri.getRawPath()) + "\n"
                + S3RequestSigner.canonicalQueryString(uri.getRawQuery()) + "\n"
                + canonicalHeaders + "\n"
                + signedHeaders + "\n"
                + sha256Hex(bodyBytes(request.getBody()));
        String credentialScope = scopeDate + "/us-east-1/" + service + "/aws4_request";
        String stringToSign = ALGORITHM + "\n" + amzDate + "\n" + credentialScope + "\n"
                + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

        byte[] key = hmacSha256(("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8), scopeDate);
        key = hmacSha256(key, "us-east-1");
        key = hmacSha256(key, service);
        key = hmacSha256(key, "aws4_request");
        String signature = hexEncode(hmacSha256(key, stringToSign));

        request.header("X-Amz-Date", amzDate);
        if (sessionToken != null) {
            request.header("X-Amz-Security-Token", sessionToken);
        }
        request.header("Authorization", ALGORITHM + " Credential=" + accessKeyId + "/" + credentialScope
                + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature);
    }

    private static String doubleEncodedPath(String rawPath) {
        String path = rawPath == null || rawPath.isEmpty() ? "/" : rawPath;
        String[] segments = path.split("/", -1);
        StringBuilder encoded = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                encoded.append('/');
            }
            encoded.append(S3RequestSigner.uriEncode(segments[i]));
        }
        return encoded.toString();
    }

    private static byte[] bodyBytes(Object body) {
        if (body == null) {
            return new byte[0];
        }
        if (body instanceof byte[] bytes) {
            return bytes;
        }
        if (body instanceof String text) {
            return text.getBytes(StandardCharsets.UTF_8);
        }
        throw new IllegalArgumentException("unsupported body type " + body.getClass().getName());
    }

    private static byte[] hmacSha256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(byte[] input) throws Exception {
        return hexEncode(MessageDigest.getInstance("SHA-256").digest(input));
    }

    private static String hexEncode(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
