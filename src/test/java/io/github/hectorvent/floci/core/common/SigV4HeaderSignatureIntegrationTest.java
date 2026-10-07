package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testing.ValidateSignaturesProfile;
import io.github.hectorvent.floci.testutil.AwsRequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.xml.XmlPath;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.time.Duration;
import java.time.Instant;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

/**
 * {@code floci.auth.validate-signatures} authenticates every header-signed request, not only S3's:
 * a request signed with the wrong secret is refused in the error vocabulary of the protocol it
 * used, a request signed with the right one is served, and an unsigned request is left alone.
 * Shares {@link ValidateSignaturesProfile} with the S3 signature tests.
 */
@QuarkusTest
@TestProfile(ValidateSignaturesProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SigV4HeaderSignatureIntegrationTest {

    private static final String QUEUE = "validate-signatures-queue";
    private static final String JSON_1_0 = "application/x-amz-json-1.0";
    private static final String JSON_1_1 = "application/x-amz-json-1.1";
    private static final String FORM = "application/x-www-form-urlencoded";
    private static final String CBOR_1_1 = "application/x-amz-cbor-1.1";

    private static String userAccessKeyId;
    private static String userSecretKey;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    @Order(1)
    void jsonRequestWithTheRightSecretIsServed() {
        given()
            .filter(AwsRequestSigner.signedAs("test", "test", "sqs"))
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.CreateQueue")
            .body("{\"QueueName\":\"" + QUEUE + "\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("QueueUrl", containsString(QUEUE));
    }

    @Test
    @Order(2)
    void jsonRequestWithTheWrongSecretIsRefused() {
        given()
            .filter(AwsRequestSigner.signedAs("test", "not-the-secret", "sqs"))
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.ListQueues")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .body("__type", equalTo("InvalidSignatureException"));

        given()
            .filter(AwsRequestSigner.signedAs("test", "not-the-secret", "kms"))
            .contentType(JSON_1_1)
            .header("X-Amz-Target", "TrentService.ListKeys")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .body("__type", equalTo("InvalidSignatureException"));
    }

    @Test
    @Order(3)
    void queryRequestWithTheWrongSecretIsRefusedInXml() {
        given()
            .filter(AwsRequestSigner.signedAs("test", "test", "iam"))
            .contentType(FORM)
            .body("Action=ListUsers&Version=2010-05-08")
        .when()
            .post("/")
        .then()
            .statusCode(200);

        given()
            .filter(AwsRequestSigner.signedAs("test", "not-the-secret", "iam"))
            .contentType(FORM)
            .body("Action=ListUsers&Version=2010-05-08")
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .body("ErrorResponse.Error.Code", equalTo("SignatureDoesNotMatch"));
    }

    @Test
    @Order(4)
    void restJsonRequestWithTheWrongSecretIsRefusedThroughTheErrorTypeHeader() {
        given()
            .filter(AwsRequestSigner.signedAs("test", "test", "scheduler"))
        .when()
            .get("/schedule-groups")
        .then()
            .statusCode(200);

        given()
            .filter(AwsRequestSigner.signedAs("test", "not-the-secret", "scheduler"))
        .when()
            .get("/schedule-groups")
        .then()
            .statusCode(403)
            .header("X-Amzn-Errortype", equalTo("InvalidSignatureException"));
    }

    @Test
    @Order(5)
    void pathWithEscapesVerifiesDoubleEncoded() {
        // A signature over the double-encoded ARN gets past authentication to Lambda's own 404.
        given()
            .filter(AwsRequestSigner.signedAs("test", "test", "lambda"))
            .urlEncodingEnabled(false)
        .when()
            .get("/2015-03-31/functions/arn%3Aaws%3Alambda%3Aus-east-1%3A000000000000%3Afunction%3Amissing")
        .then()
            .statusCode(404);
    }

    @Test
    @Order(6)
    void queueUrlPathIsVerifiedBeforeItIsRewritten() {
        // An SDK v1 Query call posts to the queue URL; the router rewrites the path to / and
        // appends QueueUrl to the body, neither of which the client signed.
        given()
            .filter(AwsRequestSigner.signedAs("test", "test", "sqs"))
            .contentType(FORM)
            .body("Action=GetQueueAttributes&AttributeName.1=All&Version=2012-11-05")
        .when()
            .post("/000000000000/" + QUEUE)
        .then()
            .statusCode(200);
    }

    @Test
    @Order(7)
    void cborContentTypeIsVerifiedAsTheClientSentIt() {
        // AwsCborContentTypeFilter rewrites application/x-amz-cbor-1.1 before matching; the client
        // signed the original. An empty CBOR map is the single byte 0xA0.
        byte[] emptyMap = {(byte) 0xA0};
        given()
            .filter(AwsRequestSigner.signedAs("test", "test", "kinesis").signingContentType())
            .contentType(CBOR_1_1)
            .header("X-Amz-Target", "Kinesis_20131202.ListStreams")
            .body(emptyMap)
        .when()
            .post("/")
        .then()
            .statusCode(200);

        given()
            .filter(AwsRequestSigner.signedAs("test", "not-the-secret", "kinesis").signingContentType())
            .contentType(CBOR_1_1)
            .header("X-Amz-Target", "Kinesis_20131202.ListStreams")
            .body(emptyMap)
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .contentType(containsString("cbor"))
            .header("x-amzn-query-error", startsWith("InvalidSignatureException"));
    }

    @Test
    @Order(8)
    void unknownAccessKeyIsRefused() {
        given()
            .filter(AwsRequestSigner.signedAs("AKIAUNKNOWNACCESSKEY", "some-secret", "sqs"))
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.ListQueues")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .body("__type", equalTo("UnrecognizedClientException"));

        given()
            .filter(AwsRequestSigner.signedAs("AKIAUNKNOWNACCESSKEY", "some-secret", "sts"))
            .contentType(FORM)
            .body("Action=GetCallerIdentity&Version=2011-06-15")
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .body("ErrorResponse.Error.Code", equalTo("InvalidClientTokenId"));
    }

    @Test
    @Order(9)
    void iamCreatedKeyVerifiesWithItsOwnSecretOnly() {
        AwsRequestSigner iam = AwsRequestSigner.signedAs("test", "test", "iam");
        given().filter(iam).contentType(FORM)
            .body("Action=CreateUser&UserName=validate-signatures-sqs-user&Version=2010-05-08")
        .when().post("/").then().statusCode(200);
        XmlPath key = given().filter(iam).contentType(FORM)
            .body("Action=CreateAccessKey&UserName=validate-signatures-sqs-user&Version=2010-05-08")
        .when().post("/").then().statusCode(200).extract().xmlPath();
        userAccessKeyId = key.getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
        userSecretKey = key.getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.SecretAccessKey");

        AwsRequestSigner user = AwsRequestSigner.signedAs(userAccessKeyId, userSecretKey, "sqs");
        given()
            .filter(user)
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.ListQueues")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(200);

        given()
            .filter(user.withSecret("not-the-secret"))
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.ListQueues")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .body("__type", equalTo("InvalidSignatureException"));
    }

    @Test
    @Order(10)
    void signatureOutsideTheClockSkewWindowIsRefused() {
        given()
            .filter(AwsRequestSigner.signedAs("test", "test", "sqs")
                    .signedAt(Instant.now().minus(Duration.ofMinutes(20))))
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.ListQueues")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(403)
            .body("__type", equalTo("InvalidSignatureException"))
            .body("message", containsString("Signature expired"));
    }

    @Test
    @Order(11)
    void malformedAuthorizationHeaderIsIncomplete() {
        given()
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/sqs/aws4_request")
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.ListQueues")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(400)
            .body("__type", equalTo("IncompleteSignatureException"));
    }

    @Test
    @Order(12)
    void unsignedRequestIsLeftToIamEnforcement() {
        given()
            .contentType(JSON_1_0)
            .header("X-Amz-Target", "AmazonSQS.ListQueues")
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(200);
    }
}
