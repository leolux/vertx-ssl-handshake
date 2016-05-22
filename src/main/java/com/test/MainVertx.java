package com.test;

import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.web.Router;

/**
 *
 */
public class MainVertx {

  public static void main(String[] args) {
    Vertx vertx = Vertx.vertx();

    // Create Webserver
    HttpServerOptions options = new HttpServerOptions();
    enableSSL(options, vertx);
    HttpServer server = vertx.createHttpServer(options);
    Router router = Router.router(vertx);
    router.routeWithRegex(".*").handler(routingContext -> {
      System.out.println("Handle request");
      routingContext.response().setStatusCode(HttpURLConnection.HTTP_OK);
      routingContext.response().end();
    });

    // Start server
    server.requestHandler(router::accept).listen(8888);

    // Create HTTP client
    HttpClientOptions clientOptions = new HttpClientOptions();
    clientOptions.setSsl(true);
    clientOptions.setTrustAll(true);
    // addToTruststore(clientOptions, vertx);
    HttpClient client = vertx.createHttpClient(clientOptions);
    makeSomeRequest(client, vertx);
  }

  private static void addToTruststore(HttpClientOptions options, Vertx vertx) {
    // Add certificate to the truststore
    Buffer jksBuffer = vertx.fileSystem().readFileBlocking("cert/wild.vertx.io.jks");
    JksOptions jksOptions = new JksOptions().setValue(jksBuffer).setPassword("reactive");
    options.setTrustStoreOptions(jksOptions);

  }

  private static void makeSomeRequest(HttpClient client, Vertx vertx) {
    // delayed request
    System.out.println("Request starts in 5 seconds...");
    vertx.setTimer(1000 * 5, p -> {
      HttpClientRequest request = client.request(HttpMethod.POST, 8888, "localhost", "/something", resp -> {
        if (resp.statusCode() == 200) {
          System.out.println("No issue found");
        } else {
          System.out.println("Unexpected statusCode: " + resp.statusCode());
        }
      });

      String data = "Hello World";
      request.putHeader("Content-Type", "text/plain");
      request.putHeader("Content-Length", computeContentLength(data));
      request.write(data, "UTF-8");
      request.end();
    });
  }

  private static void enableSSL(HttpServerOptions options, Vertx vertx) {
    options.setSsl(true);

    // certificate for the subdomain *.vertx.io
    Buffer jksBuffer = vertx.fileSystem().readFileBlocking("cert/wild.vertx.io.jks");
    JksOptions jksOptions = new JksOptions().setValue(jksBuffer).setPassword("reactive");
    options.setKeyStoreOptions(jksOptions);

    options.addEnabledCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256").addEnabledCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
        .addEnabledCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA256").addEnabledCipherSuite("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256")
        .addEnabledCipherSuite("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256").addEnabledCipherSuite("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256")
        .addEnabledCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA").addEnabledCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
        .addEnabledCipherSuite("TLS_RSA_WITH_AES_128_CBC_SHA").addEnabledCipherSuite("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA")
        .addEnabledCipherSuite("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA").addEnabledCipherSuite("TLS_DHE_DSS_WITH_AES_128_CBC_SHA")
        .addEnabledCipherSuite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256").addEnabledCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        .addEnabledCipherSuite("TLS_RSA_WITH_AES_128_GCM_SHA256").addEnabledCipherSuite("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256")
        .addEnabledCipherSuite("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256").addEnabledCipherSuite("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256")
        .addEnabledCipherSuite("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA").addEnabledCipherSuite("SSL_RSA_WITH_3DES_EDE_CBC_SHA")
        .addEnabledCipherSuite("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA").addEnabledCipherSuite("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA")
        .addEnabledCipherSuite("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA").addEnabledCipherSuite("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA")
        .addEnabledCipherSuite("SSL_RSA_WITH_RC4_128_SHA").addEnabledCipherSuite("TLS_ECDH_ECDSA_WITH_RC4_128_SHA")
        .addEnabledCipherSuite("TLS_ECDH_RSA_WITH_RC4_128_SHA").addEnabledCipherSuite("SSL_RSA_WITH_RC4_128_MD5")
        .addEnabledCipherSuite("TLS_EMPTY_RENEGOTIATION_INFO_SCSV").addEnabledCipherSuite("TLS_ECDH_anon_WITH_RC4_128_SHA")
        .addEnabledCipherSuite("SSL_DH_anon_WITH_RC4_128_MD5").addEnabledCipherSuite("SSL_RSA_WITH_DES_CBC_SHA")
        .addEnabledCipherSuite("SSL_DHE_RSA_WITH_DES_CBC_SHA").addEnabledCipherSuite("SSL_DHE_DSS_WITH_DES_CBC_SHA")
        .addEnabledCipherSuite("SSL_DH_anon_WITH_DES_CBC_SHA").addEnabledCipherSuite("SSL_RSA_EXPORT_WITH_DES40_CBC_SHA")
        .addEnabledCipherSuite("SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA").addEnabledCipherSuite("SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA")
        .addEnabledCipherSuite("SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA").addEnabledCipherSuite("SSL_RSA_EXPORT_WITH_RC4_40_MD5")
        .addEnabledCipherSuite("SSL_DH_anon_EXPORT_WITH_RC4_40_MD5").addEnabledCipherSuite("TLS_KRB5_WITH_3DES_EDE_CBC_SHA")
        .addEnabledCipherSuite("TLS_KRB5_WITH_3DES_EDE_CBC_MD5").addEnabledCipherSuite("TLS_KRB5_WITH_RC4_128_SHA")
        .addEnabledCipherSuite("TLS_KRB5_WITH_RC4_128_MD5").addEnabledCipherSuite("TLS_KRB5_WITH_DES_CBC_SHA")
        .addEnabledCipherSuite("TLS_KRB5_WITH_DES_CBC_MD5").addEnabledCipherSuite("TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA")
        .addEnabledCipherSuite("TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5").addEnabledCipherSuite("TLS_KRB5_EXPORT_WITH_RC4_40_SHA")
        .addEnabledCipherSuite("TLS_KRB5_EXPORT_WITH_RC4_40_MD5");
  }

  public static String computeContentLength(String content) {
    try {
      return String.valueOf(content.getBytes("UTF-8").length);
    } catch (UnsupportedEncodingException e) {
      return null;
    }
  }
}
