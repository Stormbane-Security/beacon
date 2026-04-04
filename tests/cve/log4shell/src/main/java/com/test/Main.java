package com.test;

import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * Deliberately vulnerable Java HTTP server using Log4j 2.14.1.
 * User-Agent header is logged without sanitization, enabling JNDI injection.
 */
public class Main {
    private static final Logger logger = LogManager.getLogger(Main.class);

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/", exchange -> {
            String ua = exchange.getRequestHeaders().getFirst("User-Agent");
            // VULNERABLE: logs unsanitized user input via Log4j 2.14.1
            logger.info("Request from: " + ua);

            byte[] response = "OK".getBytes();
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.setExecutor(null);
        System.out.println("Log4Shell-vulnerable server listening on :8080");
        server.start();
    }
}
