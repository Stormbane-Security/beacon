import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import java.io.*;
import java.net.InetSocketAddress;

/**
 * Deliberately vulnerable Java HTTP server with XXE in XML parsing.
 * DocumentBuilderFactory is NOT configured to disable external entities.
 */
public class Main {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/health", exchange -> {
            byte[] response = "OK".getBytes();
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        server.createContext("/", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                handleXML(exchange);
            } else {
                String html = "<html><body><h1>XML Parser</h1>" +
                    "<form method='POST' enctype='text/xml'>" +
                    "<textarea name='xml' rows='10' cols='50'>&lt;user&gt;&lt;name&gt;test&lt;/name&gt;&lt;/user&gt;</textarea>" +
                    "<button>Parse</button></form></body></html>";
                exchange.getResponseHeaders().set("Content-Type", "text/html");
                exchange.sendResponseHeaders(200, html.length());
                exchange.getResponseBody().write(html.getBytes());
                exchange.close();
            }
        });

        server.createContext("/api/v1/upload", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                handleXML(exchange);
            } else {
                exchange.sendResponseHeaders(405, 0);
                exchange.close();
            }
        });

        server.setExecutor(null);
        System.out.println("XXE-vulnerable server listening on :8080");
        server.start();
    }

    private static void handleXML(HttpExchange exchange) throws IOException {
        try {
            // VULNERABLE: External entity processing is enabled by default
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Deliberately NOT setting:
            // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            // factory.setFeature("http://xml.org/sax/features/external-general-entities", false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            InputStream body = exchange.getRequestBody();
            Document doc = builder.parse(new InputSource(body));

            String result = "Parsed: " + doc.getDocumentElement().getTagName();
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, result.length());
            exchange.getResponseBody().write(result.getBytes());
        } catch (Exception e) {
            String error = "Parse error: " + e.getMessage();
            exchange.sendResponseHeaders(500, error.length());
            exchange.getResponseBody().write(error.getBytes());
        }
        exchange.close();
    }
}
