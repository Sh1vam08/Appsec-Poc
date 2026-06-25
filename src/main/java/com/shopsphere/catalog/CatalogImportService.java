package com.shopsphere.catalog;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathVariableResolver;
import java.io.StringReader;

/**
 * Service for XPath Injection benchmark scenarios.
 * Covers BENCH-SAST-017 through BENCH-SAST-020.
 */
@Service
public class CatalogImportService {

    private static final String MOCK_XML = 
        "<users>" +
        "  <user><username>admin</username><email>admin@benchmark.local</email></user>" +
        "  <user><username>user</username><email>user@benchmark.local</email></user>" +
        "</users>";

    private InputSource getXmlSource() {
        return new InputSource(new StringReader(MOCK_XML));
    }

    /**
     * BENCH-SAST-017: XPath Injection (Vulnerable Variant)
     * Concatenates raw user input directly into an XPath query expression.
     */
    public String searchVulnerable(String username) {
        // BENCH-SAST-017
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            String expression = "/users/user[username='" + username + "']/email/text()";
            return xpath.evaluate(expression, getXmlSource());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-018: XPath Injection (Safe Variant)
     * Restricts inputs to safe alphanumeric strings before performing query execution.
     */
    public String searchSafe(String username) {
        // BENCH-SAST-018
        if (username == null || !username.matches("^[a-zA-Z0-9]+$")) {
            return "Invalid username input pattern.";
        }
        
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            String expression = "/users/user[username='" + username + "']/email/text()";
            return xpath.evaluate(expression, getXmlSource());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-019: XPath Injection (Unreachable Variant)
     * Unreachable helper executing vulnerable XPath concatenation.
     */
    @SuppressWarnings("unused")
    private String searchUnreachable(String username) {
        // BENCH-SAST-019
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            String expression = "/users/user[username='" + username + "']/email/text()";
            return xpath.evaluate(expression, getXmlSource());
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * BENCH-SAST-020: XPath Injection (Framework-Protected Variant)
     * Uses XPathVariableResolver to parameterize parameters inside the XPath expression,
     * separating query structure from literal values.
     */
    public String searchFrameworkProtected(String username) {
        // BENCH-SAST-020
        try {
            XPathFactory factory = XPathFactory.newInstance();
            XPath xpath = factory.newXPath();
            
            // Define variable resolver to parameterized values
            xpath.setXPathVariableResolver(new XPathVariableResolver() {
                @Override
                public Object resolveVariable(QName variableName) {
                    if (variableName.getLocalPart().equals("userParam")) {
                        return username;
                    }
                    return null;
                }
            });
            
            // Expression contains a bound variable reference
            String expression = "/users/user[username=$userParam]/email/text()";
            
            // XML Document parser
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            Document doc = dbf.newDocumentBuilder().parse(getXmlSource());
            
            return xpath.evaluate(expression, doc);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
