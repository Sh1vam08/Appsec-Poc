package com.shopsphere.service.sast.injection;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.StringReader;

/**
 * Service for XML External Entity (XXE) Injection benchmark scenarios.
 * Covers BENCH-SAST-021 through BENCH-SAST-024.
 */
@Service
public class InventoryImportService {

    /**
     * BENCH-SAST-021: XXE Injection (Vulnerable Variant)
     * Parses user XML input with DocumentBuilderFactory without disabling external entities.
     */
    public String parseVulnerable(String xmlContent) {
        // BENCH-SAST-021
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // Vulnerable: no protection features disabled
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            return "Parsed root element: " + doc.getDocumentElement().getNodeName();
        } catch (Exception e) {
            return "XML Parsing error: " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-022: XXE Injection (Safe Variant)
     * Explicitly configures security features on DocumentBuilderFactory to disable DOCTYPE declarations.
     */
    public String parseSafe(String xmlContent) {
        // BENCH-SAST-022
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // Disallow DTD (DOCTYPE declaration) completely
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            return "Parsed root safely: " + doc.getDocumentElement().getNodeName();
        } catch (Exception e) {
            return "XML Parsing error (protected): " + e.getMessage();
        }
    }

    /**
     * BENCH-SAST-023: XXE Injection (Unreachable Variant)
     * Unreachable helper parsing XML with vulnerable DocumentBuilder settings.
     */
    @SuppressWarnings("unused")
    private String parseUnreachable(String xmlContent) {
        // BENCH-SAST-023
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.parse(new InputSource(new StringReader(xmlContent)));
        } catch (Exception e) {
            // ignore
        }
        return "";
    }

    /**
     * BENCH-SAST-024: XXE Injection (Framework-Protected Variant)
     * Uses XMLInputFactory (StAX) with strict disablement features, illustrating
     * standard parser API security features for XML streams.
     */
    public String parseFrameworkProtected(String xmlContent) {
        // BENCH-SAST-024
        try {
            XMLInputFactory xif = XMLInputFactory.newInstance();
            // Disable external DTD and external resolver features
            xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            
            XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(xmlContent));
            while (xsr.hasNext()) {
                xsr.next();
            }
            return "Stream parsed safely via framework StAX reader.";
        } catch (Exception e) {
            return "StAX parsing error (protected): " + e.getMessage();
        }
    }
}
