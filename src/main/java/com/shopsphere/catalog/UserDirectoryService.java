package com.shopsphere.service.sast.injection;

import org.springframework.stereotype.Service;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;

/**
 * Service for LDAP Injection benchmark scenarios.
 * Covers BENCH-SAST-013 through BENCH-SAST-016.
 */
@Service
public class UserDirectoryService {

    private static final String PROVIDER_URL = "ldap://localhost:389";
    private static final String BASE_DN = "dc=example,dc=com";

    private DirContext getContext() throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, PROVIDER_URL);
        return new InitialDirContext(env);
    }

    /**
     * BENCH-SAST-013: LDAP Injection (Vulnerable Variant)
     * Concatenates raw user input into an LDAP search filter.
     */
    public String searchVulnerable(String username) {
        // BENCH-SAST-013
        String filter = "(uid=" + username + ")";
        try {
            DirContext ctx = getContext();
            NamingEnumeration<SearchResult> results = ctx.search(BASE_DN, filter, new SearchControls());
            ctx.close();
            return results.hasMore() ? "User found" : "User not found";
        } catch (Exception e) {
            // Graceful fallback for runtime testing when no LDAP directory server runs
            return "LDAP execution fallback - Vulnerable search constructed filter: " + filter;
        }
    }

    /**
     * BENCH-SAST-014: LDAP Injection (Safe Variant)
     * Performs manual sanitization of special characters within the LDAP filter input.
     */
    public String searchSafe(String username) {
        // BENCH-SAST-014
        String sanitized = escapeLDAPSearchFilter(username);
        String filter = "(uid=" + sanitized + ")";
        try {
            DirContext ctx = getContext();
            NamingEnumeration<SearchResult> results = ctx.search(BASE_DN, filter, new SearchControls());
            ctx.close();
            return results.hasMore() ? "User found" : "User not found";
        } catch (Exception e) {
            return "LDAP execution fallback - Safe search constructed filter: " + filter;
        }
    }

    /**
     * BENCH-SAST-015: LDAP Injection (Unreachable Variant)
     * Unreachable helper executing vulnerable LDAP filter concatenation.
     */
    @SuppressWarnings("unused")
    private String searchUnreachable(String username) {
        // BENCH-SAST-015
        String filter = "(uid=" + username + ")";
        try {
            DirContext ctx = getContext();
            ctx.search(BASE_DN, filter, new SearchControls());
        } catch (Exception e) {
            // ignore
        }
        return "";
    }

    /**
     * BENCH-SAST-016: LDAP Injection (Framework-Protected Variant)
     * Uses JNDI's built-in parameterized filter search. The LDAP engine automatically binds
     * and sanitizes parameters in the filter template.
     */
    public String searchFrameworkProtected(String username) {
        // BENCH-SAST-016
        try {
            DirContext ctx = getContext();
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            // JNDI parameterized query expression with filter arguments
            NamingEnumeration<SearchResult> results = ctx.search(
                BASE_DN, 
                "(uid={0})", 
                new Object[]{ username }, 
                sc
            );
            
            ctx.close();
            return results.hasMore() ? "User found" : "User not found";
        } catch (Exception e) {
            return "LDAP execution fallback - Framework-protected query binding verified.";
        }
    }

    /**
     * Helper to escape LDAP search filter characters.
     */
    private String escapeLDAPSearchFilter(String filter) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < filter.length(); i++) {
            char curChar = filter.charAt(i);
            switch (curChar) {
                case '\\': sb.append("\\5c"); break;
                case '*': sb.append("\\2a"); break;
                case '(': sb.append("\\28"); break;
                case ')': sb.append("\\29"); break;
                case '\u0000': sb.append("\\00"); break;
                default: sb.append(curChar);
            }
        }
        return sb.toString();
    }
}
