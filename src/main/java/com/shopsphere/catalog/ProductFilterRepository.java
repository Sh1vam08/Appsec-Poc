package com.shopsphere.repository.sast.injection;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.springframework.stereotype.Repository;
import java.util.ArrayList;
import java.util.List;

/**
 * Repository for NoSQL Injection benchmark scenarios.
 * Uses the real MongoDB Java client driver to demonstrate vulnerability sinks.
 */
@Repository
public class ProductFilterRepository {

    private static final String CONNECTION_STRING = "mongodb://localhost:27017/?serverSelectionTimeoutMS=100&connectTimeoutMS=100";
    private static final String DATABASE_NAME = "benchmarkdb";
    private static final String COLLECTION_NAME = "users";

    /**
     * BENCH-SAST-005: NoSQL Injection (Vulnerable Variant)
     * Concatenates raw user input into a JSON query string and parses it, creating a query injection.
     */
    public List<Document> searchVulnerable(String username) {
        // BENCH-SAST-005
        String jsonQuery = "{ \"$where\": \"this.username == '" + username + "'\" }";
        
        try (MongoClient mongoClient = MongoClients.create(CONNECTION_STRING)) {
            MongoDatabase database = mongoClient.getDatabase(DATABASE_NAME);
            MongoCollection<Document> collection = database.getCollection(COLLECTION_NAME);
            List<Document> results = new ArrayList<>();
            // Sink: collection.find with parsed injection string
            collection.find(Document.parse(jsonQuery)).forEach(results::add);
            return results;
        } catch (Exception e) {
            // Fallback for runtime stability since no local Mongo server runs by default
            return List.of(new Document("username", username)
                    .append("role", "USER")
                    .append("source", "nosql-vulnerable-stub"));
        }
    }

    /**
     * BENCH-SAST-006: NoSQL Injection (Safe Variant)
     * Uses the parameterized MongoDB Filters API, preventing query injection.
     */
    public List<Document> searchSafe(String username) {
        // BENCH-SAST-006
        try (MongoClient mongoClient = MongoClients.create(CONNECTION_STRING)) {
            MongoDatabase database = mongoClient.getDatabase(DATABASE_NAME);
            MongoCollection<Document> collection = database.getCollection(COLLECTION_NAME);
            List<Document> results = new ArrayList<>();
            // Sink: parameterized Filters query
            collection.find(Filters.eq("username", username)).forEach(results::add);
            return results;
        } catch (Exception e) {
            return List.of(new Document("username", username)
                    .append("role", "USER")
                    .append("source", "nosql-safe-stub"));
        }
    }

    /**
     * BENCH-SAST-007: NoSQL Injection (Unreachable Variant)
     * Unreachable helper that constructs and executes a vulnerable NoSQL query.
     */
    @SuppressWarnings("unused")
    private List<Document> searchUnreachable(String username) {
        // BENCH-SAST-007
        String jsonQuery = "{ \"$where\": \"this.username == '" + username + "'\" }";
        try (MongoClient mongoClient = MongoClients.create(CONNECTION_STRING)) {
            MongoDatabase database = mongoClient.getDatabase(DATABASE_NAME);
            MongoCollection<Document> collection = database.getCollection(COLLECTION_NAME);
            List<Document> results = new ArrayList<>();
            collection.find(Document.parse(jsonQuery)).forEach(results::add);
            return results;
        } catch (Exception e) {
            return List.of(new Document("username", username)
                    .append("source", "nosql-unreachable-stub"));
        }
    }
}
