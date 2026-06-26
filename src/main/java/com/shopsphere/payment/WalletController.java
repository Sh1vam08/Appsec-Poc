package com.shopsphere.payment;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Controller for Concurrency / Race Condition benchmark scenarios.
 * BENCH-DAST-103: Time-of-Check to Time-of-Use (TOCTOU) Race Condition (Vulnerable Variant)
 */
@RestController
@RequestMapping("/api/v1/wallet")
public class WalletController {

    // Simulating a database of user balances
    private final ConcurrentHashMap<String, Integer> userBalances = new ConcurrentHashMap<>();
    
    public WalletController() {
        userBalances.put("testuser", 100);
    }

    /**
     * BENCH-DAST-103: Race Condition
     * Maps to: POST /api/v1/wallet/transfer
     * Intentionally lacks synchronization. A highly concurrent attack can bypass the balance check.
     */
    @PostMapping("/transfer")
    public ResponseEntity<String> transferFunds(@RequestParam String fromUser, @RequestParam String toUser, @RequestParam int amount) {
        // BENCH-DAST-103
        
        Integer currentBalance = userBalances.getOrDefault(fromUser, 0);
        
        // Time of Check (TOC)
        if (currentBalance >= amount) {
            
            // Artificial delay to widen the race condition window for DAST scanners
            try { Thread.sleep(50); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            
            // Time of Use (TOU)
            // Vulnerable: Another thread could have reduced the balance during the sleep window.
            userBalances.put(fromUser, currentBalance - amount);
            
            Integer recipientBalance = userBalances.getOrDefault(toUser, 0);
            userBalances.put(toUser, recipientBalance + amount);
            
            return ResponseEntity.ok("Transfer successful. New balance for " + fromUser + ": " + userBalances.get(fromUser));
        }
        
        return ResponseEntity.badRequest().body("Insufficient funds.");
    }
    
    @GetMapping("/balance/{user}")
    public ResponseEntity<Integer> getBalance(@PathVariable String user) {
        return ResponseEntity.ok(userBalances.getOrDefault(user, 0));
    }
}
