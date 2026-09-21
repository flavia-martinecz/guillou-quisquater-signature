import java.math.BigInteger;

/**
 * Demonstration program for the Guillou-Quisquater (GQ) signature scheme.
 *
 * Demonstrated flow:
 *  1. System setup: the Certification Authority generates the public parameters (n, v, k).
 *  2. User registration: the authority issues certificates for Alice and Bob,
 *     derived from their identities.
 *  3. Public parameter distribution: Alice and Bob receive (n, v, k).
 *  4. Message signing (Alice): Alice signs a message using her certificate.
 *  5. Signature verification: Bob verifies Alice's signature (expected: VALID).
 *  6. Integrity test: the same signature is verified against a tampered message
 *     (expected: INVALID).
 *  7. Authenticity test: Alice's signature is presented with Bob's identity
 *     (expected: INVALID).
 *  8. Message signing (Bob): Bob signs his own message.
 *  9. Signature verification: Alice verifies Bob's signature (expected: VALID).
 *
 * Finally, statistics about the modulus, certificate and signature sizes are printed.
 */
public class GQDemo {

    public static void main(String[] args) {
        try {
            System.out.println("=== GUILLOU-QUISQUATER SCHEME DEMONSTRATION ===\n");

            System.out.println("Step 1: SYSTEM SETUP (Certification Authority)");
            System.out.println("-".repeat(60));

            int bitLength = 1024;
            int securityParam = 160;

            GQSignature authority = new GQSignature(bitLength, securityParam);

            System.out.println("Generated public parameters:");
            System.out.println("  n (modulus): " + authority.getN().bitLength() + " bits");
            System.out.println("  v (public exponent): " + authority.getV());
            System.out.println("  k (security parameter): " + authority.getK());
            System.out.println();

            System.out.println("Step 2: USER REGISTRATION");
            System.out.println("-".repeat(60));

            String aliceId = "alice@company.com";
            String bobId = "bob@company.com";

            System.out.println("Generating user certificates...");
            BigInteger aliceCert = authority.generateCertificate(aliceId);
            BigInteger bobCert = authority.generateCertificate(bobId);

            System.out.println("  Alice (" + aliceId + "):");
            System.out.println("    Certificate: " + aliceCert.bitLength() + " bits");
            System.out.println("  Bob (" + bobId + "):");
            System.out.println("    Certificate: " + bobCert.bitLength() + " bits");
            System.out.println();

            System.out.println("Step 3: PUBLIC PARAMETER DISTRIBUTION");
            System.out.println("-".repeat(60));

            GQSignature alice = new GQSignature(authority.getN(), authority.getV(), authority.getK());
            GQSignature bob = new GQSignature(authority.getN(), authority.getV(), authority.getK());

            System.out.println("Alice and Bob have received the public parameters (n, v, k)");
            System.out.println();

            System.out.println("Step 4: MESSAGE SIGNING (Alice)");
            System.out.println("-".repeat(60));

            String message1 = "Contract: Transfer of 1000 EUR to Bob";
            System.out.println("Message: \"" + message1 + "\"");

            GQSignature.GQSignatureData aliceSignature = alice.sign(message1, aliceId, aliceCert);

            System.out.println("\nGenerated signature:");
            System.out.println("  Challenge (d): " + aliceSignature.d.bitLength() + " bits");
            System.out.println("  Response (y): " + aliceSignature.y.bitLength() + " bits");
            System.out.println("  Identity: " + aliceSignature.identity);
            System.out.println();

            System.out.println("Step 5: SIGNATURE VERIFICATION (Bob verifies Alice's signature)");
            System.out.println("-".repeat(60));

            boolean valid1 = bob.verify(message1, aliceSignature);
            System.out.println("Verification result: " + (valid1 ? "[OK] VALID" : "[FAIL] INVALID"));
            System.out.println();

            System.out.println("Step 6: INTEGRITY TEST - Tampered Message");
            System.out.println("-".repeat(60));

            String tamperedMessage = "Contract: Transfer of 9000 EUR to Bob";
            System.out.println("Tampered message: \"" + tamperedMessage + "\"");

            boolean valid2 = bob.verify(tamperedMessage, aliceSignature);
            System.out.println("Verification result: " + (valid2 ? "[OK] VALID" : "[FAIL] INVALID (as expected)"));
            System.out.println();

            System.out.println("Step 7: AUTHENTICITY TEST - Forged Identity");
            System.out.println("-".repeat(60));

            GQSignature.GQSignatureData forgedSignature =
                new GQSignature.GQSignatureData(aliceSignature.d, aliceSignature.y, bobId);

            System.out.println("Alice's signature with Bob's identity (forgery)");
            boolean valid3 = bob.verify(message1, forgedSignature);
            System.out.println("Verification result: " + (valid3 ? "[OK] VALID" : "[FAIL] INVALID (as expected)"));
            System.out.println();

            System.out.println("Step 8: MESSAGE SIGNING (Bob)");
            System.out.println("-".repeat(60));

            String message2 = "I confirm receipt of 1000 EUR from Alice";
            System.out.println("Message: \"" + message2 + "\"");

            GQSignature.GQSignatureData bobSignature = bob.sign(message2, bobId, bobCert);

            System.out.println("\nSignature generated by Bob");
            System.out.println("  Challenge (d): " + bobSignature.d.bitLength() + " bits");
            System.out.println("  Response (y): " + bobSignature.y.bitLength() + " bits");
            System.out.println();

            System.out.println("Step 9: SIGNATURE VERIFICATION (Alice verifies Bob's signature)");
            System.out.println("-".repeat(60));

            boolean valid4 = alice.verify(message2, bobSignature);
            System.out.println("Verification result: " + (valid4 ? "[OK] VALID" : "[FAIL] INVALID"));
            System.out.println();

            System.out.println("=== STATISTICS ===");
            System.out.println("-".repeat(60));
            System.out.println("Modulus size (n): " + bitLength + " bits");
            System.out.println("Certificate size: " + aliceCert.bitLength() + " bits");
            System.out.println("Signature size: ~" +
                (aliceSignature.d.bitLength() + aliceSignature.y.bitLength()) / 8 + " bytes");
            System.out.println("\nAll tests completed successfully!");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
