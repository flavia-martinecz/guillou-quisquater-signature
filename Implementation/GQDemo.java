import java.math.BigInteger;

/**
 * Demonstration of the Guillou-Quisquater scheme
 * Complete example with 2 users (Alice and Bob)
 */
public class GQDemo {

    public static void main(String[] args) {
        try {
            printSeparator();
            System.out.println("GUILLOU-QUISQUATER SCHEME DEMONSTRATION");
            printSeparator();

            // ==================== STEP 1: SYSTEM SETUP ====================
            System.out.println("\n[STEP 1] SYSTEM SETUP - Certification Authority (CA)");
            System.out.println("-".repeat(70));

            int keySize = 1024;  // bits
            int securityParameter = 256;  // k = 256 bits (SHA-256)

            System.out.println("CA is generating system parameters...");
            GQSignature authority = new GQSignature(keySize, securityParameter);

            System.out.println("PUBLIC parameters generated:");
            System.out.println("  n (modulus):            " + authority.getN().bitLength() + " bits");
            System.out.println("     Value (first 40 hex): " + authority.getN().toString(16).substring(0, 40) + "...");
            System.out.println("  v (public exponent):    " + authority.getV());
            System.out.println("  k (security parameter): " + authority.getK() + " bits");

            // ==================== STEP 2: USER REGISTRATION ====================
            System.out.println("\n[STEP 2] USER REGISTRATION");
            System.out.println("-".repeat(70));

            String idAlice = "alice@company.com";
            String idBob = "bob@company.com";

            System.out.println("Generating certificates for users...");

            BigInteger certAlice = authority.generateCertificate(idAlice);
            System.out.println("  Alice (" + idAlice + ")");
            System.out.println("    Certificate: " + certAlice.bitLength() + " bits");
            System.out.println("    Value (first 40 hex): " + certAlice.toString(16).substring(0, 40) + "...");

            BigInteger certBob = authority.generateCertificate(idBob);
            System.out.println("  Bob (" + idBob + ")");
            System.out.println("    Certificate: " + certBob.bitLength() + " bits");
            System.out.println("    Value (first 40 hex): " + certBob.toString(16).substring(0, 40) + "...");

            // ==================== STEP 3: USERS RECEIVE PARAMETERS ====================
            System.out.println("\n[STEP 3] PUBLIC PARAMETER DISTRIBUTION");
            System.out.println("-".repeat(70));

            GQSignature alice = new GQSignature(authority.getN(), authority.getV(), authority.getK());
            GQSignature bob = new GQSignature(authority.getN(), authority.getV(), authority.getK());

            System.out.println("Alice and Bob have received the public parameters (n, v, k)");
            System.out.println("They can now sign messages and verify signatures!");

            // ==================== STEP 4: ALICE SIGNS ====================
            System.out.println("\n[STEP 4] ALICE SIGNS A MESSAGE");
            System.out.println("-".repeat(70));

            String message1 = "Contract: Transfer 1000 EUR to Bob";
            System.out.println("Message: \"" + message1 + "\"");
            System.out.println("\nAlice is signing...");

            GQSignature.Signature sigAlice = alice.sign(message1, idAlice, certAlice);

            System.out.println("Generated signature:");
            System.out.println("  Challenge (d): " + sigAlice.d.bitLength() + " bits");
            System.out.println("    Value (hex): " + sigAlice.d.toString(16));
            System.out.println("  Response (y):  " + sigAlice.y.bitLength() + " bits");
            System.out.println("    Value (first 40 hex): " + sigAlice.y.toString(16).substring(0, 40) + "...");
            System.out.println("  Identity:      " + sigAlice.identity);

            // ==================== STEP 5: BOB VERIFIES ====================
            System.out.println("\n[STEP 5] BOB VERIFIES ALICE'S SIGNATURE");
            System.out.println("-".repeat(70));

            boolean valid1 = bob.verify(message1, sigAlice);
            System.out.println("Verification result: " + (valid1 ? "VALID" : "INVALID"));

            if (!valid1) {
                System.out.println("ERROR: The signature should be valid!");
                return;
            }

            // ==================== STEP 6: INTEGRITY TEST ====================
            System.out.println("\n[STEP 6] INTEGRITY TEST - Modified Message");
            System.out.println("-".repeat(70));

            String modifiedMessage = "Contract: Transfer 9000 EUR to Bob";  // MODIFIED!
            System.out.println("Modified message: \"" + modifiedMessage + "\"");

            boolean valid2 = bob.verify(modifiedMessage, sigAlice);
            System.out.println("Verification result: " + (valid2 ? "VALID" : "INVALID"));

            if (valid2) {
                System.out.println("ERROR: The modified message should be invalid!");
                return;
            }
            System.out.println("Correct! The modified message was detected.");

            // ==================== STEP 7: AUTHENTICITY TEST ====================
            System.out.println("\n[STEP 7] AUTHENTICITY TEST - Fake Identity");
            System.out.println("-".repeat(70));

            GQSignature.Signature fakeSig =
                new GQSignature.Signature(sigAlice.d, sigAlice.y, idBob);  // Fake identity!

            System.out.println("Attempt: Alice's signature with Bob's identity");
            boolean valid3 = bob.verify(message1, fakeSig);
            System.out.println("Verification result: " + (valid3 ? "VALID" : "INVALID"));

            if (valid3) {
                System.out.println("ERROR: The fake identity should be invalid!");
                return;
            }
            System.out.println("Correct! The fake identity was detected.");

            // ==================== STEP 8: BOB SIGNS ====================
            System.out.println("\n[STEP 8] BOB SIGNS A MESSAGE");
            System.out.println("-".repeat(70));

            String message2 = "I confirm receipt of 1000 EUR from Alice";
            System.out.println("Message: \"" + message2 + "\"");
            System.out.println("\nBob is signing...");

            GQSignature.Signature sigBob = bob.sign(message2, idBob, certBob);

            System.out.println("Signature generated by Bob:");
            System.out.println("  Challenge (d): " + sigBob.d.bitLength() + " bits");
            System.out.println("    Value (hex): " + sigBob.d.toString(16));
            System.out.println("  Response (y):  " + sigBob.y.bitLength() + " bits");
            System.out.println("    Value (first 40 hex): " + sigBob.y.toString(16).substring(0, 40) + "...");

            // ==================== STEP 9: ALICE VERIFIES ====================
            System.out.println("\n[STEP 9] ALICE VERIFIES BOB'S SIGNATURE");
            System.out.println("-".repeat(70));

            boolean valid4 = alice.verify(message2, sigBob);
            System.out.println("Verification result: " + (valid4 ? "VALID" : "INVALID"));

            if (!valid4) {
                System.out.println("ERROR: Bob's signature should be valid!");
                return;
            }

            // ==================== FINAL STATISTICS ====================
            printSeparator();
            System.out.println("FINAL STATISTICS");
            printSeparator();

            int signatureSize = (sigAlice.d.bitLength() + sigAlice.y.bitLength()) / 8;

            System.out.println("Modulus size (n):         " + keySize + " bits");
            System.out.println("Certificate size:         " + certAlice.bitLength() + " bits");
            System.out.println("Signature size:           ~" + signatureSize + " bytes");
            System.out.println("Security parameter (k):   " + securityParameter + " bits");

            printSeparator();
            System.out.println("ALL TESTS EXECUTED SUCCESSFULLY!");
            printSeparator();

        } catch (Exception e) {
            System.err.println("\nERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void printSeparator() {
        System.out.println("\n" + "=".repeat(70));
    }
}
