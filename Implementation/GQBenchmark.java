import java.math.BigInteger;
import java.security.*;
import javax.crypto.Cipher;

/**
 * Comparative benchmark: GQ vs RSA
 * Measures: setup, signing, verification, sizes
 */
public class GQBenchmark {

    private static final int ITERATIONS = 1000;
    private static final String TEST_MESSAGE = "This is a test message for the digital signature";
    private static final String TEST_IDENTITY = "user@example.com";

    public static void main(String[] args) {
        printSeparator();
        System.out.println("BENCHMARK GUILLOU-QUISQUATER vs RSA");
        printSeparator();

        try {
            // Test different key sizes
            int[] sizes = {1024, 2048};

            for (int size : sizes) {
                System.out.println("\n--- Key size: " + size + " bits ---\n");

                benchmarkGQ(size);
                System.out.println();

                benchmarkRSASignature(size);
                System.out.println();

                benchmarkRSAEncryption(size);
                System.out.println();

                printSeparator();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Benchmark for the GQ scheme
     */
    private static void benchmarkGQ(int keySize) throws Exception {
        System.out.println("GUILLOU-QUISQUATER:");

        // 1. System SETUP
        long startTime = System.nanoTime();
        GQSignature authority = new GQSignature(keySize, 256);  // k=256
        double setupTime = (System.nanoTime() - startTime) / 1_000_000.0;

        // 2. Certificate GENERATION
        startTime = System.nanoTime();
        BigInteger certificate = authority.generateCertificate(TEST_IDENTITY);
        double certificateTime = (System.nanoTime() - startTime) / 1_000_000.0;

        // 3. Create user instance
        GQSignature user = new GQSignature(
            authority.getN(),
            authority.getV(),
            authority.getK()
        );

        // 4. WARMUP (JVM warm-up)
        for (int i = 0; i < 10; i++) {
            GQSignature.Signature sig = user.sign(TEST_MESSAGE, TEST_IDENTITY, certificate);
            user.verify(TEST_MESSAGE, sig);
        }

        // 5. BENCHMARK signing
        startTime = System.nanoTime();
        GQSignature.Signature signature = null;
        for (int i = 0; i < ITERATIONS; i++) {
            signature = user.sign(TEST_MESSAGE, TEST_IDENTITY, certificate);
        }
        double signTime = (System.nanoTime() - startTime) / (double) ITERATIONS / 1_000_000.0;

        // 6. BENCHMARK verification
        startTime = System.nanoTime();
        boolean valid = false;
        for (int i = 0; i < ITERATIONS; i++) {
            valid = user.verify(TEST_MESSAGE, signature);
        }
        double verifyTime = (System.nanoTime() - startTime) / (double) ITERATIONS / 1_000_000.0;

        // 7. PRINT results
        System.out.printf("  System setup:           %9.3f ms\n", setupTime);
        System.out.printf("  Certificate generation: %9.3f ms\n", certificateTime);
        System.out.printf("  Signing (average):      %9.3f ms\n", signTime);
        System.out.printf("  Verification (average): %9.3f ms\n", verifyTime);
        System.out.printf("  Verification valid:     %s\n", valid ? "YES" : "NO");

        int signatureSize = (signature.d.bitLength() + signature.y.bitLength()) / 8;
        System.out.printf("  Signature size:         %d bytes\n", signatureSize);
    }

    /**
     * Benchmark for RSA Signature
     */
    private static void benchmarkRSASignature(int keySize) throws Exception {
        System.out.println("RSA SIGNATURE (SHA256withRSA):");

        // 1. SETUP (key generation)
        long startTime = System.nanoTime();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        double setupTime = (System.nanoTime() - startTime) / 1_000_000.0;

        Signature rsaSign = Signature.getInstance("SHA256withRSA");
        byte[] messageBytes = TEST_MESSAGE.getBytes();

        // 2. WARMUP
        for (int i = 0; i < 10; i++) {
            rsaSign.initSign(keyPair.getPrivate());
            rsaSign.update(messageBytes);
            byte[] sig = rsaSign.sign();

            rsaSign.initVerify(keyPair.getPublic());
            rsaSign.update(messageBytes);
            rsaSign.verify(sig);
        }

        // 3. BENCHMARK signing
        startTime = System.nanoTime();
        byte[] signature = null;
        for (int i = 0; i < ITERATIONS; i++) {
            rsaSign.initSign(keyPair.getPrivate());
            rsaSign.update(messageBytes);
            signature = rsaSign.sign();
        }
        double signTime = (System.nanoTime() - startTime) / (double) ITERATIONS / 1_000_000.0;

        // 4. BENCHMARK verification
        startTime = System.nanoTime();
        boolean valid = false;
        for (int i = 0; i < ITERATIONS; i++) {
            rsaSign.initVerify(keyPair.getPublic());
            rsaSign.update(messageBytes);
            valid = rsaSign.verify(signature);
        }
        double verifyTime = (System.nanoTime() - startTime) / (double) ITERATIONS / 1_000_000.0;

        // 5. PRINT results
        System.out.printf("  Key generation:         %9.3f ms\n", setupTime);
        System.out.printf("  Signing (average):      %9.3f ms\n", signTime);
        System.out.printf("  Verification (average): %9.3f ms\n", verifyTime);
        System.out.printf("  Verification valid:     %s\n", valid ? "YES" : "NO");
        System.out.printf("  Signature size:         %d bytes\n", signature.length);
    }

    /**
     * Benchmark for RSA Encryption/Decryption
     */
    private static void benchmarkRSAEncryption(int keySize) throws Exception {
        System.out.println("RSA ENCRYPTION/DECRYPTION (PKCS1Padding):");

        // 1. SETUP (key generation)
        long startTime = System.nanoTime();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        double setupTime = (System.nanoTime() - startTime) / 1_000_000.0;

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // Short message for encryption (RSA limitation)
        byte[] shortMessage = "Test".getBytes();

        // 2. WARMUP
        for (int i = 0; i < 10; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encrypted = cipher.doFinal(shortMessage);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            cipher.doFinal(encrypted);
        }

        // 3. BENCHMARK encryption
        startTime = System.nanoTime();
        byte[] encrypted = null;
        for (int i = 0; i < ITERATIONS; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            encrypted = cipher.doFinal(shortMessage);
        }
        double encryptTime = (System.nanoTime() - startTime) / (double) ITERATIONS / 1_000_000.0;

        // 4. BENCHMARK decryption
        startTime = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            cipher.doFinal(encrypted);
        }
        double decryptTime = (System.nanoTime() - startTime) / (double) ITERATIONS / 1_000_000.0;

        // 5. PRINT results
        System.out.printf("  Key generation:         %9.3f ms\n", setupTime);
        System.out.printf("  Encryption (average):   %9.3f ms\n", encryptTime);
        System.out.printf("  Decryption (average):   %9.3f ms\n", decryptTime);
        System.out.printf("  Ciphertext size:        %d bytes\n", encrypted.length);
    }

    private static void printSeparator() {
        System.out.println("=".repeat(70));
    }
}
