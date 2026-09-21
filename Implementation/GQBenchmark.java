import java.math.BigInteger;
import java.security.*;
import javax.crypto.Cipher;

/**
 * Benchmark comparing the performance of the Guillou-Quisquater (GQ) scheme
 * with RSA.
 *
 * For each key size (1024 and 2048 bits) three tests are run:
 * 1. GQ: system setup (generation of n, v, s), certificate generation, then
 * signing and verification of a test message, timed over ITERATIONS iterations
 * (after a 10-iteration warmup). The signature size is also printed.
 * 2. RSA Signature (PKCS#1 v1.5 with SHA-256): key pair generation, then
 * signing and verification timed in the same way.
 * 3. RSA Encryption/Decryption (PKCS#1 v1.5): key pair generation, then
 * encryption and decryption of a short message (RSA has a size limit),
 * timed in the same way.
 *
 * For each operation the average time per call and the total time over all
 * iterations are reported, in milliseconds.
 */
public class GQBenchmark {

    private static final int ITERATIONS = 100;
    private static final String TEST_MESSAGE = "This is a test message for the digital signature";
    private static final String TEST_IDENTITY = "user@example.com";

    public static void main(String[] args) {
        System.out.println("=== GUILLOU-QUISQUATER SCHEME vs RSA BENCHMARK ===\n");

        try {
            int[] keySizes = { 1024, 2048 };

            for (int keySize : keySizes) {
                System.out.println("--- Key size: " + keySize + " bits ---\n");

                benchmarkGQ(keySize);
                System.out.println();

                benchmarkRSASignature(keySize);
                System.out.println();

                benchmarkRSAEncryption(keySize);
                System.out.println("\n" + "=".repeat(70) + "\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void benchmarkGQ(int keySize) throws Exception {
        System.out.println("GUILLOU-QUISQUATER:");

        long setupStart = System.nanoTime();
        GQSignature authority = new GQSignature(keySize, 160);
        long setupTime = System.nanoTime() - setupStart;

        long certStart = System.nanoTime();
        BigInteger certificate = authority.generateCertificate(TEST_IDENTITY);
        long certTime = System.nanoTime() - certStart;

        GQSignature user = new GQSignature(authority.getN(), authority.getV(), authority.getK());

        for (int i = 0; i < 10; i++) {
            GQSignature.GQSignatureData sig = user.sign(TEST_MESSAGE, TEST_IDENTITY, certificate);
            user.verify(TEST_MESSAGE, sig);
        }

        long signStart = System.nanoTime();
        GQSignature.GQSignatureData signature = null;
        for (int i = 0; i < ITERATIONS; i++) {
            signature = user.sign(TEST_MESSAGE, TEST_IDENTITY, certificate);
        }
        long signTime = (System.nanoTime() - signStart) / ITERATIONS;

        long verifyStart = System.nanoTime();
        boolean valid = false;
        for (int i = 0; i < ITERATIONS; i++) {
            valid = user.verify(TEST_MESSAGE, signature);
        }
        long verifyTime = (System.nanoTime() - verifyStart) / ITERATIONS;

        System.out.printf("  System setup:           %10.3f ms\n", setupTime / 1_000_000.0);
        System.out.printf("  Certificate generation: %10.3f ms\n", certTime / 1_000_000.0);
        System.out.printf("  Sign (average):         %10.3f ms\n", signTime / 1_000_000.0);
        System.out.printf("  Verify (average):       %10.3f ms\n", verifyTime / 1_000_000.0);
        System.out.printf("  Sign total (%d):       %10.3f ms\n", ITERATIONS, signTime * ITERATIONS / 1_000_000.0);
        System.out.printf("  Verify total (%d):     %10.3f ms\n", ITERATIONS, verifyTime * ITERATIONS / 1_000_000.0);
        System.out.printf("  Verification valid:     %s\n", valid ? "YES" : "NO");

        int sigSize = (signature.d.bitLength() + signature.y.bitLength()) / 8;
        System.out.printf("  Signature size:         %d bytes\n", sigSize);
    }

    private static void benchmarkRSASignature(int keySize) throws Exception {
        System.out.println("RSA SIGNATURE (PKCS#1 v1.5 with SHA-256):");

        long setupStart = System.nanoTime();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        long setupTime = System.nanoTime() - setupStart;

        Signature rsaSign = Signature.getInstance("SHA256withRSA");
        byte[] messageBytes = TEST_MESSAGE.getBytes();

        for (int i = 0; i < 10; i++) {
            rsaSign.initSign(keyPair.getPrivate());
            rsaSign.update(messageBytes);
            byte[] sig = rsaSign.sign();

            rsaSign.initVerify(keyPair.getPublic());
            rsaSign.update(messageBytes);
            rsaSign.verify(sig);
        }

        long signStart = System.nanoTime();
        byte[] signature = null;
        for (int i = 0; i < ITERATIONS; i++) {
            rsaSign.initSign(keyPair.getPrivate());
            rsaSign.update(messageBytes);
            signature = rsaSign.sign();
        }
        long signTime = (System.nanoTime() - signStart) / ITERATIONS;

        long verifyStart = System.nanoTime();
        boolean valid = false;
        for (int i = 0; i < ITERATIONS; i++) {
            rsaSign.initVerify(keyPair.getPublic());
            rsaSign.update(messageBytes);
            valid = rsaSign.verify(signature);
        }
        long verifyTime = (System.nanoTime() - verifyStart) / ITERATIONS;

        System.out.printf("  Key generation:         %10.3f ms\n", setupTime / 1_000_000.0);
        System.out.printf("  Sign (average):         %10.3f ms\n", signTime / 1_000_000.0);
        System.out.printf("  Verify (average):       %10.3f ms\n", verifyTime / 1_000_000.0);
        System.out.printf("  Sign total (%d):       %10.3f ms\n", ITERATIONS, signTime * ITERATIONS / 1_000_000.0);
        System.out.printf("  Verify total (%d):     %10.3f ms\n", ITERATIONS, verifyTime * ITERATIONS / 1_000_000.0);
        System.out.printf("  Verification valid:     %s\n", valid ? "YES" : "NO");
        System.out.printf("  Signature size:         %d bytes\n", signature.length);
    }

    private static void benchmarkRSAEncryption(int keySize) throws Exception {
        System.out.println("RSA ENCRYPTION/DECRYPTION (PKCS#1 v1.5):");

        long setupStart = System.nanoTime();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        long setupTime = System.nanoTime() - setupStart;

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        byte[] shortMessage = "Test".getBytes();

        for (int i = 0; i < 10; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] encrypted = cipher.doFinal(shortMessage);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            cipher.doFinal(encrypted);
        }

        long encryptStart = System.nanoTime();
        byte[] encrypted = null;
        for (int i = 0; i < ITERATIONS; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            encrypted = cipher.doFinal(shortMessage);
        }
        long encryptTime = (System.nanoTime() - encryptStart) / ITERATIONS;

        long decryptStart = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            cipher.doFinal(encrypted);
        }
        long decryptTime = (System.nanoTime() - decryptStart) / ITERATIONS;

        System.out.printf("  Key generation:         %10.3f ms\n", setupTime / 1_000_000.0);
        System.out.printf("  Encrypt (average):      %10.3f ms\n", encryptTime / 1_000_000.0);
        System.out.printf("  Decrypt (average):      %10.3f ms\n", decryptTime / 1_000_000.0);
        System.out.printf("  Encrypt total (%d):    %10.3f ms\n", ITERATIONS, encryptTime * ITERATIONS / 1_000_000.0);
        System.out.printf("  Decrypt total (%d):    %10.3f ms\n", ITERATIONS, decryptTime * ITERATIONS / 1_000_000.0);
    }
}
