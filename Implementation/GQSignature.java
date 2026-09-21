import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Project topic:
 * Guillou-Quisquater identity-based digital signature scheme (in Zn)
 *
 * @author Flavia Martinecz
 * @university Politehnica University of Timisoara
 * @course SISC Master's - Modern Cryptographic Techniques - year I, semester I
 */
public class GQSignature {

    // PUBLIC parameters - known to everyone
    private BigInteger n;  // RSA modulus: n = p × q
    private BigInteger v;  // Public exponent (65537)
    private int k;         // Challenge size (256 bits)

    // SECRET parameters - CA only
    private BigInteger p, q;  // Prime factors
    private BigInteger s;     // Private exponent: s = v^-1 mod φ(n)

    // Utilities
    private SecureRandom random;
    private MessageDigest hash;

    /**
     * Constructor for the Certification Authority (CA)
     * Generates all system parameters
     */
    public GQSignature(int bitLength, int k) throws Exception {
        this.k = k;
        this.random = new SecureRandom();
        this.hash = MessageDigest.getInstance("SHA-256");
        generateParameters(bitLength);
    }

    /**
     * Constructor for Users
     * Uses existing public parameters
     */
    public GQSignature(BigInteger n, BigInteger v, int k) throws Exception {
        this.n = n;
        this.v = v;
        this.k = k;
        this.random = new SecureRandom();
        this.hash = MessageDigest.getInstance("SHA-256");
    }

    /**
     * STEP 1: Generate system parameters (CA only)
     * Generates: p, q, n, v, s
     */
    private void generateParameters(int bitLength) {
        // Generate two large prime factors
        p = BigInteger.probablePrime(bitLength / 2, random);
        q = BigInteger.probablePrime(bitLength / 2, random);

        // Compute n = p × q
        n = p.multiply(q);

        // Compute φ(n) = (p-1)(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Choose v = 65537 (RSA standard)
        v = BigInteger.valueOf(65537);

        // Compute s = v^-1 mod φ(n)
        s = v.modInverse(phi);
    }

    /**
     * STEP 2: Generate certificate for a user (CA only)
     * Input: identity (e.g. "alice@company.com")
     * Output: J = secret certificate
     */
    public BigInteger generateCertificate(String identity) {
        // I = H(identity) mod n
        BigInteger I = hashToBigInteger(identity).mod(n);

        // J = I^s mod n (the secret certificate)
        BigInteger J = I.modPow(s, n);

        return J;
    }

    /**
     * STEP 3: Sign a message
     * Input: message, identity, certificate
     * Output: signature (d, y, identity)
     */
    public Signature sign(String message, String identity, BigInteger certificate) {
        // 1. Choose random r from Zn*
        BigInteger r = generateRandom();

        // 2. Compute commitment: T = r^v mod n
        BigInteger T = r.modPow(v, n);

        // 3. Compute challenge: d = H(message || T) mod 2^k
        BigInteger d = computeChallenge(message, T);

        // 4. Compute response: y = r × J^d mod n
        BigInteger Jd = certificate.modPow(d, n);
        BigInteger y = r.multiply(Jd).mod(n);

        return new Signature(d, y, identity);
    }

    /**
     * STEP 4: Verify a signature
     * Input: message, signature
     * Output: true if valid, false otherwise
     */
    public boolean verify(String message, Signature sig) {
        try {
            // 1. Recompute I = H(identity) mod n
            BigInteger I = hashToBigInteger(sig.identity).mod(n);

            // 2. Compute T' = y^v × I^(-d) mod n
            BigInteger yv = sig.y.modPow(v, n);
            BigInteger Id = I.modPow(sig.d, n);
            BigInteger IdInv = Id.modInverse(n);
            BigInteger TPrime = yv.multiply(IdInv).mod(n);

            // 3. Recompute challenge: d' = H(message || T')
            BigInteger dPrime = computeChallenge(message, TPrime);

            // 4. Check: d' == d
            return dPrime.equals(sig.d);

        } catch (Exception e) {
            return false;
        }
    }

    // ========== HELPER FUNCTIONS ==========

    /**
     * Generates a random number r from Zn*
     * Conditions: r < n and gcd(r, n) = 1
     */
    private BigInteger generateRandom() {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), random);
        } while (r.compareTo(n) >= 0 || !r.gcd(n).equals(BigInteger.ONE));
        return r;
    }

    /**
     * Hash a string to a BigInteger
     */
    private BigInteger hashToBigInteger(String text) {
        hash.reset();
        byte[] hashBytes = hash.digest(text.getBytes());
        return new BigInteger(1, hashBytes);
    }

    /**
     * Compute challenge: d = H(message || T) mod 2^k
     */
    private BigInteger computeChallenge(String message, BigInteger T) {
        hash.reset();
        String combined = message + T.toString();
        byte[] hashBytes = hash.digest(combined.getBytes());
        BigInteger hashInt = new BigInteger(1, hashBytes);

        // Reduce to k bits: hash mod 2^k
        BigInteger modulus = BigInteger.ONE.shiftLeft(k);
        return hashInt.mod(modulus);
    }

    // Getters for public parameters
    public BigInteger getN() { return n; }
    public BigInteger getV() { return v; }
    public int getK() { return k; }

    /**
     * Class for storing a signature
     */
    public static class Signature {
        public final BigInteger d;  // Challenge
        public final BigInteger y;  // Response
        public final String identity;

        public Signature(BigInteger d, BigInteger y, String identity) {
            this.d = d;
            this.y = y;
            this.identity = identity;
        }

        @Override
        public String toString() {
            return String.format("GQ Signature [d=%d bits, y=%d bits, ID=%s]",
                d.bitLength(), y.bitLength(), identity);
        }
    }
}
