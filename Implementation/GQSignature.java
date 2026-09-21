import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

/**
 * Implementation of the identity-based Guillou-Quisquater (GQ) digital signature
 * scheme, operating in Zn.
 *
 * Public system parameters:
 *  - n: RSA modulus (n = p * q)
 *  - v: public exponent, coprime with φ(n) (starting from 65537)
 *  - k: security parameter (bit size of the challenge)
 *
 * Private keys of the certification authority:
 *  - p, q: the prime factors of n
 *  - s: private exponent, s * v ≡ 1 (mod φ(n))
 *
 * Constructors:
 *  - GQSignature(bitLength, securityParameter): for the authority; generates the
 *    system parameters (p, q, n, φ(n), v, s).
 *  - GQSignature(n, v, k): for users; uses the existing public parameters.
 *
 * Operations:
 *  - generateCertificate(identity): executed by the authority; I = H(identity) mod n,
 *    and the certificate is J = I^s mod n.
 *  - sign(message, identity, certificate):
 *      1. choose a random r in Zn*
 *      2. commitment T = r^v mod n
 *      3. challenge d = H(M || T) mod 2^k
 *      4. response y = r * J^d mod n
 *    The signature is (d, y, identity).
 *  - verify(message, signature):
 *      1. recompute I = H(identity) mod n
 *      2. T' = y^v * I^(-d) mod n
 *      3. d' = H(M || T') mod 2^k
 *      4. the signature is valid if d' == d
 *
 * Helper functions: hashToInteger (SHA-256 over the identity, as a BigInteger) and
 * hashChallenge (SHA-256 over message || commitment, reduced to k bits).
 *
 * GQSignatureData is an immutable class that stores the signature: the challenge d,
 * the response y and the signer's identity.
 */
public class GQSignature {

    private BigInteger n;
    private BigInteger v;
    private int k;

    private BigInteger p;
    private BigInteger q;
    private BigInteger s;

    private SecureRandom random;
    private MessageDigest hash;

    public GQSignature(int bitLength, int securityParameter) throws Exception {
        this.k = securityParameter;
        this.random = new SecureRandom();
        this.hash = MessageDigest.getInstance("SHA-256");

        generateSystemParameters(bitLength);
    }

    public GQSignature(BigInteger n, BigInteger v, int k) throws Exception {
        this.n = n;
        this.v = v;
        this.k = k;
        this.random = new SecureRandom();
        this.hash = MessageDigest.getInstance("SHA-256");
    }

    private void generateSystemParameters(int bitLength) {
        p = BigInteger.probablePrime(bitLength / 2, random);
        q = BigInteger.probablePrime(bitLength / 2, random);

        n = p.multiply(q);

        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        v = BigInteger.valueOf(65537);

        while (!v.gcd(phi).equals(BigInteger.ONE)) {
            v = v.add(BigInteger.TWO);
        }

        s = v.modInverse(phi);
    }

    public BigInteger generateCertificate(String identity) {
        BigInteger I = hashToInteger(identity).mod(n);

        BigInteger J = I.modPow(s, n);

        return J;
    }

    public GQSignatureData sign(String message, String identity, BigInteger certificate) {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), random);
        } while (r.compareTo(n) >= 0 || r.gcd(n).compareTo(BigInteger.ONE) != 0);

        BigInteger T = r.modPow(v, n);

        BigInteger d = hashChallenge(message, T);

        BigInteger y = r.multiply(certificate.modPow(d, n)).mod(n);

        return new GQSignatureData(d, y, identity);
    }

    public boolean verify(String message, GQSignatureData signature) {
        try {
            BigInteger I = hashToInteger(signature.identity).mod(n);

            BigInteger yv = signature.y.modPow(v, n);
            BigInteger Id = I.modPow(signature.d, n);
            BigInteger IdInv = Id.modInverse(n);
            BigInteger TPrime = yv.multiply(IdInv).mod(n);

            BigInteger dPrime = hashChallenge(message, TPrime);

            return dPrime.equals(signature.d);

        } catch (Exception e) {
            return false;
        }
    }

    private BigInteger hashToInteger(String data) {
        hash.reset();
        byte[] hashBytes = hash.digest(data.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, hashBytes);
    }

    private BigInteger hashChallenge(String message, BigInteger commitment) {
        hash.reset();
        String combined = message + commitment.toString();
        byte[] hashBytes = hash.digest(combined.getBytes(StandardCharsets.UTF_8));
        BigInteger hashInt = new BigInteger(1, hashBytes);

        BigInteger modulus = BigInteger.ONE.shiftLeft(k);
        return hashInt.mod(modulus);
    }

    public BigInteger getN() { return n; }
    public BigInteger getV() { return v; }
    public int getK() { return k; }

    public static class GQSignatureData {
        public final BigInteger d;
        public final BigInteger y;
        public final String identity;

        public GQSignatureData(BigInteger d, BigInteger y, String identity) {
            this.d = d;
            this.y = y;
            this.identity = identity;
        }

        @Override
        public String toString() {
            return String.format("GQSignature[d=%s, y=%s, identity=%s]",
                d.toString(16), y.toString(16), identity);
        }
    }
}
