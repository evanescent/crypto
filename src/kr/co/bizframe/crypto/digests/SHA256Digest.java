/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.digests;

import kr.co.bizframe.crypto.util.Pack;



/**
 * FIPS 180-2 implementation of SHA-256.
 *
 * <pre>
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * </pre>
 */
public class SHA256Digest extends GeneralDigest {

    private static final int    DIGEST_LENGTH = 32;

    private int H0, H1, H2, H3, H4, H5, H6, H7;

    private int[] W = new int[64];
    private int wOff;

    /**
     * Standard constructor
     */
    public SHA256Digest() {
        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    public SHA256Digest(SHA256Digest t) {
        super(t);

        H0 = t.H0;
        H1 = t.H1;
        H2 = t.H2;
        H3 = t.H3;
        H4 = t.H4;
        H5 = t.H5;
        H6 = t.H6;
        H7 = t.H7;

        System.arraycopy(t.W, 0, W, 0, t.W.length);
        wOff = t.wOff;
    }

    public String getAlgorithmName() {
        return "SHA-256";
    }

    public int getDigestSize() {
        return DIGEST_LENGTH;
    }

    protected void processWord(byte[]  in, int inOff) {
        // Note: Inlined for performance
//        X[xOff] = Pack.bigEndianToInt(in, inOff);
        int n = in[inOff] << 24;
        n |= (in[++inOff] & 0xff) << 16;
        n |= (in[++inOff] & 0xff) << 8;
        n |= (in[++inOff] & 0xff);
        W[wOff] = n;

        if (++wOff == 16) {
            processBlock();
        }
    }

    protected void processLength(long    bitLength) {
        if (wOff > 14) {
            processBlock();
        }

        W[14] = (int)(bitLength >>> 32);
        W[15] = (int)(bitLength & 0xffffffff);
    }

    public int doFinal(byte[]  out, int outOff) {

        finish();

        Pack.intToBigEndian(H0, out, outOff);
        Pack.intToBigEndian(H1, out, outOff + 4);
        Pack.intToBigEndian(H2, out, outOff + 8);
        Pack.intToBigEndian(H3, out, outOff + 12);
        Pack.intToBigEndian(H4, out, outOff + 16);
        Pack.intToBigEndian(H5, out, outOff + 20);
        Pack.intToBigEndian(H6, out, outOff + 24);
        Pack.intToBigEndian(H7, out, outOff + 28);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables
     */
    public void reset() {

        super.reset();

        /* SHA-256 initial hash value
         * The first 32 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */

        H0 = 0x6a09e667;
        H1 = 0xbb67ae85;
        H2 = 0x3c6ef372;
        H3 = 0xa54ff53a;
        H4 = 0x510e527f;
        H5 = 0x9b05688c;
        H6 = 0x1f83d9ab;
        H7 = 0x5be0cd19;

        wOff = 0;
        for (int i = 0; i != W.length; i++) {
            W[i] = 0;
        }
    }

    protected void processBlock() {
        //
        // expand 16 word block into 64 word blocks.
        //
        for (int t = 16; t < 64; t++) {
            W[t] = Theta1(W[t - 2]) + W[t - 7] + Theta0(W[t - 15]) + W[t - 16];
        }

        //
        // set up working variables.
        //
        int     a = H0;
        int     b = H1;
        int     c = H2;
        int     d = H3;
        int     e = H4;
        int     f = H5;
        int     g = H6;
        int     h = H7;

        /*
        int t = 0;
        for(int i = 0; i < 8; i ++) {
            // t = 8 * i
            h += Sum1(e) + Ch(e, f, g) + K[t] + W[t];
            d += h;
            h += Sum0(a) + Maj(a, b, c);
            ++t;

            // t = 8 * i + 1
            g += Sum1(d) + Ch(d, e, f) + K[t] + W[t];
            c += g;
            g += Sum0(h) + Maj(h, a, b);
            ++t;

            // t = 8 * i + 2
            f += Sum1(c) + Ch(c, d, e) + K[t] + W[t];
            b += f;
            f += Sum0(g) + Maj(g, h, a);
            ++t;

            // t = 8 * i + 3
            e += Sum1(b) + Ch(b, c, d) + K[t] + W[t];
            a += e;
            e += Sum0(f) + Maj(f, g, h);
            ++t;

            // t = 8 * i + 4
            d += Sum1(a) + Ch(a, b, c) + K[t] + W[t];
            h += d;
            d += Sum0(e) + Maj(e, f, g);
            ++t;

            // t = 8 * i + 5
            c += Sum1(h) + Ch(h, a, b) + K[t] + W[t];
            g += c;
            c += Sum0(d) + Maj(d, e, f);
            ++t;

            // t = 8 * i + 6
            b += Sum1(g) + Ch(g, h, a) + K[t] + W[t];
            f += b;
            b += Sum0(c) + Maj(c, d, e);
            ++t;

            // t = 8 * i + 7
            a += Sum1(f) + Ch(f, g, h) + K[t] + W[t];
            e += a;
            a += Sum0(b) + Maj(b, c, d);
            ++t;
        }
		*/


        for(int t = 0; t < 64; t++){

        	int T1 = h + Sum1(e) + Ch(e, f, g) + K[t] + W[t];
        	int T2 = Sum0(a) + Maj(a, b, c);
        	h = g;
        	g = f;
        	f = e;
        	e = d + T1;
        	d = c;
        	c = b;
        	b = a;
        	a = T1 + T2;
        }



        H0 += a;
        H1 += b;
        H2 += c;
        H3 += d;
        H4 += e;
        H5 += f;
        H6 += g;
        H7 += h;

        //
        // reset the offset and clean out the word buffer.
        //
        wOff = 0;
        for (int i = 0; i < 16; i++) {
            W[i] = 0;
        }
    }

    /* SHA-256 functions */
    private int Ch(int x, int y, int z) {
        return (x & y) ^ ((~x) & z);
    }

    private int Maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private int Sum0(int x) {
        return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^ ((x >>> 22) | (x << 10));
    }

    private int Sum1(int x) {
        return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^ ((x >>> 25) | (x << 7));
    }

    private int Theta0(int x) {
        return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    private int Theta1(int x) {
        return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }

    /* SHA-256 Constants
     * (represent the first 32 bits of the fractional parts of the
     * cube roots of the first sixty-four prime numbers)
     */
    static final int K[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
}

