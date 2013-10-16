package kr.co.bizframe.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.ExtendedDigest;
import kr.co.bizframe.crypto.KCDSA;
import kr.co.bizframe.crypto.generators.KCDSAParametersGenerator;
import kr.co.bizframe.crypto.params.KCDSAKeyParameters;
import kr.co.bizframe.crypto.params.KCDSAParameters;
import kr.co.bizframe.crypto.params.KCDSAPrivateKeyParameters;
import kr.co.bizframe.crypto.params.KCDSAPublicKeyParameters;
import kr.co.bizframe.crypto.params.ParametersWithRandom;
import kr.co.bizframe.crypto.prngs.KCDSARandomGenerator;
import kr.co.bizframe.crypto.util.ByteUtil;

import org.apache.log4j.Logger;

public class KCDSASigner implements KCDSA {

	KCDSAKeyParameters key;

	ExtendedDigest digest;
	SecureRandom random;

	private static BigInteger TWO = BigInteger.valueOf(2);

	private BigInteger k, r;

	private boolean _test = Boolean.getBoolean("bfsec.test.vector");
	private boolean _debug = Boolean.getBoolean("bfsec.debug");
	private Logger _logger = Logger.getLogger(KCDSASigner.class);

	public void init(boolean forSigning, CipherParameters param) {

		if (forSigning) {
			if (param instanceof ParametersWithRandom) {
				ParametersWithRandom rParam = (ParametersWithRandom) param;

				this.random = rParam.getRandom();
				this.key = (KCDSAPrivateKeyParameters) rParam.getParameters();
			} else {
				this.random = new SecureRandom();
				this.key = (KCDSAPrivateKeyParameters) param;
			}
		} else {
			this.key = (KCDSAPublicKeyParameters) param;
		}

		prepare();
	}

	public void prepare() {

		KCDSAParameters params = key.getParameters();
		if (key instanceof KCDSAPrivateKeyParameters) {
			KCDSAPrivateKeyParameters pParam = (KCDSAPrivateKeyParameters) key;

			// pre generated K, R
			BigInteger q = params.getQ();
			int qBitLength = q.bitLength();
			KCDSARandomGenerator prng = new KCDSARandomGenerator();

			byte[] randomInput = new byte[qBitLength / 8];
			random.nextBytes(randomInput);
			BigInteger kKey = new BigInteger(randomInput);
			if (_test) {
				kKey = new BigInteger(new byte[] { (byte) 0x55, (byte) 0x2d,
						(byte) 0xaa, (byte) 0x16, (byte) 0x42, (byte) 0xb9,
						(byte) 0x11, (byte) 0x14, (byte) 0xf9, (byte) 0x95,
						(byte) 0x22, (byte) 0x00, (byte) 0x4f, (byte) 0xd4,
						(byte) 0xa0, (byte) 0xc3, (byte) 0xc6, (byte) 0x3e,
						(byte) 0xf6, (byte) 0x9f });
			}
			random.nextBytes(randomInput);
			if (_test) {
				randomInput = new byte[] { (byte) 0x1b, (byte) 0xf1,
						(byte) 0x23, (byte) 0xb0, (byte) 0x27, (byte) 0x52,
						(byte) 0xe2, (byte) 0xc9, (byte) 0xed, (byte) 0x81,
						(byte) 0x51, (byte) 0x74, (byte) 0x69, (byte) 0xf2,
						(byte) 0x0b, (byte) 0x0c, (byte) 0x19, (byte) 0xa9,
						(byte) 0x97, (byte) 0xa4 };
			}
			BigInteger kSeed = prng.nextValue(randomInput, qBitLength);

			BigInteger kVal = kKey.add(kSeed).mod(TWO.pow(qBitLength));

			k = prng.nextValue(ByteUtil.toByteArray(kVal), qBitLength).mod(q);
			if (_debug) {
				_logger.debug("kSeed: " + ByteUtil.toHexString(kSeed));
				_logger.debug("kKey: " + ByteUtil.toHexString(kKey));
				_logger.debug("kVal: " + ByteUtil.toHexString(kVal));
				_logger.debug("K: " + ByteUtil.toHexString(k));
			}

			BigInteger w = params.getG().modPow(k, params.getP());
			update(w);
			r = getDigest(params.getQ());

			// pre calculated Z
			BigInteger inverseXmodQ = pParam.getX().modInverse(params.getQ());
			BigInteger y = params.getG().modPow(inverseXmodQ, params.getP());
			BigInteger z = y.mod(TWO.pow(digest.getByteLength() * 8));
			update(z);

			if (_debug) {
				_logger.debug("W: " + ByteUtil.toHexString(w));
				_logger.debug("R: " + ByteUtil.toHexString(r));
				_logger.debug("Z: " + ByteUtil.toHexString(z));
			}
		} else if (key instanceof KCDSAPublicKeyParameters) {
			KCDSAPublicKeyParameters pParam = (KCDSAPublicKeyParameters) key;
			BigInteger z = pParam.getY().mod(
					TWO.pow(digest.getByteLength() * 8));
			update(z);
		}
	}

	public BigInteger[] generateSignature(byte[] message) {
		KCDSAParameters params = key.getParameters();
		KCDSAPrivateKeyParameters pParam = (KCDSAPrivateKeyParameters) key;
		verifyKeyParameters(params);

		BigInteger s = BigInteger.ZERO;

		while (true) {
			BigInteger h = calculateE(params.getQ(), message);
			BigInteger e = r.xor(h).mod(params.getQ());
			s = pParam.getX().multiply(k.subtract(e)).mod(params.getQ());

			if (_debug) {
				_logger.debug("H: " + ByteUtil.toHexString(h));
				_logger.debug("E: " + ByteUtil.toHexString(e));
				_logger.debug("S: " + ByteUtil.toHexString(s));
			}

			if (s.equals(BigInteger.ZERO))
				prepare();
			else
				break;
		}

		return new BigInteger[] { r, s };
	}

	public boolean verifySignature(byte[] message, BigInteger r, BigInteger s) {
		KCDSAParameters params = key.getParameters();
		KCDSAPublicKeyParameters pParam = (KCDSAPublicKeyParameters) key;
		verifyKeyParameters(params);
		BigInteger zero = BigInteger.valueOf(0);

		if (r.bitLength() > digest.getDigestSize() * 8) {
			if (_debug) {
				_logger
						.debug("[IllegalArgument] R's bit length must be less than "
								+ (digest.getDigestSize() * 8)
								+ ". but, "
								+ r.bitLength());
			}
			return false;
		}
		if (zero.compareTo(s) >= 0 || params.getQ().compareTo(s) <= 0) {
			if (_debug) {
				_logger.debug("[IllegalArgument] S must be 0 < S < Q("
						+ params.getQ().intValue() + "). but, " + s.intValue());
			}
			return false;
		}

		BigInteger h = calculateE(params.getQ(), message);
		// E = (R xor H) mod Q
		BigInteger e = r.xor(h).mod(params.getQ());

		BigInteger p = params.getP();
		// W = (Y^S * G^E) mod P
		BigInteger w = ((pParam.getY().modPow(s, p)).multiply(params.getG()
				.modPow(e, p))).mod(p);
		update(w);
		BigInteger rr = getDigest(params.getQ());

		if (_debug) {
			_logger.debug("H': " + ByteUtil.toHexString(h));
			_logger.debug("E': " + ByteUtil.toHexString(e));
			_logger.debug("W': " + ByteUtil.toHexString(w));
			_logger.debug("h(W): " + ByteUtil.toHexString(rr));
		}

		return r.equals(rr);
	}

	private void update(byte[] b) {
		digest.update(b, 0, b.length);
	}

	private void update(BigInteger bi) {
		update(ByteUtil.toByteArray(bi));
	}

	private BigInteger calculateE(BigInteger n, byte[] message) {
		if (n.bitLength() >= message.length * 8) {
			return new BigInteger(1, message);
		} else {
			byte[] trunc = new byte[n.bitLength() / 8];

			System.arraycopy(message, 0, trunc, 0, trunc.length);

			return new BigInteger(1, trunc);
		}
	}

	private BigInteger getDigest(BigInteger q) {
		return calculateE(q, getDigest());
	}

	private byte[] getDigest() {
		byte[] out = new byte[digest.getDigestSize()];
		digest.doFinal(out, 0);
		return out;
	}

	private void verifyKeyParameters(KCDSAParameters params) {
		KCDSAParametersGenerator verifier = new KCDSAParametersGenerator();
		verifier.init(params.getP().bitLength(), params.getQ().bitLength(), 80,
				random);
		if (!verifier.verifyParameters(params)) {
			if (_debug) {
				_logger
						.debug("[Warning] DO NOT TRUST the Result using this parameters.");
			}
		}
	}

	public void setDigest(ExtendedDigest digest) {
		this.digest = digest;
	}

}
