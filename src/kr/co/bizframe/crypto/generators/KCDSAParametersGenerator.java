package kr.co.bizframe.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import kr.co.bizframe.crypto.params.KCDSAParameters;
import kr.co.bizframe.crypto.params.KCDSAValidationParameters;
import kr.co.bizframe.crypto.prngs.KCDSARandomGenerator;
import kr.co.bizframe.crypto.util.ByteUtil;

import org.apache.log4j.Logger;

public class KCDSAParametersGenerator {

	private int alpha;
	private int beta;
	private int certainty;
	private SecureRandom random;

	private KCDSARandomGenerator prng = new KCDSARandomGenerator();

	private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private boolean _test = Boolean.getBoolean("bfsec.test.vector");
    private boolean _debug = Boolean.getBoolean("bfsec.debug");
    private Logger _logger = Logger.getLogger(KCDSAKeyPairGenerator.class);

    public void init(
			int alpha,
			int beta,
			int certainty,
			SecureRandom random)
	{
		this.alpha = alpha;
		this.beta = beta;
		this.certainty = certainty;
		this.random = random;
	}

	/*
	 * [TTAS.KO-12.001/R1] 표준에 따르면(<b>부기 3.2 소수 P, Q 생성 알고리즘</b>)
	 * count가 2<sup>24</sup>(16777216) 보다 클 경우 다시 시작하도록 기술하고 있지만,
	 * 효율이 떨어져 2<sup>16</sup>(65536)로 낮추어 구현함.
	 */
	public KCDSAParameters generateParameters() {
		BigInteger p = null, q = null, j = null, g = null;
		byte[] seed = new byte[beta / 8];
		int count = 0;
		boolean primesFound = false;

		while(!primesFound) {
			random.nextBytes(seed);
			if(_test) {
				seed = new byte[] {
						(byte) 0x68, (byte) 0xad, (byte) 0xb0, (byte) 0xd1,
						(byte) 0xb6, (byte) 0xae, (byte) 0xf1, (byte) 0x44,
						(byte) 0xa9, (byte) 0x50, (byte) 0xf3, (byte) 0xe7,
						(byte) 0x84, (byte) 0xc9, (byte) 0x89, (byte) 0x3d,
						(byte) 0x36, (byte) 0x04, (byte) 0x09, (byte) 0x0e };
			}
			j = getJ(seed);
			if(!j.isProbablePrime(certainty))
				continue;

			count = 0;

			while(count < 65536) {
				count++;
				q = getQ(seed, count);
				if(!q.isProbablePrime(certainty))
					continue;

				p = TWO.multiply(j).multiply(q).add(ONE);
				if(p.bitLength() > alpha || !p.isProbablePrime(certainty))
					continue;

				if(_debug) {
					_logger.debug( "P: " + ByteUtil.toHexString(p) );
					_logger.debug( "Q: " + ByteUtil.toHexString(q) );
					_logger.debug( "J: " + ByteUtil.toHexString(j) );
				}

				primesFound = true;
				break;
			}
		}

		for(;;) {
			BigInteger t = new BigInteger(p.bitLength(), random);
			if(_test) {
				t = new BigInteger( new byte[] {
						(byte) 0x17, (byte) 0x11, (byte) 0x79, (byte) 0x7e,
						(byte) 0xcf, (byte) 0x9b, (byte) 0xc4, (byte) 0xb8,
						(byte) 0x1c, (byte) 0x5a, (byte) 0xd4, (byte) 0x87,
						(byte) 0xb2, (byte) 0xd9, (byte) 0xf3, (byte) 0xd4,
						(byte) 0xf4, (byte) 0xde, (byte) 0x86, (byte) 0x16,
						(byte) 0xc4, (byte) 0x7b, (byte) 0xb0, (byte) 0x30,
						(byte) 0x35, (byte) 0x5e, (byte) 0xa4, (byte) 0xbf,
						(byte) 0x2a, (byte) 0xb0, (byte) 0x71, (byte) 0x04,
						(byte) 0x0e, (byte) 0xe5, (byte) 0x9c, (byte) 0x95,
						(byte) 0x45, (byte) 0x31, (byte) 0x19, (byte) 0xd7,
						(byte) 0x68, (byte) 0xaf, (byte) 0x7a, (byte) 0x79,
						(byte) 0x95, (byte) 0x13, (byte) 0x3c, (byte) 0x2d,
						(byte) 0xa1, (byte) 0xe3, (byte) 0x02, (byte) 0xc6,
						(byte) 0x91, (byte) 0x28, (byte) 0xaf, (byte) 0xba,
						(byte) 0x12, (byte) 0x9e, (byte) 0x69, (byte) 0x8d,
						(byte) 0xc7, (byte) 0x98, (byte) 0x2f, (byte) 0x56,
						(byte) 0x06, (byte) 0x4c, (byte) 0x70, (byte) 0xc1,
						(byte) 0x8f, (byte) 0xb5, (byte) 0x23, (byte) 0xba,
						(byte) 0x82, (byte) 0x6b, (byte) 0x76, (byte) 0xf8,
						(byte) 0x1e, (byte) 0xfa, (byte) 0x58, (byte) 0xa9,
						(byte) 0x12, (byte) 0x26, (byte) 0xe6, (byte) 0xaf,
						(byte) 0xc9, (byte) 0x6e, (byte) 0x20, (byte) 0x10,
						(byte) 0x97, (byte) 0x58, (byte) 0x99, (byte) 0x40,
						(byte) 0x8e, (byte) 0x78, (byte) 0x5f, (byte) 0xe4,
						(byte) 0xa3, (byte) 0x38, (byte) 0xb3, (byte) 0x98,
						(byte) 0x06, (byte) 0x5f, (byte) 0xfd, (byte) 0x22,
						(byte) 0x2f, (byte) 0xd1, (byte) 0xe1, (byte) 0xb7,
						(byte) 0xa1, (byte) 0xda, (byte) 0x01, (byte) 0xa0,
						(byte) 0x90, (byte) 0xb8, (byte) 0x41, (byte) 0x68,
						(byte) 0xe3, (byte) 0x52, (byte) 0x22, (byte) 0x41,
						(byte) 0xd2, (byte) 0x85, (byte) 0x5a, (byte) 0x4e,
						(byte) 0xfe, (byte) 0x87, (byte) 0x61, (byte) 0x1a
				});
			}
			g = t.modPow(TWO.multiply(j), p);
			// verification.
			if( !(g.modPow(q, p).equals(ONE)) ) {
				continue;
			}

			if(!g.equals(ONE))
				break;
		}

		return new KCDSAParameters(p, q, g, new KCDSAValidationParameters(j, seed, count));
	}

	private BigInteger getJ(byte[] seed) {
		BigInteger U = prng.nextValue(seed, (alpha - beta - 4));
		return TWO.pow(alpha - beta - 1).or(U).or(ONE);
	}

	private byte[] toByteArray(int value) {
		byte[] b = new byte[4];
		for (int i = 0; i < 4; i++) {
			b[3 - i] = (byte) (value >>> (i * 8));
		}
		return b;
	}

	private byte[] concat(byte[] bytes, int n) {
		byte[] nBytes = toByteArray(n);
		byte[] concatBytes = new byte[bytes.length + nBytes.length];
		System.arraycopy(bytes, 0, concatBytes, 0, bytes.length);
		System.arraycopy(nBytes, 0, concatBytes, bytes.length, nBytes.length);
		return concatBytes;
	}

	private BigInteger getQ(byte[] seed, int count) {
		byte[] seedNcount = concat(seed, count);
		BigInteger U = prng.nextValue(seedNcount, beta);
		return TWO.pow(beta - 1).or(U).or(ONE);
	}

	public boolean verifyParameters(KCDSAParameters params) {
		KCDSAValidationParameters vParams = params.getValidationParams();
		if(vParams == null) {
			if(_debug) {
				_logger.debug("[Notification] No ValidationParameters. Ignore verify parameters.");
			}
			return true;
		}

		BigInteger p = params.getP();
		BigInteger q = params.getQ();

		byte[] seed = vParams.getSeed();

		BigInteger jj = getJ(seed);
		BigInteger exp = p.subtract(ONE).divide(TWO.multiply(q));
		if( !jj.equals( exp ) || !jj.equals(vParams.getJ()) ) {
			if(_debug) {
				_logger.debug("Wrong parameter J.");
				_logger.debug("Expected J is " + ByteUtil.toHexString( jj ));
				_logger.debug("But, " + ByteUtil.toHexString( exp ));
			}
			return false;
		}

		BigInteger qq = getQ(seed, vParams.getCounter());
		if( !qq.equals(q) ) {
			if(_debug) {
				_logger.debug("Wrong parameter Q.");
				_logger.debug("Expected Q is " + ByteUtil.toHexString( qq ));
				_logger.debug("But, " + ByteUtil.toHexString( q ));
			}
			return false;
		}

		BigInteger pp = TWO.multiply(jj).multiply(qq).add(ONE);
		if( !pp.isProbablePrime(certainty) || !pp.equals(p) ) {
			if(_debug) {
				_logger.debug("Wrong parameter P.");
				_logger.debug("Expected P is " + ByteUtil.toHexString( pp ));
				_logger.debug("But, " + ByteUtil.toHexString( p ));
			}
			return false;
		}

		if(_debug) {
			_logger.debug("[Notification] Parameters are correct.");
		}
		return true;
	}

}
