/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.ciphers;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import kr.co.bizframe.crypto.BlockCipher;
import kr.co.bizframe.crypto.BufferedBlockCipher;
import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.DataLengthException;
import kr.co.bizframe.crypto.InvalidCipherTextException;
import kr.co.bizframe.crypto.paddings.BlockCipherPadding;
import kr.co.bizframe.crypto.paddings.PaddedBufferedBlockCipher;
import kr.co.bizframe.crypto.params.KeyParameter;
import kr.co.bizframe.crypto.params.ParametersWithIV;

/**
 * 
 */
public class CipherManager {

	private BlockCipher baseEngine;

	private GenericBlockCipher cipher;

	/**
	 * 
	 * @param engine
	 */
	public CipherManager(BlockCipher engine) {
		this.baseEngine = engine;
		this.cipher = new BufferedGenericBlockCipher(engine);
	}

	/**
	 * 
	 * @param encrypting
	 * @param keyBytes
	 */
	public void init(boolean encrypting, byte[] keyBytes) {
		KeyParameter key = new KeyParameter(keyBytes);
		cipher.init(encrypting, key);
	}

	/**
	 * 
	 * @param encrypting
	 * @param keyBytes
	 * @param ivBytes
	 */
	public void init(boolean encrypting, byte[] keyBytes, byte[] ivBytes) {
		KeyParameter key = new KeyParameter(keyBytes);
		ParametersWithIV iv = new ParametersWithIV(key, ivBytes);
		cipher.init(encrypting, iv);
	}

	/**
	 * 
	 * @param input
	 * @param inputOffset
	 * @param inputLen
	 * @return
	 */
	public byte[] update(byte[] input, int inputOffset, int inputLen) {
		int length = cipher.getUpdateOutputSize(inputLen);

		if (length > 0) {
			byte[] out = new byte[length];

			int len = cipher.processBytes(input, inputOffset, inputLen, out, 0);

			if (len == 0) {
				return null;
			} else if (len != out.length) {
				byte[] tmp = new byte[len];
				System.arraycopy(out, 0, tmp, 0, len);
				return tmp;
			}

			return out;
		}

		cipher.processBytes(input, inputOffset, inputLen, null, 0);

		return null;
	}

	/**
	 * 
	 * @param input
	 * @param inputOffset
	 * @param inputLen
	 * @param output
	 * @param outputOffset
	 * @return
	 * @throws ShortBufferException
	 */
	public int update(
			byte[] input, int inputOffset, int inputLen, 
			byte[] output, int outputOffset) throws ShortBufferException {
		try {
			return cipher.processBytes(
					input, inputOffset, inputLen, output, outputOffset);
		} catch (DataLengthException e) {
			throw new ShortBufferException(e.getMessage());
		}
	}

	/**
	 * 
	 * @param input
	 * @param inputOffset
	 * @param inputLen
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] doFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		int len = 0;
		byte[] tmp = new byte[cipher.getOutputSize(inputLen)];

		if (inputLen != 0) {
			len = cipher.processBytes(input, inputOffset, inputLen, tmp, 0);
		}

		try {
			len += cipher.doFinal(tmp, len);
		} catch (DataLengthException e) {
			throw new IllegalBlockSizeException(e.getMessage());
		} catch (InvalidCipherTextException e) {
			throw new BadPaddingException(e.getMessage());
		}

		if (len == tmp.length) {
			return tmp;
		}

		byte[] out = new byte[len];

		System.arraycopy(tmp, 0, out, 0, len);

		return out;
	}

	/**
	 * 
	 * @param input
	 * @param inputOffset
	 * @param inputLen
	 * @param output
	 * @param outputOffset
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public int doFinal(
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws IllegalBlockSizeException,
			BadPaddingException {
		int len = 0;

		if (inputLen != 0) {
			len = cipher.processBytes(
					input, inputOffset, inputLen, output, outputOffset);
		}

		try {
			return (len + cipher.doFinal(output, outputOffset + len));
		} catch (DataLengthException e) {
			throw new IllegalBlockSizeException(e.getMessage());
		} catch (InvalidCipherTextException e) {
			throw new BadPaddingException(e.getMessage());
		}
	}

	static private interface GenericBlockCipher {

		public void init(boolean forEncryption, CipherParameters params)
				throws IllegalArgumentException;

		public String getAlgorithmName();

		public BlockCipher getUnderlyingCipher();

		public int getOutputSize(int len);

		public int getUpdateOutputSize(int len);

		public int processByte(byte in, byte[] out, int outOff)
				throws DataLengthException;

		public int processBytes(byte[] in, int inOff, int len, byte[] out,
				int outOff) throws DataLengthException;

		public int doFinal(byte[] out, int outOff)
				throws IllegalStateException, InvalidCipherTextException;
	}

	private static class BufferedGenericBlockCipher 
		implements GenericBlockCipher {

		private BufferedBlockCipher cipher;

		BufferedGenericBlockCipher(BufferedBlockCipher cipher) {
			this.cipher = cipher;
		}

		BufferedGenericBlockCipher(BlockCipher cipher) {
			this.cipher = new PaddedBufferedBlockCipher(cipher);
		}

		BufferedGenericBlockCipher(BlockCipher cipher,
				BlockCipherPadding padding) {
			this.cipher = new PaddedBufferedBlockCipher(cipher, padding);
		}

		public void init(boolean forEncryption, CipherParameters params)
				throws IllegalArgumentException {
			cipher.init(forEncryption, params);
		}

		public String getAlgorithmName() {
			return cipher.getUnderlyingCipher().getAlgorithmName();
		}

		public BlockCipher getUnderlyingCipher() {
			return cipher.getUnderlyingCipher();
		}

		public int getOutputSize(int len) {
			return cipher.getOutputSize(len);
		}

		public int getUpdateOutputSize(int len) {
			return cipher.getUpdateOutputSize(len);
		}

		public int processByte(byte in, byte[] out, int outOff)
				throws DataLengthException {
			return cipher.processByte(in, out, outOff);
		}

		public int processBytes(byte[] in, int inOff, int len, byte[] out,
				int outOff) throws DataLengthException {
			return cipher.processBytes(in, inOff, len, out, outOff);
		}

		public int doFinal(byte[] out, int outOff)
				throws IllegalStateException, InvalidCipherTextException {
			return cipher.doFinal(out, outOff);
		}
	}


}
