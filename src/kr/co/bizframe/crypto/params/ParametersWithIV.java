/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto.params;

import kr.co.bizframe.crypto.CipherParameters;

/**
 * 
 */
public class ParametersWithIV implements CipherParameters {

	private byte[] iv;
	private CipherParameters parameters;

	/**
	 * 
	 * @param parameters
	 * @param iv
	 */
	public ParametersWithIV(CipherParameters parameters, byte[] iv) {
		this(parameters, iv, 0, iv.length);
	}

	/**
	 * 
	 * @param parameters
	 * @param iv
	 * @param ivOff
	 * @param ivLen
	 */
	public ParametersWithIV(CipherParameters parameters, byte[] iv, 
			int ivOff, int ivLen) {
		this.iv = new byte[ivLen];
		this.parameters = parameters;

		System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
	}

	/**
	 * 
	 * @return
	 */
	public byte[] getIV() {
		return iv;
	}

	/**
	 * 
	 * @return
	 */
	public CipherParameters getParameters() {
		return parameters;
	}
}
