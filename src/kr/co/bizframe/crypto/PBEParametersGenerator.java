/**
 * Copyright (c) 2013-2014 Torpedo Corporations. All rights reserved.
 *
 * BizFrame and BizFrame-related trademarks and logos are
 * trademarks or registered trademarks of Torpedo Corporations
 */
package kr.co.bizframe.crypto;

import kr.co.bizframe.crypto.util.Strings;

/**
 * ��� PBE(Password Based Encryption) �Ű����� �����⿡�� ����� �θ� Ŭ����
 */
public abstract class PBEParametersGenerator {
	protected byte[] password;
	protected byte[] salt;
	protected int iterationCount;

	/**
	 * �⺻ ������
	 */
	protected PBEParametersGenerator() {
	}

	/**
	 * PBE �����⸦ �ʱ�ȭ�Ѵ�.
	 * 
	 * @param password ��й�ȣ
	 * @param salt salt
	 * @param iterationCount �ݺ���
	 */
	public void init(byte[] password, byte[] salt, int iterationCount) {
		this.password = password;
		this.salt = salt;
		this.iterationCount = iterationCount;
	}

	/**
	 * ������ ��й�ȣ�� ��ȯ�Ѵ�.
	 *
	 * @return ������ ��й�ȣ
	 */
	public byte[] getPassword() {
		return password;
	}

	/**
	 * ������ salt�� ��ȯ�Ѵ�.
	 *
	 * @return ������ salt
	 */
	public byte[] getSalt() {
		return salt;
	}

	/**
	 * ������ �ݺ����� ��ȯ�Ѵ�.
	 *
	 * @return ������ �ݺ���
	 */
	public int getIterationCount() {
		return iterationCount;
	}

	/**
	 * �־��� Ű ���̿� ���� ������ �Ű������� �����Ѵ�.
	 *
	 * @param keySize Ű ���� (��Ʈ)
	 * @return ������ �Ű�����
	 */
	public abstract CipherParameters generateDerivedParameters(int keySize);

	/**
	 * �־��� Ű/IV ���̿� ���� ������ �Ű������� �����Ѵ�.
	 *
	 * @param keySize Ű ���� (��Ʈ)
	 * @param ivSize IV ���� (��Ʈ)
	 * @return ������ �Ű�����
	 */
	public abstract CipherParameters generateDerivedParameters(int keySize,
			int ivSize);

	/**
	 * �־��� Ű/IV ���̿� ���� ������ MAC �Ű������� �����Ѵ�.
	 *
	 * @param keySize Ű ���� (��Ʈ)
	 * @return ������ �Ű�����
	 */
	public abstract CipherParameters generateDerivedMacParameters(int keySize);

	/**
	 * PKCS #5�� ���� ASCII ���� �迭�� ����Ʈ �迭�� ��ȯ�Ѵ�.
	 *
	 * @param password ASCII ���� �迭
	 * @return ��ȯ�� ����Ʈ �迭
	 */
	public static byte[] PKCS5PasswordToBytes(char[] password) {
		byte[] bytes = new byte[password.length];

		for (int i = 0; i != bytes.length; i++) {
			bytes[i] = (byte) password[i];
		}

		return bytes;
	}

	/**
	 * PKCS #5�� ���� UTF-8 ���� �迭�� ����Ʈ �迭�� ��ȯ�Ѵ�.
	 *
	 * @param password UTF-8 ���� �迭
	 * @return ��ȯ�� ����Ʈ �迭
	 */
	public static byte[] PKCS5PasswordToUTF8Bytes(char[] password) {
		return Strings.toUTF8ByteArray(password);
	}

	/**
	 * PKCS #12�� ���� (2���� �е� ����Ʈ�� ���� �߰���) �����ڵ�(�� �����) �迭�� 
	 * ����Ʈ �迭�� ��ȯ�Ѵ�.
	 *
	 * @param password �����ڵ�(�� �����) ���� �迭
	 * @return ��ȯ�� ����Ʈ �迭
	 */
	public static byte[] PKCS12PasswordToBytes(char[] password) {
		if (password.length > 0) {
			// +1 for extra 2 pad bytes.
			byte[] bytes = new byte[(password.length + 1) * 2];

			for (int i = 0; i != password.length; i++) {
				bytes[i * 2] = (byte) (password[i] >>> 8);
				bytes[i * 2 + 1] = (byte) password[i];
			}

			return bytes;
		} else {
			return new byte[0];
		}
	}
}
