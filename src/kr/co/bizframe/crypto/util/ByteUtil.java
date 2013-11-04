package kr.co.bizframe.crypto.util;

import java.math.BigInteger;

public final class ByteUtil {

	public static String HEX = "0123456789abcdef";

	public static String toHexString(byte[] b) {
		StringBuffer sb = new StringBuffer();

		for(int i = 0, len = b.length; i < len; i++) {
			sb.append( HEX.charAt( (b[i] >> 4) & 0x0f ) );
			sb.append( HEX.charAt( (b[i]) & 0x0f ) );
		}

		return sb.toString();
	}

	public static String toHexString(int[] b) {
		StringBuffer sb = new StringBuffer();

		for(int i = 0, len = b.length; i < len; i++) {
			sb.append( HEX.charAt( (b[i] >> 28) & 0x0f ) );
			sb.append( HEX.charAt( (b[i] >> 24) & 0x0f ) );
			sb.append( HEX.charAt( (b[i] >> 20) & 0x0f ) );
			sb.append( HEX.charAt( (b[i] >> 16) & 0x0f ) );
			sb.append( HEX.charAt( (b[i] >> 12) & 0x0f ) );
			sb.append( HEX.charAt( (b[i] >> 8) & 0x0f ) );
			sb.append( HEX.charAt( (b[i] >> 4) & 0x0f ) );
			sb.append( HEX.charAt( (b[i]) & 0x0f ) );
		}

		return sb.toString();
	}

	public static String toHexString(byte b) {
		return toHexString(new byte[] { b });
	}

	public static String toHexString(BigInteger biginteger)
    {
        String s = biginteger.toString(16);
        StringBuffer stringbuffer = new StringBuffer(s.length() * 2);
        if(s.startsWith("-"))
        {
            stringbuffer.append("   -");
            s = s.substring(1);
        } else
        {
            stringbuffer.append("    ");
        }
        if(s.length() % 2 != 0)
            s = (new StringBuffer()).append("0").append(s).toString();
        int i = 0;
        do
        {
            if(i >= s.length())
                break;
            stringbuffer.append(s.substring(i, i + 2));
            if((i += 2) != s.length())
                if(i % 64 == 0)
                    stringbuffer.append("\n    ");
                else
                if(i % 8 == 0)
                    stringbuffer.append(" ");
        } while(true);
        return stringbuffer.toString();
    }

	public static byte[] toByteArray(BigInteger bi) {
		if(bi.signum() < 0) {
			return new BigInteger(1, bi.toByteArray()).toByteArray();
		}
		return bi.toByteArray();
	}


	/**
	 *  "0123456789abcdef"의 문자로 구성된 Base-16 형식의 문자열을 byte 배열로 바꿔준다.
	 *
	 * @param hexString Base-16 형식의 문자열
	 * @return byte 배열
	 * @throws NullPointerException 문자열이 <code>null</code>인 경우.
	 * @throws IllegalArgumentException 문자열의 길이가 짝수가 아닌 경우, 또는 Base-16 형식의 문자열이 아닌 경우.
	 * @since 0.4.2
	 */
	public static byte[] toByteArray(boolean removeSpace, String hexString) {
		if(removeSpace){
			hexString = hexString.replaceAll("\\p{Space}", "");
		}

		hexString = hexString.toLowerCase();
		int sLen = hexString.getBytes().length;
		if(sLen % 2 != 0)
			throw new IllegalArgumentException("argument is not an even.");
		byte[] bytes = new byte[sLen >> 1];
		int idx = -1;
		for(int i = 0; i < sLen >> 1; i++) {
			idx = HEX.indexOf(hexString.charAt(i << 1));
			if(idx == -1)
				throw new IllegalArgumentException("invalid base-16 string.");
			bytes[i] |= idx << 4;
			idx = HEX.indexOf(hexString.charAt((i << 1) + 1));
			if(idx == -1)
				throw new IllegalArgumentException("invalid base-16 string.");
			bytes[i] |= idx;
		}
		return bytes;

	}


	public static byte[] toByteArray(String hexString) {
		return toByteArray(false, hexString);
	}

	public static String removeSpace(String ss){
		if(ss == null) return null;
		return ss.replaceAll("\\p{Space}", "");
	}

	public static void main(String[] argv){

		String ss = "1b 73 31 8b 75 0a 01 67 d0";
		ByteUtil.toByteArray(true, ss);

	}
}
