package kr.co.bizframe.crypto.test.unit.encodings;

import java.math.BigInteger;

import kr.co.bizframe.crypto.ciphers.RSAEngine;
import kr.co.bizframe.crypto.encodings.EMEOAEPEncoding;
import kr.co.bizframe.crypto.encodings.PKCSV1_5Encoding;
import kr.co.bizframe.crypto.params.RSAKeyParameters;
import kr.co.bizframe.crypto.util.ByteUtil;

public class RSAPKCSV1_5Test {



	public void test1024(){

		try{
			//PKCSncoding

			String pubExp = "01 00 01";
			pubExp = ByteUtil.removeSpace(pubExp);

			String priExp =
				"1C BC 9A 76 AD E2 08 52 4C 9D C0 3A 5D E2 E7 26 DF 4E 02 DF 84 F7 31 7C 82 BC DC 70 EA BF C9 05 08 3D 69 78 CC ED 5B 1A 7A DF 63 EA 86 AA 07 DC 74 95 4F AD 7C B0 54 55 19 3A C9 4B 18 6B A1 F7 8E 3C 7D 35 6A D7 32 0B BD B9 4B 44 1C 16 BB 52 62 6C 5F 81 5F DB 60 C7 9F 91 C6 C2 27 78 7E C9 ED 7B 0A 67 AD 2A 68 D5 04 3B C4 8A 13 2D 0A 36 2E A7 20 60 F5 69 51 86 B6 7F 31 6F 45 8A 44 BF D1 40 3D 93 A9 B9 12 CB B5 98 15 91 6A 14 A2 BA D4 F9 A1 ED 57 8E BD 2B 5D 47 2F 62 3B 4B B5 F9 B8 0B 93 57 2B EA 61 BD 10 68 09 4E 41 E8 39 0E 2E 28 A3 51 43 3E DD 1A 09 9A 8C 6E 68 92 60 4A EF 16 3A 43 9B 1C AE 6A 09 5E 68 94 3C A6 7B 18 C8 DC 7F 98 CC 5F 8E FA 22 BB C8 7D 2E 73 57 83 D2 BA A3 8F 4C 17 D5 ED 0C 58 36 6D CE F5 E8 52 DD 3D 6E 0F 63 72 95 43 E2 63 8B 29 14 D7 2A 01";
			priExp = ByteUtil.removeSpace(priExp);

			String modulus =
				"F7 48 D8 D9 8E D0 57 CF 39 8C 43 7F EF C6 15 D7 57 D3 F8 EC E6 F2 C5 80 AE 07 80 76 8F 9E C8 3A AA 08 1F F0 9E 53 17 ED 60 99 C6 3F D1 5C FE 11 17 2F 78 90 8C D5 8C 03 AE C9 3A 48 1F F5 0E 17 22 04 AF ED FC 1F 16 AF DB 99 0A AB 45 BE 19 0B C1 92 59 BD 4A 1B FC DF BE 2A 29 8B 3C 0E 31 8F 78 A3 39 19 88 23 28 DA CA C8 5C B3 5A 0D E5 37 B1 63 76 97 52 17 E5 A5 EA AF 98 26 6B 58 8C 2D BA FD 0B E3 71 C3 49 89 CB 36 E6 23 D7 5E FF ED BE 4A 95 1A 68 40 98 2B C2 79 B3 0F CD 41 DA C8 7C 00 74 D4 62 F1 01 29 00 B8 97 3B 46 AD C7 EA C0 17 70 DF C6 32 EA 96 7F 94 71 E9 78 98 31 F3 A4 10 73 0F F9 14 34 8B E1 11 86 3C 13 37 63 01 07 97 56 A1 47 D8 01 03 CE 9F A6 88 A3 38 E2 2B 2D 91 6C AD 42 D6 73 C9 D0 0F 08 21 4D E5 44 F5 DE 81 2A 9A 94 91 89 07 8B 2B DA 14 B2 8C A6 2F";
			modulus = ByteUtil.removeSpace(modulus);

			RSAKeyParameters pubKey = new RSAKeyParameters(false, new BigInteger(modulus, 16), new BigInteger(pubExp, 16));
			RSAKeyParameters priKey = new RSAKeyParameters(true, new BigInteger(modulus, 16), new BigInteger(priExp, 16));

			RSAEngine rsa = new RSAEngine();
			PKCSV1_5Encoding encoding = new PKCSV1_5Encoding(rsa);

			String smsg = "11 22 33 44";
			smsg = ByteUtil.removeSpace(smsg);
			byte[] msg = ByteUtil.toByteArray(smsg);

			encoding.init(true, pubKey);
			byte[] encrypted = encoding.processBlock(msg, 0, msg.length);
			System.out.println("encrypted = " + ByteUtil.toHexString(encrypted));

		}catch(Exception e){
			e.printStackTrace();
		}

	}

	public static void main(String[] argv){
		RSAPKCSV1_5Test rt = new RSAPKCSV1_5Test();
		rt.test1024();

	}


}
