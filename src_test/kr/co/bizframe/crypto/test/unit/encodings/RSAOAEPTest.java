package kr.co.bizframe.crypto.test.unit.encodings;

import java.math.BigInteger;

import kr.co.bizframe.crypto.ciphers.RSAEngine;
import kr.co.bizframe.crypto.digests.SHA1Digest;
import kr.co.bizframe.crypto.encodings.EMEOAEPEncoding;
import kr.co.bizframe.crypto.params.RSAKeyParameters;
import kr.co.bizframe.crypto.util.ByteUtil;

public class RSAOAEPTest {



	public void test1024(){

		try{
			//OAEPEncoding

			String pubExp = "01 00 01";
			pubExp = ByteUtil.removeSpace(pubExp);

			String priExp =
				"53 33 9c fd b7 9f c8 46 6a 65 5c 73 16 ac a8 5c"+
				"55 fd 8f 6d d8 98 fd af 11 95 17 ef 4f 52 e8 fd"+
				"8e 25 8d f9 3f ee 18 0f a0 e4 ab 29 69 3c d8 3b"+
				"15 2a 55 3d 4a c4 d1 81 2b 8b 9f a5 af 0e 7f 55"+
				"fe 73 04 df 41 57 09 26 f3 31 1f 15 c4 d6 5a 73"+
				"2c 48 31 16 ee 3d 3d 2d 0a f3 54 9a d9 bf 7c bf"+
				"b7 8a d8 84 f8 4d 5b eb 04 72 4d c7 36 9b 31 de"+
				"f3 7d 0c f5 39 e9 cf cd d3 de 65 37 29 ea d5 d1";

			priExp = ByteUtil.removeSpace(priExp);

			String modulus =

				"a8 b3 b2 84 af 8e b5 0b 38 70 34 a8 60 f1 46 c4"+
				"91 9f 31 87 63 cd 6c 55 98 c8 ae 48 11 a1 e0 ab"+
				"c4 c7 e0 b0 82 d6 93 a5 e7 fc ed 67 5c f4 66 85"+
				"12 77 2c 0c bc 64 a7 42 c6 c6 30 f5 33 c8 cc 72"+
				"f6 2a e8 33 c4 0b f2 58 42 e9 84 bb 78 bd bf 97"+
				"c0 10 7d 55 bd b6 62 f5 c4 e0 fa b9 84 5c b5 14"+
				"8e f7 39 2d d3 aa ff 93 ae 1e 6b 66 7b b3 d4 24"+
				"76 16 d4 f5 ba 10 d4 cf d2 26 de 88 d3 9f 16 fb";

			modulus = ByteUtil.removeSpace(modulus);

			RSAKeyParameters pubKey = new RSAKeyParameters(false, new BigInteger(modulus, 16), new BigInteger(pubExp, 16));
			RSAKeyParameters priKey = new RSAKeyParameters(true, new BigInteger(modulus, 16), new BigInteger(priExp, 16));

			RSAEngine rsa = new RSAEngine();
			EMEOAEPEncoding encoding = new EMEOAEPEncoding(rsa);


			String smsg = "66 28 19 4e 12 07 3d b0 3b a9 4c da 9e f9 53 23"+
							   "97 d5 0d ba 79 b9 87 00 4a fe fe 34";

			smsg = ByteUtil.removeSpace(smsg);
			byte[] msg = ByteUtil.toByteArray(smsg);

			encoding.init(true, pubKey);
			byte[] encrypted = encoding.processBlock(msg, 0, msg.length);
			System.out.println("encrypted = " + ByteUtil.toHexString(encrypted));

		}catch(Exception e){
			e.printStackTrace();
		}

	}




	public void test1024_2(){

		try{
			//OAEPEncoding

			String pubExp = "01 00 01";
			pubExp = ByteUtil.removeSpace(pubExp);

			String priExp =
				"53 33 9c fd b7 9f c8 46 6a 65 5c 73 16 ac a8 5c"+
				"55 fd 8f 6d d8 98 fd af 11 95 17 ef 4f 52 e8 fd"+
				"8e 25 8d f9 3f ee 18 0f a0 e4 ab 29 69 3c d8 3b"+
				"15 2a 55 3d 4a c4 d1 81 2b 8b 9f a5 af 0e 7f 55"+
				"fe 73 04 df 41 57 09 26 f3 31 1f 15 c4 d6 5a 73"+
				"2c 48 31 16 ee 3d 3d 2d 0a f3 54 9a d9 bf 7c bf"+
				"b7 8a d8 84 f8 4d 5b eb 04 72 4d c7 36 9b 31 de"+
				"f3 7d 0c f5 39 e9 cf cd d3 de 65 37 29 ea d5 d1";

			priExp = ByteUtil.removeSpace(priExp);

			String modulus =

				"a8 b3 b2 84 af 8e b5 0b 38 70 34 a8 60 f1 46 c4"+
				"91 9f 31 87 63 cd 6c 55 98 c8 ae 48 11 a1 e0 ab"+
				"c4 c7 e0 b0 82 d6 93 a5 e7 fc ed 67 5c f4 66 85"+
				"12 77 2c 0c bc 64 a7 42 c6 c6 30 f5 33 c8 cc 72"+
				"f6 2a e8 33 c4 0b f2 58 42 e9 84 bb 78 bd bf 97"+
				"c0 10 7d 55 bd b6 62 f5 c4 e0 fa b9 84 5c b5 14"+
				"8e f7 39 2d d3 aa ff 93 ae 1e 6b 66 7b b3 d4 24"+
				"76 16 d4 f5 ba 10 d4 cf d2 26 de 88 d3 9f 16 fb";

			modulus = ByteUtil.removeSpace(modulus);

			RSAKeyParameters pubKey = new RSAKeyParameters(false, new BigInteger(modulus, 16), new BigInteger(pubExp, 16));
			RSAKeyParameters priKey = new RSAKeyParameters(true, new BigInteger(modulus, 16), new BigInteger(priExp, 16));

			RSAEngine rsa = new RSAEngine();
			EMEOAEPEncoding encoding = new EMEOAEPEncoding(rsa, new SHA1Digest(),
					new SHA1Digest(), null);


			String smsg = "d4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49";
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
		RSAOAEPTest rt = new RSAOAEPTest();
		rt.test1024_2();

	}


}
