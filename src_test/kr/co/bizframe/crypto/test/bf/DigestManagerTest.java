package kr.co.bizframe.crypto.test.bf;

import kr.co.bizframe.crypto.BizframeCrypto;
import kr.co.bizframe.crypto.ciphers.CipherManager;
import kr.co.bizframe.crypto.digests.DigestManager;
import kr.co.bizframe.crypto.digests.SHA1Digest;
import kr.co.bizframe.crypto.util.ByteUtil;

public class DigestManagerTest {


	public void test(){

		try{
			BizframeCrypto bc = new BizframeCrypto();
			DigestManager dm = bc.getDigest("SHA256");

			byte[] source = "abc".getBytes();

			dm.update(source, 0, source.length);
			byte[] ss = dm.digest();

			System.out.println("sha hash = "+ ByteUtil.toHexString(ss));

		}catch(Exception e){
			e.printStackTrace();
		}
	}


	public static void main(String[] argv){

		DigestManagerTest bct = new DigestManagerTest();
		bct.test();
	}
}
