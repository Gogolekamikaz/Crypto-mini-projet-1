package crypto;

import static crypto.Helper.cleanString;
import static crypto.Helper.stringToBytes;
import static crypto.Helper.bytesToString;

/*
 * Part 1: Encode (with note that one can reuse the functions to decode)
 * Part 2: bruteForceDecode (caesar, xor) and CBCDecode
 * Part 3: frequency analysis and key-length search
 * Bonus: CBC with encryption, shell
 */

public class Main {


	//---------------------------MAIN---------------------------
	public static void main(String args[]) {


		String inputMessage = Helper.readStringFromFile("text_one.txt");
		String key = "2cF%5";

		String messageClean = cleanString(inputMessage);


		byte[] messageBytes = stringToBytes(messageClean);
		byte[] keyBytes = stringToBytes(key);
		
		
		System.out.println("Original input sanitized : " + messageClean);
		System.out.println();
		
		System.out.println("------Caesar------");
		testCaesar(messageBytes, keyBytes[0]);

		byte key2 = (byte)50;

		System.out.println("------Xor------");
		testXor(messageBytes, key2);

		System.out.println("------Vigenere------");
		testVigenere(messageBytes, keyBytes);

		System.out.println("------PAD------");
		System.out.println(bytesToString(Encrypt.generatePad(5)));

		System.out.println("------OTP------");
		testOTP(messageBytes);



		// TODO: TO BE COMPLETED


		
	}
	
	
	//Run the Encoding and Decoding using the caesar pattern 
	public static void testCaesar(byte[] string , byte key) {
		//Encoding
		byte[] result = Encrypt.caesar(string, key);
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);
		
		//Decoding with key
		String sD = bytesToString(Encrypt.caesar(result, (byte) (-key)));
		System.out.println("Decoded knowing the key : " + sD);
		
		//Decoding without key
		byte[][] bruteForceResult = Decrypt.caesarBruteForce(result);
		String sDA = Decrypt.arrayToString(bruteForceResult);
		Helper.writeStringToFile(sDA, "bruteForceCaesar.txt");
		
		byte decodingKey = Decrypt.caesarWithFrequencies(result);
		String sFD = bytesToString(Encrypt.caesar(result, decodingKey));
		System.out.println("Decoded without knowing the key : " + sFD);
	}

	//Run the Encoding and Decoding using the xor pattern
	public static void testXor(byte[] string , byte key) {
		//Encoding
		byte[] result = Encrypt.xor(string, key);
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);

		//Decoding with key
		String sD = bytesToString(Encrypt.xor(result, (byte)key));
		System.out.println("Decoded knowing the key : " + sD);



		//Decoding without key
		byte[][] bruteForceResult = Decrypt.xorBruteForce(result);
		String sDA = Decrypt.arrayToString(bruteForceResult);
		Helper.writeStringToFile(sDA, "bruteForceXor.txt");

		/*byte decodingKey = Decrypt.caesarWithFrequencies(result);
		String sFD = bytesToString(Encrypt.caesar(result, decodingKey));
		System.out.println("Decoded without knowing the key : " + sFD);*/
	}

	//Run the Encoding and Decoding using the Vigenere pattern
	public static void testVigenere(byte[] string , byte[] key) {
		//Encoding
		byte[] result = Encrypt.vigenere(string, key);
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);

		//Decoding with key
		String sD = bytesToString(Encrypt.vigenere(result, stringToBytes("Î\u009DºÛË")));
		System.out.println("Decoded knowing the key : " + sD);



		/*//Decoding without key
		byte[][] bruteForceResult = Decrypt.xorBruteForce(result);
		String sDA = Decrypt.arrayToString(bruteForceResult);
		Helper.writeStringToFile(sDA, "bruteForceXor.txt");*/

		/*byte decodingKey = Decrypt.caesarWithFrequencies(result);
		String sFD = bytesToString(Encrypt.caesar(result, decodingKey));
		System.out.println("Decoded without knowing the key : " + sFD);*/
	}

	//Run the Encoding and Decoding using the OTP pattern
	public static void testOTP(byte[] string) {
		//Encoding
		byte[] result = Encrypt.oneTimePad(string, Encrypt.generatePad(string.length));
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);

		/*//Decoding with key
		String sD = bytesToString(Encrypt.vigenere(result, stringToBytes("Î\u009DºÛË")));
		System.out.println("Decoded knowing the key : " + sD);*/



		/*//Decoding without key
		byte[][] bruteForceResult = Decrypt.xorBruteForce(result);
		String sDA = Decrypt.arrayToString(bruteForceResult);
		Helper.writeStringToFile(sDA, "bruteForceXor.txt");*/

		/*byte decodingKey = Decrypt.caesarWithFrequencies(result);
		String sFD = bytesToString(Encrypt.caesar(result, decodingKey));
		System.out.println("Decoded without knowing the key : " + sFD);*/
	}
	
//TODO : TO BE COMPLETED
	
}
