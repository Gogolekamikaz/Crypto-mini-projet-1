package crypto;

import static crypto.Helper.*;/*
 * Part 1: Encode (with note that one can reuse the functions to decode)
 * Part 2: bruteForceDecode (caesar, xor) and CBCDecode
 * Part 3: frequency analysis and key-length search
 * Bonus: CBC with encryption, shell
 */

public class Main {


	//---------------------------MAIN---------------------------
	public static void main(String args[]) {

		String inputMessage = Helper.readStringFromFile("text_two.txt");
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
		//System.out.println(Decrypt.vigenereFindKeyLength(Decrypt.removeSpaces(Helper.stringToBytes("cqqog mpwuoëh"))));

		System.out.println("------PAD------");
		System.out.println(bytesToString(Encrypt.generatePad(5)));

		System.out.println("------OTP------");
		testOTP(messageBytes);

		System.out.println("------CBC------");
		testCBC(messageBytes);

		/*System.out.println(Decrypt.caesarWithFrequencies(stringToBytes(Helper.readStringFromFile("challenge-encrypted.txt"))));
		System.out.println(bytesToString(Encrypt.caesar(stringToBytes(Helper.readStringFromFile("challenge-encrypted.txt")), (byte)-107)));*/
		/*System.out.println(bytesToString(Decrypt.vigenereWithFrequencies(stringToBytes(Helper.readStringFromFile("challenge-encrypted.txt")))));
		System.out.println(bytesToString(Decrypt.vigenereWithKey(stringToBytes(readStringFromFile("challenge-encrypted.txt")), Decrypt.vigenereWithFrequencies(stringToBytes(Helper.readStringFromFile("challenge-encrypted.txt"))))));
*/
		// TODO: TO BE COMPLETED

		//SignaturesCheck.check();

		//System.out.println(bytesToString(Encrypt.cbc(new byte[10], new byte[8])));

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
		decodingKey = (byte)(-decodingKey); // Important pour pouvoir correctement décoder le message. En effet, on décode on encodant avec l'opposé de la clé de chiffrement.
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
		System.out.println("Exemple du diapo :");
		System.out.println(Helper.bytesToString(Encrypt.vigenere(Helper.stringToBytes("bonne journée"), new byte[]{(byte) 1, (byte) 2, (byte) 3}, false)));
		/*
		//Decoding with key
		String sD = bytesToString(Encrypt.vigenere(result, stringToBytes("Î\u009DºÛË")));
		System.out.println("Decoded knowing the key : " + sD);*/

		System.out.println("Decoded without knowing the key (key lenght) : ");
		System.out.println(Decrypt.vigenereFindKeyLength(Decrypt.removeSpaces(result)));
		System.out.println(bytesToString(Decrypt.vigenereFindKey(Decrypt.removeSpaces(result), Decrypt.vigenereFindKeyLength(Decrypt.removeSpaces(result)))));
		System.out.println(bytesToString(Decrypt.vigenereWithFrequencies(result)));


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

	//Run the Encoding and Decoding using the CBC pattern
	public static void testCBC(byte[] string) {
		//Encoding
		byte[] padTest = {49, 50, 51}; //Encrypt.generatePad(5);
		byte[] result = Encrypt.cbc(string, padTest);
		String s = bytesToString(result);
		System.out.println("Encoded : " + s);

		//Decoding with key
		String sD = bytesToString(Decrypt.decryptCBC(result, padTest));
		System.out.println("Decoded knowing the key : " + sD);

	}
	
//TODO : TO BE COMPLETED
	
}
