package crypto;

import java.util.Random;
import static crypto.Helper.*;

public class Encrypt {
	
	public static final int CAESAR = 0;
	public static final int VIGENERE = 1;
	public static final int XOR = 2;
	public static final int ONETIME = 3;
	public static final int CBC = 4; 
	
	public static final byte SPACE = 32;
	
	final static Random rand = new Random();
	
	//-----------------------General-------------------------
	
	/**
	 * General method to encode a message using a key, you can choose the method you want to use to encode.
	 * @param message the message to encode already cleaned
	 * @param key the key used to encode
	 * @param type the method used to encode : 0 = Caesar, 1 = Vigenere, 2 = XOR, 3 = One time pad, 4 = CBC
	 * 
	 * @return an encoded String
	 * if the method is called with an unknown type of algorithm, it returns the original message
	 */
	public static String encrypt(String message, String key, int type) {
		byte[] inputKeyTable = Helper.stringToBytes(key); // /!\ Tableau des clés (input utilisateur)
		byte[] plainText = Helper.stringToBytes(message);
		
		// Generation du tableau des clés valides (modulo 256)
		byte[] validKeyTable = new byte[inputKeyTable.length]; // Tableau "validé" avec les modulo. C'est peut être inutile en vrai...
		for(int keyIndex = 0; keyIndex < inputKeyTable.length; ++keyIndex)
		{
			validKeyTable[keyIndex] = (byte)(inputKeyTable[keyIndex] % 256);
		}

		String encodedStrings;

		switch(type){

			case CAESAR:
				byte ceasarKey = validKeyTable[0]; //La clé du chiffrement césar ne contient qu'un seul caractère
				encodedStrings = Helper.bytesToString(caesar(plainText, ceasarKey, false));
				return encodedStrings;

			case VIGENERE:
				return null;

			case XOR:
				byte xorKey = validKeyTable[0]; //La clé du chiffrement xor ne contient qu'un seul caractère
				encodedStrings = Helper.bytesToString(xor(plainText, xorKey));
				return encodedStrings;

			case ONETIME:
				return null;

			case CBC:
				return null;

			default:
				return null;

		}

	}
	
	
	//-----------------------Caesar-------------------------
	
	/**
	 * Method to encode a byte array message using a single character key
	 * the key is simply added to each byte of the original message
	 * @param plainText The byte array representing the string to encode
	 * @param key the byte corresponding to the char we use to shift
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */
	public static byte[] caesar(byte[] plainText, byte key, boolean spaceEncoding) {
		assert(plainText != null);
		byte[] encodedText = new byte[plainText.length];
		for(int byteIndex = 0; byteIndex < plainText.length; ++byteIndex)
		{			
			if(!spaceEncoding) // Si on choisit de ne pas encoder les espaces
			{
				if(plainText[byteIndex] == SPACE) // Si charactère associé au byte est un espace
				{
					encodedText[byteIndex] = plainText[byteIndex]; // Aucun décalage
				}
				else
				{
					encodedText[byteIndex] = (byte) (plainText[byteIndex] + key);
				}
			}
			else 
			{
			encodedText[byteIndex] = (byte) (plainText[byteIndex] + key); 
			}
		}
		return encodedText;
	}
	
	/**
	 * Method to encode a byte array message  using a single character key
	 * the key is simply added  to each byte of the original message
	 * spaces are not encoded
	 * @param plainText The byte array representing the string to encode
	 * @param key the byte corresponding to the char we use to shift
	 * @return an encoded byte array
	 */
	public static byte[] caesar(byte[] plainText, byte key) {
		byte[] encodedText = new byte[plainText.length];
		for (int byteIndex = 0; byteIndex < plainText.length; ++byteIndex) {
			if (plainText[byteIndex] == 20) // Si charactère associé au byte est un espace
			{
				encodedText[byteIndex] = plainText[byteIndex]; // Aucun décalage

			} else {
				encodedText[byteIndex] = (byte) (plainText[byteIndex] + key);
			}
		}
		return encodedText;
	}

	
	
	//-----------------------XOR-------------------------
	
	/**
	 * Method to encode a byte array using a XOR with a single byte long key
	 * @param plainText the byte array representing the string to encode
	 * @param key the byte we will use to XOR
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */

	public static byte[] xor(byte[] plainText, byte key, boolean spaceEncoding) {

		byte[] encodedBytes = new byte[plainText.length];
		if(spaceEncoding){
			for (int i = 0; i< encodedBytes.length; i++) {
				encodedBytes[i] = (byte)(plainText[i] ^ key);
			}
			return encodedBytes;
		} else {
			for (int i = 0; i< encodedBytes.length; i++) {
				if(plainText[i] != SPACE){
					encodedBytes[i] = (byte)(plainText[i] ^ key);
				} else {
					encodedBytes[i] = plainText[i];
				}
			}
			return encodedBytes;
		}
	}

	/**
	 * Method to encode a byte array using a XOR with a single byte long key
	 * spaces are not encoded
	 * @param key the byte we will use to XOR
	 * @return an encoded byte array
	 */
	public static byte[] xor(byte[] plainText, byte key) {

		byte[] encodedBytes = new byte[plainText.length];
		for (int i = 0; i< encodedBytes.length; i++) {
			if(plainText[i] != SPACE){
				encodedBytes[i] = (byte)(plainText[i] ^ key);
			} else {
				encodedBytes[i] = plainText[i];
			}
		}
		return encodedBytes;
	}

	//-----------------------Vigenere-------------------------
	
	/**
	 * Method to encode a byte array using a byte array keyword
	 * The keyword is repeated along the message to encode
	 * The bytes of the keyword are added to those of the message to encode
	 * @param plainText the byte array representing the message to encode
	 * @param keyword the byte array representing the key used to perform the shift
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array 
	 */
	public static byte[] vigenere(byte[] plainText, byte[] keyword, boolean spaceEncoding) {

		byte[] encodedBytes = new byte[plainText.length];

		for(int i = 0; i< plainText.length; i++){
			if(spaceEncoding){
				if(plainText[i] != SPACE){
					encodedBytes[i] = (byte) (plainText[i] + keyword[i% keyword.length]);
				} else {
					encodedBytes[i] = plainText[i];
				}
			} else {
				encodedBytes[i] = (byte) (plainText[i] + keyword[i% keyword.length]);
			}
		}

		return encodedBytes;
	}
	
	/**
	 * Method to encode a byte array using a byte array keyword
	 * The keyword is repeated along the message to encode
	 * spaces are not encoded
	 * The bytes of the keyword are added to those of the message to encode
	 * @param plainText the byte array representing the message to encode
	 * @param keyword the byte array representing the key used to perform the shift
	 * @return an encoded byte array 
	 */
	public static byte[] vigenere(byte[] plainText, byte[] keyword) {
		byte[] encodedBytes = new byte[plainText.length];

		for(int i = 0; i< plainText.length; i++){
			if(plainText[i] != SPACE){
				encodedBytes[i] = (byte) (plainText[i] + keyword[i% keyword.length]);
			} else {
				encodedBytes[i] = plainText[i];
			}
		}
		return encodedBytes;
	}
	
	
	
	//-----------------------One Time Pad-------------------------
	
	/**
	 * Method to encode a byte array using a one time pad of the same length.
	 *  The method  XOR them together.
	 * @param plainText the byte array representing the string to encode
	 * @param pad the one time pad
	 * @return an encoded byte array
	 */

	public static byte[] oneTimePad(byte[] plainText, byte[] pad) {
		try{
			byte[] encodedBytes = new byte[plainText.length];
			for(int i = 0; i< plainText.length; i++){
				encodedBytes[i] = (byte)(plainText[i]^pad[i]);
			}
			return encodedBytes;
		} catch (ArrayIndexOutOfBoundsException e) {
			System.out.println("The length of the Pad does not correspond.");
			return null;
		}
	}
	
	
	
	
	//-----------------------Basic CBC-------------------------
	
	/**
	 * Method applying a basic chain block counter of XOR without encryption method. Encodes spaces.
	 * @param plainText the byte array representing the string to encode
	 * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return an encoded byte array
	 */
	public static byte[] cbc(byte[] plainText, byte[] iv) {
		// TODO: COMPLETE THIS METHOD
		
		return null; // TODO: to be modified
	}
	
	
	/**
	 * Generate a random pad/IV of bytes to be used for encoding
	 * @param size the size of the pad
	 * @return random bytes in an array
	 */
	public static byte[] generatePad(int size) {
		byte[] pad = new byte[size];
		for (int i = 0; i< pad.length; i++) {
			pad[i] = (byte)(rand.nextInt(256));
		}
		return pad;
	}
	
	
	
}
