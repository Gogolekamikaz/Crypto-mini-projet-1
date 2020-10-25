package crypto;

import static crypto.Helper.bytesToString;
import static crypto.Helper.stringToBytes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Decrypt {
	
	
	public static final int ALPHABETSIZE = Byte.MAX_VALUE - Byte.MIN_VALUE + 1 ; //256
	public static final int APOSITION = 97 + ALPHABETSIZE/2; 
	
	//source : https://en.wikipedia.org/wiki/Letter_frequency
	public static final double[] ENGLISHFREQUENCIES = {0.08497,0.01492,0.02202,0.04253,0.11162,0.02228,0.02015,0.06094,0.07546,0.00153,0.01292,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.07587,0.06327,0.09356,0.02758,0.00978,0.0256,0.0015,0.01994,0.00077};
	
	/**
	 * Method to break a string encoded with different types of cryptosystems
	 * @param type the integer representing the method to break : 0 = Caesar, 1 = Vigenere, 2 = XOR
	 * @return the decoded string or the original encoded message if type is not in the list above.
	 */
	public static String breakCipher(String cipher, int type) {
		//TODO : COMPLETE THIS METHOD
		
		return null; //TODO: to be modified
	}
	
	
	/**
	 * Converts a 2D byte array to a String
	 * @param bruteForceResult a 2D byte array containing the result of a brute force method
	 */
	public static String arrayToString(byte[][] bruteForceResult) {
		String bruteForceStringResult = "";
		
		for(int keyNumber = 0; keyNumber<bruteForceResult.length; ++keyNumber)
		{
			byte decodedBytes[] = new byte[bruteForceResult[0].length]; //Taille du tableau des bytes encodés
			for(int byteIndex = 0; byteIndex < bruteForceResult[0].length; ++ byteIndex)
			{
				decodedBytes[byteIndex] = bruteForceResult[keyNumber][byteIndex];
			}
			String byteTableString = Helper.bytesToString(decodedBytes); //Associe le i ème tableau de bytes à ses Strings
			
			bruteForceStringResult += " - - - - - /!\\ TRY N°"+ (int)(keyNumber+1)+"/!\\ - - - - - "+ System.lineSeparator() + byteTableString + System.lineSeparator(); //Ajoute l'équivalene en String du i ème tableau au texte final qui sera affiché
			
		}
		return bruteForceStringResult;
	}
	
	
	//-----------------------Caesar-------------------------
	
	/**
	 *  Method to decode a byte array  encoded using the Caesar scheme
	 * This is done by the brute force generation of all the possible options
	 * @param cipher the byte array representing the encoded text
	 * @return a 2D byte array containing all the possibilities
	 */
	public static byte[][] caesarBruteForce(byte[] cipher) {
		byte[][] decodedPossibilities = new byte[256][cipher.length]; 
		for(int keyTry = -128; keyTry <128; ++keyTry)
		{
			for(int encodedByteIndex = 0; encodedByteIndex < cipher.length; ++ encodedByteIndex)
			{
				if(cipher[encodedByteIndex] != Encrypt.SPACE)
				{
					decodedPossibilities[keyTry+128][encodedByteIndex] = (byte)(cipher[encodedByteIndex] - keyTry);
				}
				else 
				{
					decodedPossibilities[keyTry+128][encodedByteIndex] = (byte)(cipher[encodedByteIndex]);
				}
			}
		}
		return decodedPossibilities;
	}	
	
	
	/**
	 * Method that finds the key to decode a Caesar encoding by comparing frequencies
	 * @param cipherText the byte array representing the encoded text
	 * @return the encoding key
	 */
	public static byte caesarWithFrequencies(byte[] cipherText) {
		float[] frequencies = computeFrequencies(cipherText);
		byte deducedKey = caesarFindKey(frequencies);
		return deducedKey;
	}
	
	/**
	 * Method that computes the frequencies of letters inside a byte array corresponding to a String
	 * @param cipherText the byte array 
	 * @return the character frequencies as an array of float
	 */
	public static float[] computeFrequencies(byte[] cipherText) {
		
		float[] cardinal = new float[ALPHABETSIZE];
		float[] frequencies = new float[ALPHABETSIZE];
		int spaceNumber = 0;
		
		for(int iterator0 = 0; iterator0 < cipherText.length; ++iterator0) //Comptage du nombre d'espaces
		{
			if(cipherText[iterator0] == Encrypt.SPACE)
			{
				spaceNumber += 1;
			}
			
		}
		
		float totalBytesNumber = cipherText.length - spaceNumber; //On ne compte plus les espaces dans le nombre total
		
		for(int iterator = 0; iterator < ALPHABETSIZE; ++iterator)  // Initialisation du tableau cardinal à 0
		{
			cardinal[iterator] = 0;
		}
		
		for(int byteIndex = 0; byteIndex < cipherText.length; ++byteIndex)
		{
			byte iteratedByte = cipherText[byteIndex];
			if (iteratedByte != Encrypt.SPACE)
			{
				int validIteratedByte = iteratedByte + 128;
				cardinal[validIteratedByte] += 1;
			}
		}
				
		for(int numberIndex = 0; numberIndex < ALPHABETSIZE ; ++numberIndex)
		{
			frequencies[numberIndex] = (cardinal[numberIndex])/totalBytesNumber;
		}
		return frequencies; 
	}
	
	
	/**
	 * Method that finds the key used by a  Caesar encoding from an array of character frequencies
	 * @param charFrequencies the array of character frequencies
	 * @return the key
	 */
	public static byte caesarFindKey(float[] charFrequencies) {
		
		float produitScalaireMaximal = 0;
		int indiceProduitScalaireMaximal = 0;
		for(int frequencieIndex = 0; frequencieIndex < ALPHABETSIZE; ++ frequencieIndex)
		{
			float produitScalaire = 0;
			for(int m = frequencieIndex , englishFrequencieIndex = 0; englishFrequencieIndex < ENGLISHFREQUENCIES.length;  m++ , ++englishFrequencieIndex)
			{
				m = m%256;
				produitScalaire += charFrequencies[m]* ENGLISHFREQUENCIES[englishFrequencieIndex];
			}
			if(produitScalaire > produitScalaireMaximal)
			{
				produitScalaireMaximal = produitScalaire;
				indiceProduitScalaireMaximal = frequencieIndex;
			}	
		}
		byte key = (byte)(indiceProduitScalaireMaximal - APOSITION);
		
		return key;
	}
	
	
	
	//-----------------------XOR-------------------------
	
	/**
	 * Method to decode a byte array encoded using a XOR 
	 * This is done by the brute force generation of all the possible options
	 * @param cipher the byte array representing the encoded text
	 * @return the array of possibilities for the clear text
	 */
	public static byte[][] xorBruteForce(byte[] cipher) {

		byte[][] results = new byte[ALPHABETSIZE][cipher.length];

		for(int i = 0; i< results.length; i++){
			results[i] = Encrypt.xor(cipher, (byte)i);
		}

		return results;
	}
	
	
	
	//-----------------------Vigenere-------------------------
	// Algorithm : see  https://www.youtube.com/watch?v=LaWp_Kq0cKs	
	/**
	 * Method to decode a byte array encoded following the Vigenere pattern, but in a clever way, 
	 * saving up on large amounts of computations
	 * @param cipher the byte array representing the encoded text
	 * @return the byte encoding of the clear text
	 */
	public static byte[] vigenereWithFrequencies(byte[] cipher) {
		//TODO : COMPLETE THIS METHOD
		return null; //TODO: to be modified
	}
	
	
	
	/**
	 * Helper Method used to remove the space character in a byte array for the clever Vigenere decoding
	 * @param array the array to clean
	 * @return a List of bytes without spaces
	 */
	public static List<Byte> removeSpaces(byte[] array){
		List<Byte> sanitizedCipher = new ArrayList<Byte>();

		for (int i = 0; i<array.length; i++){
			if(array[i] != Encrypt.SPACE){
				sanitizedCipher.add(array[i]);
			}
		}

		return sanitizedCipher;
	}
	
	
	/**
	 * Method that computes the key length for a Vigenere cipher text.
	 * @param cipher the byte array representing the encoded text without space
	 * @return the length of the key
	 */
	public static int vigenereFindKeyLength(List<Byte> cipher) {

		ArrayList<Integer> maxima = localMaximaIndex(characterCoincidence(cipher));
		int keyLength = 0;

		for (int i = 0; i < (maxima.size()-1); i++){
			keyLength += maxima.get(i+1)- maxima.get(i);
		}

		keyLength = (int) Math.ceil(((double)keyLength)/(maxima.size()-1));

		return keyLength;

	}

	
	
	/**
	 * Takes the cipher without space, and the key length, and uses the dot product with the English language frequencies 
	 * to compute the shifting for each letter of the key
	 * @param cipher the byte array representing the encoded text without space
	 * @param keyLength the length of the key we want to find
	 * @return the inverse key to decode the Vigenere cipher text
	 */
	public static byte[] vigenereFindKey(List<Byte> cipher, int keyLength) {
		//TODO : COMPLETE THIS METHOD
		return null; //TODO: to be modified
	}



	/**
	 * Compare the cipher text with a shifted version of itself and compute how many letters coincide
	 * @param cipher the byte array representing the encoded text
	 * @return a List containing the coincidences for every shifted byte array.
	 */
	public static List<Integer> characterCoincidence(List<Byte> cipher) {

		List<Integer> coincidences = new ArrayList<Integer>();

		for (int shift = 1; shift < cipher.size() ; shift++){
			int coincidence = 0;
			for (int i = 0; i < (cipher.size()-shift); i++){
				if(cipher.get(i).equals(cipher.get(i + shift))){
					++coincidence;
				}
			}
			coincidences.add(coincidence);
		}

		return coincidences;

	}


	/**
	 * Find local maxima in the coincidence ArrayList
	 * @param coincidenceList the Integer ArrayList representing the he coincidences for every shifted byte array
	 * @return an ArrayList containing the index of each local maxima in the ArrayList.
	 */
	public static ArrayList<Integer> localMaximaIndex(List<Integer> coincidenceList) {

		ArrayList<Integer> localMaxima = new ArrayList<Integer>();

		for (int i = 0; i < Math.ceil(coincidenceList.size()/2); i++) {
			int n = coincidenceList.get(i);
			switch(i){
				case 0 :
					if (n>coincidenceList.get(1) && n>coincidenceList.get(2)){
						localMaxima.add(0);
					}
					break;

				case 1 :
					if (n>coincidenceList.get(0) && n>coincidenceList.get(2) && n>coincidenceList.get(3)){
						localMaxima.add(1);
					}
					break;

				default :
					if (n>coincidenceList.get(i-2) && n>coincidenceList.get(i-1) && n>coincidenceList.get(i+1) && n>coincidenceList.get(i+2)){
						localMaxima.add(i);
					}
					break;

			}
		}

		return localMaxima;

	}



	/**
	 * Gives the index of space characters in the cipher array to add them after decoding the message
	 * @param array the byte array representing the encoded text
	 * @return an ArrayList containing the index of all space character bytes in the array.
	 */
	public static ArrayList<Integer> spacesMemorize(byte[] array) {

		ArrayList<Integer> spaceIndex = new ArrayList<Integer>();
		int index = 0;

		for (byte character : array ) {
			if(character == Encrypt.SPACE){
				spaceIndex.add(index);
			}
			index++;
		}

		return spaceIndex;

	}
	
	
	//-----------------------Basic CBC-------------------------
	
	/**
	 * Method used to decode a String encoded following the CBC pattern
	 * @param cipher the byte array representing the encoded text
	 * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return the clear text
	 */
	public static byte[] decryptCBC(byte[] cipher, byte[] iv) {
		//TODO : COMPLETE THIS METHOD	
		return null; //TODO: to be modified
	}
		
		
}
