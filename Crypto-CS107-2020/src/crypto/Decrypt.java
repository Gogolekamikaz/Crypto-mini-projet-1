package crypto;

import java.util.*;

import static crypto.Helper.*;
import static crypto.Encrypt.*;

public class Decrypt {
	
	
	public static final int ALPHABETSIZE = Byte.MAX_VALUE - Byte.MIN_VALUE + 1 ; //256
	public static final int APOSITION = 97 + ALPHABETSIZE/2; 

	public static final String[] LANGUAGES = {"French", "English", "German", "Italian", "Spanish"};
	//source : https://en.wikipedia.org/wiki/Letter_frequency
	public static final double[] ENGLISHFREQUENCIES = {0.08497,0.01492,0.02202,0.04253,0.11162,0.02228,0.02015,0.06094,0.07546,0.00153,0.01292,0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.07587,0.06327,0.09356,0.02758,0.00978,0.0256,0.0015,0.01994,0.00077};
	public static final double[][] LANGUAGEFREQUENCIES = {{0.07636,0.00901,0.03260,0.03669,0.14715,0.01066,0.00866,0.00737,0.07529,0.00613,0.00074,0.05456,0.02968,0.07095,0.05796,0.02521,0.01362,0.06693,0.07948,0.07244,0.06311,0.01838,0.00049,0.00427,0.00128,0.00326},
														  ENGLISHFREQUENCIES,
														  {0.06516,0.01886,0.02732,0.05076,0.16396,0.01656,0.03009,0.04577,0.06550,0.00268,0.01417,0.03437,0.02534,0.09776,0.02594,0.00670,0.00018,0.07003,0.07270,0.06154,0.04166,0.00846,0.01921,0.00034,0.00039,0.01134},
														  {0.11745,0.00927,0.04501,0.03736,0.11792,0.01153,0.01644,0.00636,0.10143,0.00011,0.00009,0.06510,0.02994,0.06883,0.09832,0.03056,0.00505,0.06367,0.04981,0.05623,0.03011,0.02097,0.00033,0.00003,0.00020,0.01181},
														  {0.11525,0.02215,0.04019,0.05010,0.12181,0.00692,0.01768,0.00703,0.06247,0.00493,0.00011,0.04967,0.03157,0.06712,0.08683,0.02510,0.00877,0.06871,0.07977,0.04632,0.02927,0.01138,0.00017,0.00215,0.01008,0.00467}};


	/**
	 * Method to break a string encoded with different types of cryptosystems by analysis (without the key)
	 * @param type the integer representing the method to break : 0 = Caesar, 1 = Vigenere, 2 = XOR
	 * @return the decoded string or the original encoded message if type is not in the list above.
	 */
	public static String breakCipher(String cipher, int type) {
		String decodedCipher = "";
		HashMap<String, HashSet<String>> Dictionaries = setDictionaries();
		int max = 0;

		switch (type) {
			case CAESAR -> {
				byte[][] BruteForce = caesarBruteForce(stringToBytes(cipher));
				for (String language : LANGUAGES) {
					for (byte[] decode : BruteForce) {
						int currCount = countWords(bytesToString(decode), Dictionaries.get(language));
						if (currCount > max) {
							if ((100 * currCount) / cipher.length() > 70) {
								break;
							}
							max = currCount;
							decodedCipher = bytesToString(decode);
						}
					}
				}
			}
			case VIGENERE -> decodedCipher = bytesToString(advancedVigenere(stringToBytes(cipher)));
			case XOR -> {
				byte[][] BruteForce2 = xorBruteForce(stringToBytes(cipher));
				for (String language : LANGUAGES) {
					for (byte[] decode : BruteForce2) {
						int currCount = countWords(bytesToString(decode), Dictionaries.get(language));
						if (currCount > max) {
							if ((100 * currCount) / cipher.length() > 70) {
								break;
							}
							max = currCount;
							decodedCipher = bytesToString(decode);
						}
					}
				}
			}
			default -> {
				System.out.println("Vous n'avez pas sélectionné une méthode de déchiffrement valide!");
				decodedCipher = cipher;
			}
		}

		return decodedCipher;
	}


	/**
	 * Method to break a string encoded with different types of cryptosystems with a one-char key
	 * @param type the integer representing the method to break : 0 = Caesar, 1 = Vigenere, 2 = XOR
	 * @return the decoded string or the original encoded message if type is not in the list above.
	 */
	public static String breakCipher(String cipher, int type, byte key) {
		String decodedCipher;

		switch (type) {
			case CAESAR -> decodedCipher = bytesToString(caesarWithKey(stringToBytes(cipher), key));
			case VIGENERE -> decodedCipher = bytesToString(vigenereWithKey(stringToBytes(cipher), new byte[]{key}));
			case XOR -> decodedCipher = bytesToString(xorWithKey(stringToBytes(cipher), key));
			default -> {
				decodedCipher = cipher;
				System.out.println("Vous n'avez pas sélectionné une méthode de déchiffrement valide!");
			}
		}

		return decodedCipher;
	}


	/**
	 * Method to break a string encoded with different types of cryptosystems with a multi-char key
	 * @param type the integer representing the method to break : 1 = Vigenere, 3 = OTP, 4 = CBC
	 * @return the decoded string or the original encoded message if type is not in the list above.
	 */
	public static String breakCipher(String cipher, int type, byte[] key) {
		String decodedCipher;

		switch (type) {
			case CBC -> decodedCipher = bytesToString(decryptCBC(stringToBytes(cipher), key));
			case ONETIME -> decodedCipher = bytesToString(oneTimePad(stringToBytes(cipher), key));
			case VIGENERE -> decodedCipher = bytesToString(vigenereWithKey(stringToBytes(cipher), key));
			default -> {
				decodedCipher = cipher;
				System.out.println("Vous n'avez pas sélectionné une méthode de déchiffrement valide correspondant à la clé!");
			}
		}

		return decodedCipher;
	}
	
	
	/**
	 * Converts a 2D byte array to a String
	 * @param bruteForceResult a 2D byte array containing the result of a brute force method
	 */
	public static String arrayToString(byte[][] bruteForceResult) {
		String bruteForceStringResult = "";

		for (int keyNumber = 0; keyNumber < bruteForceResult.length; ++keyNumber) {
			byte[] decodedBytes = new byte[bruteForceResult[0].length]; //Taille du tableau des bytes encodés
			for (int byteIndex = 0; byteIndex < bruteForceResult[0].length; ++byteIndex) {
				decodedBytes[byteIndex] = bruteForceResult[keyNumber][byteIndex];
			}
			String byteTableString = Helper.bytesToString(decodedBytes); //Associe le i ème tableau de bytes à ses Strings

			bruteForceStringResult += " - - - - - /!\\ TRY N°" + (keyNumber + 1) + "/!\\ - - - - - " + System.lineSeparator() + byteTableString + System.lineSeparator(); //Ajoute l'équivalene en String du i ème tableau au texte final qui sera affiché

		}
		return bruteForceStringResult;
	}
	
	
	//-----------------------Caesar-------------------------

	/**
	 *  Method to decode a byte array encoded using the Caesar scheme knowing the key
	 * This is done by applying the inverse Caesar method in Encrypt to the key and the cipher
	 * @param cipher the byte array representing the encoded text
	 * @param key the key encoding the cipher
	 * @return the decoded string.
	 */
	public static byte[] caesarWithKey(byte[] cipher, byte key) {
		byte[] decodedCaesar = new byte[cipher.length];
		for (int encodedByteIndex = 0; encodedByteIndex < cipher.length; ++encodedByteIndex) {
			if (cipher[encodedByteIndex] != SPACE) {
				decodedCaesar[encodedByteIndex] = (byte) (cipher[encodedByteIndex] - key);
			} else {
				decodedCaesar[encodedByteIndex] = cipher[encodedByteIndex];
			}
		}
		return decodedCaesar;
	}


	/**
	 *  Method to decode a byte array  encoded using the Caesar scheme
	 * This is done by the brute force generation of all the possible options
	 * @param cipher the byte array representing the encoded text
	 * @return a 2D byte array containing all the possibilities
	 */
	public static byte[][] caesarBruteForce(byte[] cipher) {
		byte[][] decodedPossibilities = new byte[256][cipher.length];
		for (int keyTry = -128; keyTry < 128; ++keyTry) {
			for (int encodedByteIndex = 0; encodedByteIndex < cipher.length; ++encodedByteIndex) {
				if (cipher[encodedByteIndex] != SPACE) {
					decodedPossibilities[keyTry + 128][encodedByteIndex] = (byte) (cipher[encodedByteIndex] - keyTry);
				} else {
					decodedPossibilities[keyTry + 128][encodedByteIndex] = cipher[encodedByteIndex];
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
		return caesarFindKey(frequencies);
	}

	/**
	 * Method that finds the key to decode a Caesar encoding by comparing frequencies
	 * @param cipherText the byte array representing the encoded text
	 * @param languageFrequencies the frequencies of letters for a particular language
	 * @return the encoding key
	 */
	public static byte caesarWithFrequencies(byte[] cipherText, double[] languageFrequencies) {
		float[] frequencies = computeFrequencies(cipherText);
		return caesarFindKey(frequencies, languageFrequencies);
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

		//Comptage du nombre d'espaces
		for (byte b : cipherText) {
			if (b == SPACE) {
				spaceNumber += 1;
			}

		}
		
		float totalBytesNumber = cipherText.length - spaceNumber; //On ne compte plus les espaces dans le nombre total
		
		for(int iterator = 0; iterator < ALPHABETSIZE; ++iterator)  // Initialisation du tableau cardinal à 0
		{
			cardinal[iterator] = 0;
		}

		for (byte iteratedByte : cipherText) {
			if (iteratedByte != SPACE) {
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

		for (int frequencieIndex = 0; frequencieIndex < ALPHABETSIZE; ++frequencieIndex) {
			float produitScalaire = 0;
			for (int m = frequencieIndex, englishFrequencieIndex = 0; englishFrequencieIndex < ENGLISHFREQUENCIES.length; m++, ++englishFrequencieIndex) {
				m = m % 256;
				produitScalaire += charFrequencies[m] * ENGLISHFREQUENCIES[englishFrequencieIndex];
			}
			if (produitScalaire > produitScalaireMaximal) {
				produitScalaireMaximal = produitScalaire;
				indiceProduitScalaireMaximal = frequencieIndex;
			}
		}

		return (byte) (indiceProduitScalaireMaximal - APOSITION);
	}


	/**
	 * Method that finds the key used by a  Caesar encoding from an array of character frequencies for a particular language
	 * @param charFrequencies the array of character frequencies
	 * @param languageFrequencies the frequencies of letters for a particular language
	 * @return the key
	 */
	public static byte caesarFindKey(float[] charFrequencies, double[] languageFrequencies) {

		float produitScalaireMaximal = 0;
		int indiceProduitScalaireMaximal = 0;

		for (int frequencieIndex = 0; frequencieIndex < ALPHABETSIZE; ++frequencieIndex) {
			float produitScalaire = 0;
			for (int m = frequencieIndex, languageFrequencyIndex = 0; languageFrequencyIndex < languageFrequencies.length; m++, ++languageFrequencyIndex) {
				m = m % 256;
				produitScalaire += charFrequencies[m] * languageFrequencies[languageFrequencyIndex];
			}
			if (produitScalaire > produitScalaireMaximal) {
				produitScalaireMaximal = produitScalaire;
				indiceProduitScalaireMaximal = frequencieIndex;
			}
		}

		return (byte) (indiceProduitScalaireMaximal - APOSITION);
	}
	
	
	
	//-----------------------XOR-------------------------

	/**
	 * Method to decode a byte array encoded using a XOR knowing the key
	 * This is done by applying the XOR method in Encrypt to the key and the cipher
	 * @param cipher the byte array representing the encoded text
	 * @param key the key encoding the cipher
	 * @return the decoded string.
	 */
	public static byte[] xorWithKey(byte[] cipher, byte key) {
		return xor(cipher, key, false);
	}


	/**
	 * Method to decode a byte array encoded using a XOR 
	 * This is done by the brute force generation of all the possible options
	 * @param cipher the byte array representing the encoded text
	 * @return the array of possibilities for the clear text
	 */
	public static byte[][] xorBruteForce(byte[] cipher) {

		byte[][] results = new byte[ALPHABETSIZE][cipher.length];

		for (int i = 0; i < results.length; i++) {
			results[i] = xor(cipher, (byte) i);
		}

		return results;
	}
	
	
	
	//-----------------------Vigenere-------------------------

	/**
	 * Method to decode a byte array encoded using a Vigenere method knowing the key
	 * This is done by applying the inverse of the Vigenere method in Encrypt to the key and the cipher
	 * @param cipher the byte array representing the encoded text
	 * @param key the key encoding the cipher
	 * @return the decoded string.
	 */
	public static byte[] vigenereWithKey(byte[] cipher, byte[] key) {
		List<Byte> cipherByteWithoutSpace = removeSpaces(cipher);
		ArrayList<Integer> spacesIndex = spacesMemorize(cipher);
		byte[] decodedCipher = new byte[cipher.length];
		int spaceShift = 0;

		for (int i = 0; i < decodedCipher.length; i++) {
			if (spacesIndex.contains(i)) {
				decodedCipher[i] = SPACE;
				++spaceShift;
			} else {
				decodedCipher[i] = (byte) (cipherByteWithoutSpace.get(i - spaceShift) - key[(i - spaceShift) % key.length]);
			}
		}

		return decodedCipher;
	}


	// Algorithm : see  https://www.youtube.com/watch?v=LaWp_Kq0cKs
	/**
	 * Method to decode a byte array encoded following the Vigenere pattern, but in a clever way, 
	 * saving up on large amounts of computations
	 * @param cipher the byte array representing the encoded text
	 * @return the byte encoding the clear text
	 */
	public static byte[] vigenereWithFrequencies(byte[] cipher) {

		List<Byte> cipherByteWithoutSpace = removeSpaces(cipher);

		return vigenereFindKey(cipherByteWithoutSpace, vigenereFindKeyLength(cipherByteWithoutSpace));
	}
	
	
	
	/**
	 * Helper Method used to remove the space character in a byte array for the clever Vigenere decoding
	 * @param array the array to clean
	 * @return a List of bytes without spaces
	 */
	public static List<Byte> removeSpaces(byte[] array) {

		List<Byte> sanitizedCipher = new ArrayList<>();

		for (byte b : array) {
			if (b != SPACE) {
				sanitizedCipher.add(b);
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

		if (maxima.size() > 1) {
			for (int i = 0; i < (maxima.size() - 1); i++) {
				keyLength += maxima.get(i + 1) - maxima.get(i);
			}

			keyLength = (int) Math.ceil(((double) keyLength) / (maxima.size() - 1));

		} else {
			keyLength = maxima.get(0) + 1;
		}

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

		byte[] key = new byte[keyLength];

		for (int i = 0; i < keyLength; i++) {
			byte[] cipherChar = new byte[(int) Math.ceil(cipher.size() / keyLength) + 1];

			for (int charIndex = i, j = 0; charIndex < cipher.size(); charIndex += keyLength, j++) {
				cipherChar[j] = cipher.get(charIndex);
			}

			key[i] = caesarWithFrequencies(cipherChar);
		}

		return key;
	}


	/**
	 * Takes the cipher without space, and the key length, and uses the dot product with the English language frequencies
	 * to compute the shifting for each letter of the key
	 * @param cipher the byte array representing the encoded text without space
	 * @param keyLength the length of the key we want to find
	 * @param frequencies the frequencies of letters for a particular language
	 * @return the inverse key to decode the Vigenere cipher text
	 */
	public static byte[] vigenereFindKey(List<Byte> cipher, int keyLength, double[] frequencies) {

		byte[] key = new byte[keyLength];

		for (int i = 0; i < keyLength; i++) {
			byte[] cipherChar = new byte[(int) Math.ceil(cipher.size() / keyLength) + 1];

			for (int charIndex = i, j = 0; charIndex < cipher.size(); charIndex += keyLength, j++) {
				cipherChar[j] = cipher.get(charIndex);
			}

			key[i] = caesarWithFrequencies(cipherChar, frequencies);
		}

		return key;
	}



	/**
	 * Compare the cipher text with a shifted version of itself and compute how many letters coincide
	 * @param cipher the byte array representing the encoded text
	 * @return a List containing the coincidences for every shifted byte array.
	 */
	public static List<Integer> characterCoincidence(List<Byte> cipher) {

		List<Integer> coincidences = new ArrayList<>();

		for (int shift = 1; shift < cipher.size(); shift++) {
			int coincidence = 0;//-15;
			for (int i = 0; i < (cipher.size() - shift); i++) {
				if (cipher.get(i).equals(cipher.get(i + shift))) {
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

		ArrayList<Integer> localMaxima = new ArrayList<>();

		for (int i = 0; i <= Math.ceil(coincidenceList.size() / 2); i++) {
			int n = coincidenceList.get(i);
			switch (i) {
				case 0:
					if (n > coincidenceList.get(1) && n > coincidenceList.get(2)) {
						localMaxima.add(0);
					}
					break;

				case 1:
					if (n > coincidenceList.get(0) && n > coincidenceList.get(2) && n > coincidenceList.get(3)) {
						localMaxima.add(1);
					}
					break;

				default:
					if (n > coincidenceList.get(i - 2) && n > coincidenceList.get(i - 1) && n > coincidenceList.get(i + 1) && n > coincidenceList.get(i + 2)) {
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

		ArrayList<Integer> spaceIndex = new ArrayList<>();
		int index = 0;

		for (byte character : array) {
			if (character == SPACE) {
				spaceIndex.add(index);
			}
			index++;
		}

		return spaceIndex;

	}


	//---------------BONUS : Advanced Vigenere-----------------

	/**
	 * Method to decode a byte array encoded using a Vigenere method without knowing the key
	 * This is done by searching for the right key in different language, up to a key length of 100
	 * @param cipher the byte array representing the encoded text
	 * @return the decoded byte.
	 */
	public static byte[] advancedVigenere(byte[] cipher){
		HashMap<String, HashSet<String>> Dictionaries = setDictionaries();

		byte[] decrypted = new byte[cipher.length];
		int max = 0, index = 0;

		for (String language : Dictionaries.keySet()){
			HashSet<String> currLanguage = Dictionaries.get(language);
			String currDecrypt = breakForLanguage(cipher, currLanguage, LANGUAGEFREQUENCIES[index]);
			int currCount = countWords(currDecrypt, currLanguage);
			if (currCount > max){
				if((100*currCount)/cipher.length > 70){
					break;
				}
				max = currCount;
				decrypted = stringToBytes(currDecrypt);
			}
			++index;
		}

		return decrypted;
	}


	/**
	 * Method used to initialize the dictionaries in French, English, Italian, German and Spanish
	 * @return the HashMap containing all the Dictionaries
	 */
	public static HashMap<String, HashSet<String>> setDictionaries(){
		HashMap<String, HashSet<String>> Dictionaries = new HashMap<>();

		for (String language : LANGUAGES ) {
			String[] dictionaryLanguage = cleanString(readStringFromFile(language, "src\\Dictionaries")).split(" ");
			HashSet<String> dict = new HashSet<>();

			Collections.addAll(dict, dictionaryLanguage);

			Dictionaries.put(language, dict);

		}

		return Dictionaries;
	}


	/**
	 * Method used to count the number of correct words in a given String for a particular language
	 * @param decryptedMessage the String to check
	 * @param dictionary the HashSet containing a dictionary in a particular language
	 * @return the number of words well decrypted.
	 */
	public static int countWords(String decryptedMessage, HashSet<String> dictionary){
		String[] words = decryptedMessage.split(" ");
		int validWords = 0;
		for (String word: words){
			if (dictionary.contains(word.toLowerCase())){
				validWords++;
			}
		}
		return validWords;
	}


	/**
	 * Method used to find the best result of decoded string obtained using a particular language
	 * @param cipher the byte array representing the encoded text
	 * @param dictionary the HashSet containing a dictionary in a particular language
	 * @param frequencies the frequencies of letters for a particular language
	 * @return the number of words well decrypted.
	 */
	public static String breakForLanguage(byte[] cipher, HashSet<String> dictionary, double[] frequencies){
		String decryptedString = "";
		int mostCorrectWord = 0;
		for (int i=1; i<100; i++){
			byte[] key = vigenereFindKey(removeSpaces(cipher), i, frequencies);
			String decryptedMessage = bytesToString(vigenereWithKey(cipher, key));
			int validWords = countWords(decryptedMessage, dictionary);
			if (validWords > mostCorrectWord){
				if((100*validWords)/cipher.length > 70){
					break;
				}
				mostCorrectWord = validWords;
				decryptedString = decryptedMessage;
			}
		}
		return decryptedString;
	}



	
	//-----------------------Basic CBC-------------------------
	
	/**
	 * Method used to decode a String encoded following the CBC pattern
	 * @param cipher the byte array representing the encoded text
	 * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return the clear text
	 */
	public static byte[] decryptCBC(byte[] cipher, byte[] iv) {

		byte[] decodedBytes = new byte[cipher.length];
		int alreadyDecodedBytes = 0;
		
		byte[] ivUtilisation = new byte[iv.length];
		for(int z = 0; z < iv.length; ++z )
		{
			ivUtilisation[z] = iv[z];
		}
		
		boolean decodedBytesListFullyCompleted = false;
		int blockDone = 0;
		byte[][] allBlocks = new byte[cipher.length][cipher.length]; //Taille maximale

		while (!decodedBytesListFullyCompleted) {

			// Decodage jusqu'au T ème byte. T étant la taille du pad

			for (int padIndex = 0, decodedBytesNumber1 = alreadyDecodedBytes; padIndex < iv.length; ++padIndex, ++decodedBytesNumber1) {
				if (decodedBytesNumber1 < cipher.length) //Eviter le Out Of Bound
				{
					allBlocks[blockDone][padIndex] = (byte) (cipher[decodedBytesNumber1] ^ ivUtilisation[padIndex]); // On génère la T ème partie encodée
					 }
			}

			// Le ième block chiffré devient le nouveau PAD
			for (int m = 0, decodedBytesNumber3 = alreadyDecodedBytes; m < iv.length; ++m, ++decodedBytesNumber3) {
				if (decodedBytesNumber3 < decodedBytes.length) // Eviter Out Of Bound
				{
					ivUtilisation[m] = cipher[decodedBytesNumber3];
				}
			}

			//On transfert les caractères de AllBlocks dans le tableau unidimensionel des caractères décodés (decodedBytes)

			for (int j = 0, decodedBytesNumber2 = alreadyDecodedBytes; j < iv.length; j++, ++decodedBytesNumber2) {
				if (decodedBytesNumber2 < decodedBytes.length) //Eviter le Out Of Bound
				{
					decodedBytes[decodedBytesNumber2] = allBlocks[blockDone][j];
				}
			}


			alreadyDecodedBytes += iv.length;

			//Vérifie si le texte est toalement déchiffré, auquel cas, on s'arrête

			if (decodedBytes[(decodedBytes.length) - 1] != 0) // Si la dernière valeur de la liste est différente de 0 (valeur par défault)
			{
				decodedBytesListFullyCompleted = true;  // L'intégralité du message a été chiffré, on s'arrête comme promis.
			}

			blockDone += 1;

		}

		return decodedBytes;
	}
		
		
}
