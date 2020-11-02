package crypto;
import java.util.Scanner;
import java.util.Arrays;

public class UI {

	public static void main(String[] args) {
		boolean keepGoing = true; 
		while(keepGoing) {
			
			Scanner input0 = new Scanner(System.in);
			int[] acceptedNumber = {1,2};
			int[] acceptedNumber3 = {1,2,3,4};
			int choixChiffrerDechiffrer = askChoice("Bonjour, voici vos options : \n[1] Chiffrer un message \n[2] Déchiffrer un message", acceptedNumber );
			int[] acceptedNumber2 = {1,2,3,4,5};
			if(choixChiffrerDechiffrer == 1)
			{
				int choixMethodeChiffrement = askChoice(
						"Choisissez entre ces différentes méthodes de chiffrements \n[1] César\n[2] Vigenere\n[3] XOR\n[4] One Time Pad\n[5] CBC",
						acceptedNumber2);

				for (int i = 0; i < 5; ++i) {
					if (choixMethodeChiffrement == i + 1) {
						AskInfoAndCipher(i);
					}

				}
			}

			else if (choixChiffrerDechiffrer == 2) {
				int choixMethodeDechiffrement = askChoice(
						"Quel type de chiffrement souhaitez-vous déchiffrer : \n[1] César\n[2] Vigenere\n[3] XOR\n[4] CBC",
						acceptedNumber3);
				
				if (choixMethodeDechiffrement == 1) { //César 
					int choixMethodeCesar = askChoice(
							"Voulez-vous déchiffrer César : \n[1] Par bruteforce\n[2] Par analyse des fréquences",
							acceptedNumber);
					if (choixMethodeCesar == 1) {
						
						System.out.print("Renseignez le mot que vous désirez déchiffrer");
						String encodedWordString = input0.nextLine();
						byte[] encodedWordBytes = Helper.stringToBytes(encodedWordString);
						byte[][] bruteForceResult = Decrypt.caesarBruteForce(encodedWordBytes);
						String sDA = Decrypt.arrayToString(bruteForceResult);
						System.out.println("Voici le résultat du bruteforce : \n" + sDA);

					} else if (choixMethodeCesar == 2) {
						AskInfoAndDecode(0);
					}

				}

				else if (choixMethodeDechiffrement == 2) { //Vigenere
					int choixMethodeVigenere = askChoice("Dechiffrer :\n[1] En conaissant la clé\n[2] Sans connaître la clé",
							acceptedNumber);
					if (choixMethodeVigenere == 1) {

					} 
					else if (choixMethodeVigenere == 2) {
						AskInfoAndDecode(1);
					}
				}
				
				else if(choixMethodeDechiffrement == 3) { //XOR

					AskInfoAndDecode(2);
				}
					
				else if (choixMethodeDechiffrement == 4) //CBC
				{
					System.out.print("Renseignez le mot que vous désirez déchiffrer");
					String encodedWordString = input0.nextLine();
					byte[] encodedWordBytes = Helper.stringToBytes(encodedWordString);
					System.out.println("Veuillez entrer le PAD avec lequel vous avez chiffré votre message : ");
					String stringPAD = input0.nextLine();
					byte[] bytePAD = Helper.stringToBytes(stringPAD);
					byte[] decodedBytes = Decrypt.decryptCBC(encodedWordBytes, bytePAD);						
					String decodedString = Helper.bytesToString(decodedBytes);
					System.out.print("Voici le mot déchiffré : " + decodedString);
				}

				}
			}
			
			
			keepGoing = false;
		}
	
	public static void clearConsole() {
	    //System.out.print("\033[H\033[2J");   
	    System.out.flush();
	}
	
	public static int askChoice(String welcomeText, int[] acceptedNumberList)
	{
		int choix = 0;
		do {
			Scanner input = new Scanner(System.in);
			System.out.println(welcomeText);
			clearConsole();
			try {
				choix = input.nextInt();
				if(!(inList(acceptedNumberList, choix)))
				{
					System.out.println("Veuillez entrer des chiffres valides");
				}
			}
			catch(Exception InputMismatchException) {
				System.out.println("Entrée invalide, entrez des chiffres");
				input.next();
			}
		}while(!(inList(acceptedNumberList, choix))); 
		
		return choix;
	}
	
	public static boolean inList(int[] intList, int searchedValue)
	{
		boolean inList = false;
		for(int listIndex = 0; listIndex < intList.length; ++listIndex)
		{
			if(intList[listIndex] == searchedValue)
			{
				inList = true;
			}
		}
		
		return inList;
	}
	
	public static void AskInfoAndCipher(int type)
	{
		int[] acceptedNumber = {1,2};
		Scanner input2 = new Scanner(System.in);
		System.out.println("Renseignez le mot que vous désirer chiffrer : ");
		String wordToCipher = input2.nextLine();
		String key = "";
		
		if(type == 3 || type == 4)
		{
			int choixGenerationPad = askChoice("Souhaitez vous :\n[1] Générer un PAD aléatoirement\n[2] Spécifier vous même votre PAD", acceptedNumber);
			if(choixGenerationPad == 1)
			{
				System.out.println("Entrez la taille du PAD (nécessairement inférieure à la taille de votre mot) : ");
				int size = input2.nextInt();
				key = Helper.bytesToString(Encrypt.generatePad(size));
			}
			
			else if (choixGenerationPad == 2)
			{
				System.out.println("Entrez votre PAD sous forme de String ici : ");
				key = input2.nextLine();
				
			}
		}
		else {
			System.out.println("Entrez votre clé en String : ");
			key = input2.nextLine();
		}
		
		String CipheredWord = Encrypt.encrypt(wordToCipher, key, type);
		
		System.out.println("Voici le mot chiffré : " + CipheredWord);
	}
	
	public static void AskInfoAndDecode(int type)
	{
		Scanner input3 = new Scanner(System.in);
		System.out.println("Renseignez le mot que vous désirer déchiffrer : ");
		String wordToDecode = input3.nextLine();
		String decodedWord = Decrypt.breakCipher(wordToDecode, type);	
		if(type == 2)
		{
			System.out.println("Voici le résultat du bruteforce :\n" + decodedWord);
		}
		else {
			System.out.println("Voici le mot déchiffré : " + decodedWord);
		}
		
	}
	
}
