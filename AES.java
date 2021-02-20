import java.io.*;
import java.math.*;
import java.security.*;
import java.text.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

public class AES{

    private static int[] SBox = {9,4,10,11,13,1,8,5,6,2,0,3,12,14,15,7};
	private static int[] SInverseBox = new int[16];
	private static int[] encryptionKey = new int[6];
	private static int[] key = new int[3];
	private static int[][] mixColumnMatrix = {{1,4},{4,1}};
	private static int[][] mixInverseColumnMatrix = {{9,2},{2,9}};
	private static int mod = 3;
	
	public static String getBufHexStr(int[] raw){
    String HEXES = "0123456789ABCDEF";
    if ( raw == null ) {
      return null;
    }
    final StringBuilder hex = new StringBuilder( 2 * raw.length );
    for ( final int b : raw ) {
      hex.append(HEXES.charAt((b & 0xF0) >> 4))
        .append(HEXES.charAt((b & 0x0F)));
    }
    return hex.toString();
	}
	
	private static int merge(int a,int b){
		return (int)((a<<4)+b);
	}
	
	private static int multiply(int l , int r){
		int ans=0,finalAns=0;
		ans=r;
		for(int i=0;i<4;i++){
			if(ans>15)
			ans = (int)((ans%(1<<4))^mod);
			if((l&(1<<i))>0){
				finalAns = (int)(finalAns^ans);
			}
			ans = (int)(ans<<1);
		}
		return finalAns;
	}
	
	private static int[] mixColums(int[] word,int[][] Matrix){
		int[][] temp = new int[2][2];
		for(int i =0;i<2;i++){
			for(int j=0;j<2;j++){
				temp[i][j]=(int)(multiply(Matrix[i][0],(int)(word[j]/(int)(1<<4)))^multiply(Matrix[i][1],(int)(word[j]%(int)(1<<4))));
				//System.out.println(word[j]%(1<<4) +" " + i + " " + j +"Binary is " + word[j]/(1<<4));
				//System.out.println("Binary is " + integer.toBinaryString(temp[i][j]));
			}
		}
		
		word[0]=merge(temp[0][0],temp[1][0]);
		word[1]=merge(temp[0][1],temp[1][1]);
		return word;
	}
	
	private static int SubNib(int word){
		return (int)((SBox[(word/(1<<4))]<<4)+SBox[(word%(1<<4))]);
	}
	
	private static int SubInverseNib(int word){
		return (int)((SInverseBox[(word/(1<<4))]<<4)+SInverseBox[(word%(1<<4))]);
	}
	
	private static int SubNibRotNib(int word){
		return (int)((SBox[(word%(1<<4))]<<4)+SBox[(word/(1<<4))]);
	}
	
	private static int[] shiftRow(int[] a){
		int[] word = new int[2];
		word[0] = (int)(((a[0]/(int)(1<<4))<<4)+a[1]%(1<<4));
		word[1] = (int)(((a[1]/(int)(1<<4))<<4)+a[0]%(1<<4));
		return word;
	}
	
	private static void keyGeneration(int[] a){
		encryptionKey[0] = (int)((a[0]<<4)+a[1]);
		encryptionKey[1] = (int)((a[2]<<4)+a[3]);
		int[] round = new int[2];
		round[0]=(int)128;
		round[1]=(int)48;
		for(int i=0;i<2;i++){
			encryptionKey[2*i+2] = (int)(encryptionKey[2*i]^round[i]^SubNibRotNib(encryptionKey[2*i+1]));
			encryptionKey[2*i+3] = (int)(encryptionKey[2*i+2]^encryptionKey[2*i+1]);
		}
		for(int i=0;i<3;i++){
			key[i] = merge(encryptionKey[2*i],encryptionKey[2*i+1]); 
		}
	}
	
	public static void show(int[] a,String s){
		for(int i : a){
			System.out.print(i+ " ");
		}
		System.out.println(s);
	}


	public static String encrypt(String plaintext, String keyText){
		int[] word = {(int)(plaintext.charAt(0)),(int)(plaintext.charAt(1))};
		//show(word);
		int[] temp = new int[2];
		int[] key = new int[4];
		for(int i=0;i<2;i++){
			key[2*i]=(int)(keyText.charAt(i)/(int)(1<<4));
			key[2*i+1]=(int)(keyText.charAt(i)%(int)(1<<4));
		}
		
		keyGeneration(key);
		
		// start of Round 0 
		// plaintext XOR key1
		int[] encryptedWord = new int[2];
		encryptedWord[0] = (int)(word[0]^encryptionKey[0]);
		encryptedWord[1] = (int)(word[1]^encryptionKey[1]);
		
		show(encryptedWord,"After Pre round transformation");
		
		temp[0] = encryptionKey[0];
		temp[1] = encryptionKey[1];
		
		show(temp,"Round Key K0");
		
		//start Round 1
		for(int i=0;i<2;i++){
			encryptedWord[i]=SubNib(encryptedWord[i]);
		}
		
		show(encryptedWord,"After Round 1 Substitute nibbles");
		
		encryptedWord = shiftRow(encryptedWord);
		
		show(encryptedWord,"After Round 1 shift Row");
		
		encryptedWord = mixColums(encryptedWord,mixColumnMatrix);
		
		show(encryptedWord,"After Round 1 Mix Columns");
		
		// Add round 1 key
		encryptedWord[0] = (int)(encryptedWord[0]^encryptionKey[2]);
		encryptedWord[1] = (int)(encryptedWord[1]^encryptionKey[3]);
		
		show(encryptedWord,"After Round 1 Add round key");
		
		temp[0] = encryptionKey[2];
		temp[1] = encryptionKey[3];
		
		show(temp,"Round Key K1");
		
		// Final Round 
		for(int i=0;i<2;i++){
			encryptedWord[i]=SubNib(encryptedWord[i]);
		}
		
		show(encryptedWord,"After Round 2 Substitute nibbles");
		
		encryptedWord = shiftRow(encryptedWord);
		
		show(encryptedWord,"After Round 2 shift Row");
		//System.out.println(encryptedWord[0]^encryptionKey[4]);
		//System.out.println((encryptedWord[0]^encryptionKey[4]) + " " + encryptedWord[0] + " " +(encryptionKey[4]));
		
		encryptedWord[0] = (int)(encryptedWord[0]^encryptionKey[4]);
		encryptedWord[1] = (int)(encryptedWord[1]^encryptionKey[5]);
		
		show(encryptedWord,"After Round 2 Add round key");
		
		temp[0] = encryptionKey[4];
		temp[1] = encryptionKey[5];
		
		show(temp,"Round Key K2");
		
		return getBufHexStr(encryptedWord);
    }
	
	public static String decrypt(int[] word,String keyText ){
		//show(word);
		int[] temp = new int[2];
		int[] key = new int[4];
		for(int i=0;i<2;i++){
			key[2*i]=(int)(keyText.charAt(i)/(1<<4));
			key[2*i+1]=(int)(keyText.charAt(i)%(1<<4));
		}
		keyGeneration(key);
		
		for(int i=0;i<16;i++)
			SInverseBox[SBox[i]] = i; 
		
		int[] dencryptedWord = new int[2];
		show(word,"cipherText");
		//System.out.println((word[0]^encryptionKey[4]));
		// Add round 2 key
		dencryptedWord[0] = (int)(word[0]^encryptionKey[4]);
		dencryptedWord[1] = (int)(word[1]^encryptionKey[5]);
		//System.out.println((word[0]^encryptionKey[4]) + " " + word[0] + " " +(encryptionKey[4]));
		show(dencryptedWord,"After Pre round transformation");
		
		temp[0] = encryptionKey[4];
		temp[1] = encryptionKey[5];
		
		show(temp,"Round Key K2");
		
		
		dencryptedWord = shiftRow(dencryptedWord);
		
		show(dencryptedWord,"After Round 1 invshift row");
		
		for(int i=0;i<2;i++){
			dencryptedWord[i]=SubInverseNib(dencryptedWord[i]);
		}
		
		show(dencryptedWord,"After Round 1 Inv Substitute nibbles");
		
		
		
		// Add round 1 key
		dencryptedWord[0] = (int)(dencryptedWord[0]^encryptionKey[2]);
		dencryptedWord[1] = (int)(dencryptedWord[1]^encryptionKey[3]);
		
		show(dencryptedWord,"After Round 1 invAdd round key");
		
		temp[0] = encryptionKey[2];
		temp[1] = encryptionKey[3];
		
		show(temp,"Round Key K1");
		
		
		dencryptedWord = mixColums(dencryptedWord,mixInverseColumnMatrix);
		
		show(dencryptedWord,"After Round 1 Inv Mix column");
		
		dencryptedWord = shiftRow(dencryptedWord);
		
		show(dencryptedWord,"After Round 2 Inv Shift rows");
		
		for(int i=0;i<2;i++){
			dencryptedWord[i]=SubInverseNib(dencryptedWord[i]);
		}
		
		show(dencryptedWord,"After Round 2 InvSubstitute nibbles");
		// Add round 1 key
		
		dencryptedWord[0] = (int)(dencryptedWord[0]^encryptionKey[0]);
		dencryptedWord[1] = (int)(dencryptedWord[1]^encryptionKey[1]);
		
		show(dencryptedWord,"After Round 2 add round key");
		
		temp[0] = encryptionKey[0];
		temp[1] = encryptionKey[1];
		
		show(temp,"Round Key K0");
		
		show(dencryptedWord,"plaintext");
		String plaintext = "";
		char c;
		for(int i : dencryptedWord){
			c = (char)i;
			plaintext = plaintext+c;
		}
		return plaintext;
		
		//System.out.println((char)encryptedWord[0] +"Binary is " + (char)encryptedWord[1]);
	}

}
