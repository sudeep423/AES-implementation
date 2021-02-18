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
	
	private static int merge(int a,int b){
		return (a<<4)+b;
	}
	
	private static int multiply(int l , int r){
		int ans=0,finalAns=0;
		ans=r;
		for(int i=0;i<4;i++){
			if(ans>15)
			ans = (ans%(1<<4))^mod;
			if((l&(1<<i))>0){
				finalAns = finalAns^ans;
			}
			ans = ans<<1;
			
		}
		return finalAns;
	}
	
	private static int[] mixColums(int[] word,int[][] Matrix){
		int[][] temp = new int[2][2];
		for(int i =0;i<2;i++){
			for(int j=0;j<2;j++){
				temp[i][j]=multiply(Matrix[i][0],word[j]/(1<<4))^multiply(Matrix[i][1],word[j]%(1<<4));
				System.out.println(word[j]%(1<<4) +" " + i + " " + j +"Binary is " + word[j]/(1<<4));
				System.out.println("Binary is " + Integer.toBinaryString(temp[i][j]));
			}
		}
		
		word[0]=merge(temp[0][0],temp[1][0]);
		word[1]=merge(temp[0][1],temp[1][1]);
		return word;
	}
	
	private static int SubNib(int word){
		return (SBox[(word/(1<<4))]<<4)+SBox[(word%(1<<4))];
	}
	
	private static int SubInverseNib(int word){
		return (SInverseBox[(word/(1<<4))]<<4)+SInverseBox[(word%(1<<4))];
	}
	
	private static int SubNibRotNib(int word){
		return (SBox[(word%(1<<4))]<<4)+SBox[(word/(1<<4))];
	}
	
	private static int[] shiftRow(int[] a){
		int[] word = new int[2];
		word[0] = ((a[0]/(1<<4))<<4)+a[1]%(1<<4);
		word[1] = ((a[1]/(1<<4))<<4)+a[0]%(1<<4);
		return word;
	}
	
	private static void keyGeneration(int[] a){
		encryptionKey[0] = (a[0]<<4)+a[1];
		encryptionKey[1] = (a[2]<<4)+a[3];
		int[] round = new int[2];
		round[0]=128;
		round[1]=48;
		for(int i=0;i<2;i++){
			encryptionKey[2*i+2] = encryptionKey[2*i]^round[i]^SubNibRotNib(encryptionKey[2*i+1]);
			encryptionKey[2*i+3] = encryptionKey[2*i+2]^encryptionKey[2*i+1];
		}
			
		for(int i : encryptionKey){
			//System.out.println(i);
			//System.out.println("Binary is " + Integer.toBinaryString(i));
		}			
		
		for(int i=0;i<3;i++){
			key[i] = merge(encryptionKey[2*i],encryptionKey[2*i+1]); 
		}
	}
	
	public static void show(int[] a){
		for(int i: a)
			System.out.println("Binary is " + Integer.toBinaryString(i));
	}


	public static void encrypt(){
		int[] word = {'o','k'};
		System.out.println("Binary is " + Integer.toBinaryString(multiply(4,6)));
		//show(word);
		
		int[] key = {10,7,3,11};
		
		
		
		/*String s = "ok" ;

		for(int i=0;i<2;i++){
			word[i] = s.charAt(i);
		}*/
		
		keyGeneration(key);
		
		// start of Round 0 
		// plaintext XOR key1
		int[] encryptedWord = new int[2];
		encryptedWord[0] = word[0]^encryptionKey[0];
		encryptedWord[1] = word[1]^encryptionKey[1];
		
		
		//start Round 1
		for(int i=0;i<2;i++){
			encryptedWord[i]=SubNib(encryptedWord[i]);
		}
		
		show(encryptedWord);
		encryptedWord = shiftRow(encryptedWord);
		show(encryptedWord);
		encryptedWord = mixColums(encryptedWord,mixColumnMatrix);
		//show(encryptedWord);
		
		// Add round 1 key
		encryptedWord[0] = encryptedWord[0]^encryptionKey[2];
		encryptedWord[1] = encryptedWord[1]^encryptionKey[3];
		
		//show(encryptedWord);
		
		// Final Round 
		for(int i=0;i<2;i++){
			encryptedWord[i]=SubNib(encryptedWord[i]);
		}
		
		encryptedWord = shiftRow(encryptedWord);
		
		encryptedWord[0] = encryptedWord[0]^encryptionKey[4];
		encryptedWord[1] = encryptedWord[1]^encryptionKey[5];
		
		
		
		//show(encryptedWord);
		System.out.println(encryptedWord[0] +"Binary is " + encryptedWord[1]);
		
    }
	
	public static void decrypt(){
		int[] word = {7,56};
		int[] key = {10,7,3,11};
		keyGeneration(key);
		for(int i=0;i<16;i++)
			SInverseBox[SBox[i]] = i; 
		
		int[] encryptedWord = new int[2];
		// Add round 2 key
		encryptedWord[0] = word[0]^encryptionKey[4];
		encryptedWord[1] = word[1]^encryptionKey[5];
		
		show(encryptedWord);
		encryptedWord = shiftRow(encryptedWord);
		
		for(int i=0;i<2;i++){
			encryptedWord[i]=SubInverseNib(encryptedWord[i]);
		}
		
		
		
		// Add round 1 key
		encryptedWord[0] = encryptedWord[0]^encryptionKey[2];
		encryptedWord[1] = encryptedWord[1]^encryptionKey[3];
		
		encryptedWord = mixColums(encryptedWord,mixInverseColumnMatrix);
		
		encryptedWord = shiftRow(encryptedWord);
		
		for(int i=0;i<2;i++){
			encryptedWord[i]=SubInverseNib(encryptedWord[i]);
		}
		
		// Add round 1 key
		encryptedWord[0] = encryptedWord[0]^encryptionKey[0];
		encryptedWord[1] = encryptedWord[1]^encryptionKey[1];
		
		System.out.println((char)encryptedWord[0] +"Binary is " + (char)encryptedWord[1]);
		
		
		
	}

}
