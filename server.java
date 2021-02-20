import java.io.*;
import java.net.*;
import java.util.*;

class server{
	
	public static String getBufHexStr(byte[] raw){
    String HEXES = "0123456789ABCDEF";
    if ( raw == null ) {
      return null;
    }
    final StringBuilder hex = new StringBuilder( 2 * raw.length );
    for ( final byte b : raw ) {
      hex.append(HEXES.charAt((b & 0xF0) >> 4))
        .append(HEXES.charAt((b & 0x0F)));
    }
    return hex.toString();
  }
  
  // The hexadecimal string converted into an array of characters
  public static int[] getHexBytes(String str){
    int[] bytes = new int[str.length() / 2];
    for(int i = 0; i < str.length() / 2; i++) {
      String subStr = str.substring(i * 2, i * 2 + 2);
      bytes[i] = Integer.parseInt(subStr, 16);
    }
    return bytes;
  }
	
	
	
  public static void main(String args[])throws Exception{
    try{
		DatagramSocket serverSocket = new DatagramSocket(9876);
        byte[] bufKey= new byte[2];
        DatagramPacket receivekey = new DatagramPacket(bufKey, bufKey.length);
        serverSocket.receive(receivekey);
		String key = new String(receivekey.getData());
		System.out.println(key);
		byte[] bufCypherText = new byte[1024];
        DatagramPacket receiveCypherText = new DatagramPacket(bufCypherText, bufCypherText.length);
        serverSocket.receive(receiveCypherText);
		String cypherText = new String(receiveCypherText.getData());
		System.out.println(cypherText.trim());
		int[] sentence = getHexBytes(cypherText.trim());
		
		//key[0]= receiveData[0]& 0xff; 
		//key[1]= receiveData[1]& 0xff;
		AES aes = new AES();
		StringBuilder plainText = new StringBuilder();
		int[] part = new int[2];
		for(int i=0;i<sentence.length;i=i+2){
			part[0]=sentence[i];
			part[1]=sentence[i+1];
			plainText.append(aes.decrypt(part,key));
		}
		System.out.println(plainText.toString());
		//String plainText = aes.decrypt(cipherContent,key);
		//System.out.println("Plain text : " + plainText);
    }
    catch(Exception e){
      e.printStackTrace();
    }
  }
}
