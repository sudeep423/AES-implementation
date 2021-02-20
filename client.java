import java.io.*;
import java.net.*;

class client{
	
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
  
  


	
  public static void main(String args[])throws Exception{
    BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
    DatagramSocket clientSocket = new DatagramSocket();
    InetAddress IPAddress = InetAddress.getByName("127.0.0.1");
    
		System.out.println("Enter plain text");
		String sentence = inFromUser.readLine();
		System.out.println("Enter key of 2 bytes only ");
		String key = inFromUser.readLine();
		AES aes = new AES();
		byte[] sendKey = key.getBytes();
		DatagramPacket sendPacket = new DatagramPacket(sendKey, sendKey.length,IPAddress, 9876);
		clientSocket.send(sendPacket);
		System.out.println(sentence.length());
		StringBuilder plainText = new StringBuilder(sentence);
		if(sentence.length()%2==1)
			plainText.append(' ');
		sentence = plainText.toString();
		System.out.println(sentence);
		StringBuilder cypherText = new StringBuilder();
		for(int i=0;i<sentence.length();i=i+2){
			cypherText.append(aes.encrypt(sentence.substring(i,i+2),key));
		}

		byte[] cypherString = cypherText.toString().getBytes();
		System.out.println(cypherText.toString());
		DatagramPacket sendCypherText = new DatagramPacket(cypherString, cypherString.length,IPAddress, 9876);
		clientSocket.send(sendCypherText);
	
    try{
		clientSocket.close();
		inFromUser.close();
    }
    catch(Exception e){
		e.printStackTrace();
    }
  }
}
