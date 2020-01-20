package com.robert.packet;
import java.io.*;
import java.util.HashMap;


public class Packet implements Serializable{
	String sourceIP;
	String destinationIP;
	String sourcePort;
	String destinationPort;
	String content;
	String msg;
	
	public class Header{
		
		public  String storeSourceIP(String a) {
			//a = "10.10.10.10"; /**********REMEMBER TO CHANGE THE $HOME_NET AND $EXTERNAL_NET **************/
			sourceIP = a;
			//System.out.println("Source IP is: " +sourceIP);
			
			return sourceIP;	
		}
		public String storeDestinationIP(String a) {
			destinationIP = a;
			//System.out.println("Destination IP IP is: " +destinationIP);
			return destinationIP;	
		}
		public String storeSourcePort(String a) {
			sourcePort = a;
			//System.out.println("Source Port is: " +sourcePort);
			return sourcePort;	
		}
		public String storeDestinationPort(String a) {
			destinationPort = a;
			//System.out.println("Destination Port is: " +destinationPort);
			return destinationPort;	
		}
		public String toString() {
			return sourceIP + destinationIP + sourcePort + destinationPort;
			//return "[Source IP: " + sourceIP +  ", Destination IP: " + destinationIP + ", SourcePort: " + sourcePort + ", DestinationPort: " +destinationPort]";
		}
		//generate hash function
		//@Override
		
	}
	public class Options{
		public String storeContent(String a) {
			content = a;
			//System.out.println("Content: " +content);
			return content;
		}
		public String storeMessage(String a) {
			msg = a;
			//System.out.println("Message: " +msg);
			return msg;
		}
		public String toString() {
			return content + msg;
		}
	}
	
	/**public int hashcode() {
	return java.util.Objects.hash(setstoreSourceIP(sourceIP), storeDestinationIP(destinationIP), storeSourcePort(sourcePort), storeDestinationPort(destinationPort));
	}
	*/
	public Header head = new Header();
	Options opt = new Options();
	
	
	public HashMap<Header, Options> hashmap() {
		
		HashMap<Header, Options> map = new HashMap <Header, Options>();
		map.put(head,opt); 
		
		return map;
	
	}	
}

