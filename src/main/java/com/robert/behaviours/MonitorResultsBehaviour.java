package com.robert.behaviours;

import jade.core.behaviours.Behaviour;

import java.io.File;

import javax.swing.JOptionPane;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import jade.core.AID;
import jade.core.Agent;
import jade.core.behaviours.Behaviour;
import jade.lang.acl.ACLMessage;
import jade.lang.acl.MessageTemplate;

import com.robert.packet.Packet;
import com.robert.packet.Packet.Header;
import com.robert.packet.Packet.Options;
import com.robert.parser.Parser;
import com.robert.parser.Rules;
import com.robert.util.RuleHandler;

public class MonitorResultsBehaviour extends Behaviour{
	
	static String filepath = "C:\\pcap packets\\wrccdc.regionals.2019-03-01.083858000050000.pcap";
	static double count = 0;
	static double count_tcp = 0;
	static double count_ip = 0;
	static double count_udp = 0;
	static double count_icmp = 0;
	static double globalcount = 0;
	static String protocol;
	
	static String[] temprule = new String[1000];
	static String[] rule= new String[10000];
	int cntStart=0;
	int cntEnd=0;
	int ruleCount=0;
	
	Rules rules = new Rules();
	Parser parser = new Parser();
	RuleHandler rh = new RuleHandler();
	
	String file_name = "c:\\rules/snort3-community.rules";
	
	public void action() {
		
		int tcp_count=0;
		int udp_count=0;
		int icmp_count=0;
		int ip_count=0;
		
		//Receive rules
		final MessageTemplate msgTemplate = MessageTemplate.and(MessageTemplate.MatchPerformative(ACLMessage.INFORM),
											MessageTemplate.MatchSender(new AID("Agent1", AID.ISLOCALNAME)));
		
		//final MessageTemplate msgTemplate = MessageTemplate.MatchPerformative(ACLMessage.INFORM);
  		final ACLMessage msg = this.myAgent.receive(msgTemplate);
  		
  		System.out.println("Monitor Agent - The message is:" +msg);
  		System.out.println();
		
  		 if(msg != null) {
			//JOptionPane.showMessageDialog(null, ((Rules)msg.getContentObject()));
			JOptionPane.showMessageDialog(null, "Message Received " + msg.getContent());
			System.out.println("Rules received by Analysis Agent" + msg.getContent());
			
		}else {
			block();
			System.out.println("Receiver - No message received");
		}
		
		try {
	  		
			File file = new File(filepath);
			
			final StringBuilder errbuf = new StringBuilder();
			
			Pcap pcap = Pcap.openOffline(filepath, errbuf);
			
			//Throw exception if it cannot open the file
			if (pcap == null) {
				System.err.printf("Error while opening file for capture: " + errbuf.toString());
			}
			else {
				//System.out.println("Network File opened successfully");
				System.out.println();
			}
			
			//get rules from file to parse
			temprule = rh.getRules(file_name);
			cntEnd = rh.noOfRules()+cntStart;
			int l=0;
			
			for(int k=cntStart; k<cntEnd; k++) {
				
				rule[k]=temprule[l];
				//System.out.println("Net cap: "+rule[k]);
				l++;
				
			}
			cntStart = cntEnd;
			
			for (int i=0; i<240; i++) {
    			
    			rules = parser.getRules(rule[i]);

    			//Get the rule headers as first categorization step.
    			String proto = rules.getRuleHeader().getProtocols();
    			protocol = proto;
    			//System.out.println(protocol);
    			
    			switch (protocol) {
    			case "tcp":
    				tcp_count++;
    				//rules = parser.getRules("tcp");
    				//System.out.println(protocol);
    				//System.out.println(rules.getRuleOption().getGeneralOption().getMsg());
    				//System.out.println();
    				//System.out.println("Switch TCP " +rules.getRuleHeader().getProtocols());
    				break;
    				
    			case "udp":
    				udp_count++;
    				//rules = parser.getRules("udp");
    				//System.out.println(protocol);
    				//System.out.println(rules.getRuleOption().getGeneralOption().getMsg());
    				//System.out.println();
    				//System.out.println("Switch UDP " +rules.getRuleHeader().getProtocols());
    				break;
    			
    			case "icmp":
    				icmp_count++;
    				//rules = parser.getRules("icmp");
    				//System.out.println(protocol);
    				//System.out.println(rules.getRuleOption().getGeneralOption().getMsg());
    				//System.out.println();	
    				break;
    				
    			case "ip":
    				ip_count++;
    				//rules = parser.getRules("ip");
    				//System.out.println(protocol);
    				//System.out.println(rules.getRuleOption().getGeneralOption().getMsg());
    				//System.out.println();
    								
    				break;
    			
    			default:
    				System.out.println("");
    				break;
    			}
    		}
			
			//instantiate packet class
			Packet pkt = new Packet();
			Packet.Header head = pkt.new Header();
			Packet.Options opt = pkt.new Options();
			
			//Create packet handler which will receive packets
	        PcapPacketHandler jpacketHandler = new PcapPacketHandler <String>() {
	           
	        	Icmp icmp = new Icmp();
	            Tcp tcp = new Tcp();
	            Ip4 ip = new Ip4();
	            Udp udp = new Udp();
	            byte[] sIP = new byte[4]; //variable to hold source IP address
	            byte[] dIP = new byte[4]; //variable to hold destination IP address
	            int sPrt; //variable to hold source port
	            int dPrt; //variable to hold destination port
	            
	           
	            
	            @Override
	            public void nextPacket(PcapPacket packet, String user) {
	            	
	            	count ++;
	                //Here i am capturing the icmp, tcp, ipv4 and udp packets.
	                if (packet.hasHeader(icmp)) {
	                    //System.out.println("Hardware type" + icmp.hardwareType());
	                    //System.out.println("Protocol type" + icmp.protocolType());
	                	
	                	//IP address information of the packet
	                	sIP = ip.source();
	                	dIP = ip.destination();
	                	
	                	String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
	                	String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
	                	
	                	//copies to carry the actual values of the IPs
	                	String sourceIP_2 = sourceIP;
	                	String destinationIP_2 = destinationIP;
	                	
	                	//Classify the IP Addresses as either Home network or External Network
	                	String delimiter = "\\.";
	                	String range_1 = "10.0.0.0";
	                	String range_2 = "10.255.255.255";
	                	String range_3 = "172.20.0.0";
	                	String range_4 = "172.20.0.255";
	                	
	                	String[] temp1 = sourceIP.split(delimiter);
	                	String[] temp2 = destinationIP.split(delimiter);
	                	
	                	String[] temp3 = range_1.split(delimiter);
	                	String[] temp4 = range_2.split(delimiter);
	                	
	                	String[] temp5 = range_3.split(delimiter);
	                	String[] temp6 = range_4.split(delimiter);
	                	
	                	int octet1, octet2, octet3, octet4;
	            		int octet5, octet6, octet7, octet8;
	            		
	            		int octet9, octet10, octet11, octet12;
	            		int octet13, octet14, octet15, octet16;
	            		
	            		int octet17, octet18, octet19, octet20;
	            		int octet21, octet22, octet23, octet24;
	            		
	            		long result1 = 0; //Source IP
	            		long result2 = 0; //Destination IP
	            		long result3 = 0; //Network address 1
	            		long result4 = 0; //Broadcast address 1
	            		long result5 = 0; //Network address 2
	            		long result6 = 0; //Broadcast address 2
	            		
	            		for(int i = 0; i < temp1.length ; i++) {
	            			octet1 = Integer.parseInt(temp1[0]);
	            			octet2 = Integer.parseInt(temp1[1]);
	            			octet3 = Integer.parseInt(temp1[2]);
	            			octet4 = Integer.parseInt(temp1[3]);
	            			
	            			result1 = (octet1 << 24) + (octet2 << 18) + (octet3 << 8) + octet4;
	            		}
	            		//System.out.println("Source IP:" +result1);
	            		
	            		for(int i = 0; i < temp2.length ; i++) {
	            			octet5 = Integer.parseInt(temp2[0]);
	            			octet6 = Integer.parseInt(temp2[1]);
	            			octet7 = Integer.parseInt(temp2[2]);
	            			octet8 = Integer.parseInt(temp2[3]);
	            			
	            			result2 = (octet5 << 24) + (octet6 << 18) + (octet7 << 8) + octet8;
	            		}
	            		//System.out.println("Dest IP:" + result2);
	                	
	            		for(int i = 0; i < temp3.length ; i++) {
	            			octet9 = Integer.parseInt(temp3[0]);
	            			octet10 = Integer.parseInt(temp3[1]);
	            			octet11 = Integer.parseInt(temp3[2]);
	            			octet12 = Integer.parseInt(temp3[3]);
	            			
	            			result3 = (octet9 << 24) + (octet10 << 18) + (octet11 << 8) + octet12;
	            		}
	            		//System.out.println("Network IP 1:" + result3);
	            		
	            		for(int i = 0; i < temp4.length ; i++) {
	            			octet13 = Integer.parseInt(temp4[0]);
	            			octet14 = Integer.parseInt(temp4[1]);
	            			octet15 = Integer.parseInt(temp4[2]);
	            			octet16 = Integer.parseInt(temp4[3]);
	            			
	            			result4 = (octet13 << 24) + (octet14 << 18) + (octet15 << 8) + octet16;
	            		}
	            		//System.out.println("Broadcast IP 1:" + result4);
	            		
	            		for(int i = 0; i < temp5.length ; i++) {
	            			octet17 = Integer.parseInt(temp5[0]);
	            			octet18 = Integer.parseInt(temp5[1]);
	            			octet19 = Integer.parseInt(temp5[2]);
	            			octet20 = Integer.parseInt(temp5[3]);
	            			
	            			result5 = (octet17 << 24) + (octet18 << 18) + (octet19 << 8) + octet20;
	            		}
	            		//System.out.println("Network IP 2:" + result5);
	            		
	            		for(int i = 0; i < temp6.length ; i++) {
	            			octet21 = Integer.parseInt(temp6[0]);
	            			octet22 = Integer.parseInt(temp6[1]);
	            			octet23 = Integer.parseInt(temp6[2]);
	            			octet24 = Integer.parseInt(temp6[3]);
	            			
	            			result6 = (octet21 << 24) + (octet22 << 18) + (octet23 << 8) + octet24;
	            		}
	            		//System.out.println("Broadcast IP 2:" + result6);
	            		
	            		//Specify home and external networks
	            		if(result3 <= result1 && result1 <= result4 || result5 <= result1 && result1 <= result6) {
	            			sourceIP = "$HOME_NET";
	            			destinationIP = "$HOME_NET";
	            		}
	            		else {
	            			sourceIP = "$EXTERNAL_NET";
	            			destinationIP = "$EXTERNAL_NET";
	            		}
	            		
	            		//RETRIEVE ICMP PAYLOAD DATA
	                	byte [] icmpMessage =  icmp.getPayload();
	                	String msg = new String(icmpMessage);
	                	//System.out.println("Payload information is: " + msg);
	                	//System.out.println("Payload information is: " + icmp.getPayload());
	                	
	                    count_icmp ++;
	                    
	                   //Get the icmp rules
	                    rules = parser.getRules("icmp");
	                    //System.out.println("ICMP rule from pkt switch: " +rules.getRuleHeader().getProtocols());
	                    //System.out.println(rules.getRuleHeader().getIpAddress().getSource());
	                   /** if(sourceIP == rules.getRuleHeader().getIpAddress().getSource() && destinationIP == rules.getRuleHeader().getIpAddress().getDestination()) {
	                    	System.out.println("TCP header match");
	                    }*/
	                     
	                }
	                
	                else if (packet.hasHeader(tcp)) {
	                	//IP address information of the packet
	                	sIP = ip.source();
	                	dIP = ip.destination();
	                	
	                	String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
	                	String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
	                	
	                	//copies to carry the actual values of the IPs
	                	String sourceIP_2 = sourceIP;
	                	String destinationIP_2 = destinationIP;
	                	
	                	//Classify the IP Addresses as either Home network or External Network
	                	String delimiter = "\\.";
	                	String range_1 = "10.0.0.0";
	                	String range_2 = "10.255.255.255";
	                	String range_3 = "172.20.0.0";
	                	String range_4 = "172.20.0.255";
	                	
	                	String[] temp1 = sourceIP.split(delimiter);
	                	String[] temp2 = destinationIP.split(delimiter);
	                	
	                	String[] temp3 = range_1.split(delimiter);
	                	String[] temp4 = range_2.split(delimiter);
	                	
	                	String[] temp5 = range_3.split(delimiter);
	                	String[] temp6 = range_4.split(delimiter);
	                	
	                	int octet1, octet2, octet3, octet4;
	            		int octet5, octet6, octet7, octet8;
	            		
	            		int octet9, octet10, octet11, octet12;
	            		int octet13, octet14, octet15, octet16;
	            		
	            		int octet17, octet18, octet19, octet20;
	            		int octet21, octet22, octet23, octet24;
	            		
	            		long result1 = 0; //Source IP
	            		long result2 = 0; //Destination IP
	            		long result3 = 0; //Network address 1
	            		long result4 = 0; //Broadcast address 1
	            		long result5 = 0; //Network address 2
	            		long result6 = 0; //Broadcast address 2
	            		
	            		for(int i = 0; i < temp1.length ; i++) {
	            			octet1 = Integer.parseInt(temp1[0]);
	            			octet2 = Integer.parseInt(temp1[1]);
	            			octet3 = Integer.parseInt(temp1[2]);
	            			octet4 = Integer.parseInt(temp1[3]);
	            			
	            			result1 = (octet1 << 24) + (octet2 << 18) + (octet3 << 8) + octet4;
	            		}
	            		//System.out.println("Source IP:" +result1);
	            		
	            		for(int i = 0; i < temp2.length ; i++) {
	            			octet5 = Integer.parseInt(temp2[0]);
	            			octet6 = Integer.parseInt(temp2[1]);
	            			octet7 = Integer.parseInt(temp2[2]);
	            			octet8 = Integer.parseInt(temp2[3]);
	            			
	            			result2 = (octet5 << 24) + (octet6 << 18) + (octet7 << 8) + octet8;
	            		}
	            		//System.out.println("Dest IP:" + result2);
	                	
	            		for(int i = 0; i < temp3.length ; i++) {
	            			octet9 = Integer.parseInt(temp3[0]);
	            			octet10 = Integer.parseInt(temp3[1]);
	            			octet11 = Integer.parseInt(temp3[2]);
	            			octet12 = Integer.parseInt(temp3[3]);
	            			
	            			result3 = (octet9 << 24) + (octet10 << 18) + (octet11 << 8) + octet12;
	            		}
	            		//System.out.println("Network IP 1:" + result3);
	            		
	            		for(int i = 0; i < temp4.length ; i++) {
	            			octet13 = Integer.parseInt(temp4[0]);
	            			octet14 = Integer.parseInt(temp4[1]);
	            			octet15 = Integer.parseInt(temp4[2]);
	            			octet16 = Integer.parseInt(temp4[3]);
	            			
	            			result4 = (octet13 << 24) + (octet14 << 18) + (octet15 << 8) + octet16;
	            		}
	            		//System.out.println("Broadcast IP 1:" + result4);
	            		
	            		for(int i = 0; i < temp5.length ; i++) {
	            			octet17 = Integer.parseInt(temp5[0]);
	            			octet18 = Integer.parseInt(temp5[1]);
	            			octet19 = Integer.parseInt(temp5[2]);
	            			octet20 = Integer.parseInt(temp5[3]);
	            			
	            			result5 = (octet17 << 24) + (octet18 << 18) + (octet19 << 8) + octet20;
	            		}
	            		//System.out.println("Network IP 2:" + result5);
	            		
	            		for(int i = 0; i < temp6.length ; i++) {
	            			octet21 = Integer.parseInt(temp6[0]);
	            			octet22 = Integer.parseInt(temp6[1]);
	            			octet23 = Integer.parseInt(temp6[2]);
	            			octet24 = Integer.parseInt(temp6[3]);
	            			
	            			result6 = (octet21 << 24) + (octet22 << 18) + (octet23 << 8) + octet24;
	            		}
	            		//System.out.println("Broadcast IP 2:" + result6);
	            		
	            		//Specify home and external networks
	            		if(result3 <= result1 && result1 <= result4 || result5 <= result1 && result1 <= result6) {
	            			sourceIP = "$HOME_NET";
	            			destinationIP = "$HOME_NET";
	            		}
	            		else {
	            			sourceIP = "$EXTERNAL_NET";
	            			destinationIP = "$EXTERNAL_NET";
	            		}
	            		
	                	//System.out.println("Source port of the tcp packet is: " +tcp.source());//prints out source port of tcp packet
	                	//System.out.println("Destination port of the tcp packet is: " +tcp.destination());//prints out source port of tcp packet
	                	
	                	//RETRIEVE TCP PAYLOAD DATA
	                	byte [] tcpMessage =  tcp.getPayload();
	                	String msg = new String(tcpMessage);
	                	//System.out.println("Payload information is: " + msg);
	                	
	                    count_tcp ++;
	                    
	                    //Get the tcp rules
	                    rules = parser.getRules("tcp");
	                    //System.out.println("TCP from pkt switch: " +rules.getRuleHeader().getProtocols());
	                }
	                else if (packet.hasHeader(ip)) {
	                	//IP address information of the packet
	                	sIP = ip.source();
	                	dIP = ip.destination();
	                	
	                	String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
	                	String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
	                	
	                	//copies to carry the actual values of the IPs
	                	String sourceIP_2 = sourceIP;
	                	String destinationIP_2 = destinationIP;
	                	
	                	//Classify the IP Addresses as either Home network or External Network
	                	String delimiter = "\\.";
	                	String range_1 = "10.0.0.0";
	                	String range_2 = "10.255.255.255";
	                	String range_3 = "172.20.0.0";
	                	String range_4 = "172.20.0.255";
	                	
	                	String[] temp1 = sourceIP.split(delimiter);
	                	String[] temp2 = destinationIP.split(delimiter);
	                	
	                	String[] temp3 = range_1.split(delimiter);
	                	String[] temp4 = range_2.split(delimiter);
	                	
	                	String[] temp5 = range_3.split(delimiter);
	                	String[] temp6 = range_4.split(delimiter);
	                	
	                	int octet1, octet2, octet3, octet4;
	            		int octet5, octet6, octet7, octet8;
	            		
	            		int octet9, octet10, octet11, octet12;
	            		int octet13, octet14, octet15, octet16;
	            		
	            		int octet17, octet18, octet19, octet20;
	            		int octet21, octet22, octet23, octet24;
	            		
	            		long result1 = 0; //Source IP
	            		long result2 = 0; //Destination IP
	            		long result3 = 0; //Network address 1
	            		long result4 = 0; //Broadcast address 1
	            		long result5 = 0; //Network address 2
	            		long result6 = 0; //Broadcast address 2
	            		
	            		for(int i = 0; i < temp1.length ; i++) {
	            			octet1 = Integer.parseInt(temp1[0]);
	            			octet2 = Integer.parseInt(temp1[1]);
	            			octet3 = Integer.parseInt(temp1[2]);
	            			octet4 = Integer.parseInt(temp1[3]);
	            			
	            			result1 = (octet1 << 24) + (octet2 << 18) + (octet3 << 8) + octet4;
	            		}
	            		//System.out.println("Source IP:" +result1);
	            		
	            		for(int i = 0; i < temp2.length ; i++) {
	            			octet5 = Integer.parseInt(temp2[0]);
	            			octet6 = Integer.parseInt(temp2[1]);
	            			octet7 = Integer.parseInt(temp2[2]);
	            			octet8 = Integer.parseInt(temp2[3]);
	            			
	            			result2 = (octet5 << 24) + (octet6 << 18) + (octet7 << 8) + octet8;
	            		}
	            		//System.out.println("Dest IP:" + result2);
	                	
	            		for(int i = 0; i < temp3.length ; i++) {
	            			octet9 = Integer.parseInt(temp3[0]);
	            			octet10 = Integer.parseInt(temp3[1]);
	            			octet11 = Integer.parseInt(temp3[2]);
	            			octet12 = Integer.parseInt(temp3[3]);
	            			
	            			result3 = (octet9 << 24) + (octet10 << 18) + (octet11 << 8) + octet12;
	            		}
	            		//System.out.println("Network IP 1:" + result3);
	            		
	            		for(int i = 0; i < temp4.length ; i++) {
	            			octet13 = Integer.parseInt(temp4[0]);
	            			octet14 = Integer.parseInt(temp4[1]);
	            			octet15 = Integer.parseInt(temp4[2]);
	            			octet16 = Integer.parseInt(temp4[3]);
	            			
	            			result4 = (octet13 << 24) + (octet14 << 18) + (octet15 << 8) + octet16;
	            		}
	            		//System.out.println("Broadcast IP 1:" + result4);
	            		
	            		for(int i = 0; i < temp5.length ; i++) {
	            			octet17 = Integer.parseInt(temp5[0]);
	            			octet18 = Integer.parseInt(temp5[1]);
	            			octet19 = Integer.parseInt(temp5[2]);
	            			octet20 = Integer.parseInt(temp5[3]);
	            			
	            			result5 = (octet17 << 24) + (octet18 << 18) + (octet19 << 8) + octet20;
	            		}
	            		//System.out.println("Network IP 2:" + result5);
	            		
	            		for(int i = 0; i < temp6.length ; i++) {
	            			octet21 = Integer.parseInt(temp6[0]);
	            			octet22 = Integer.parseInt(temp6[1]);
	            			octet23 = Integer.parseInt(temp6[2]);
	            			octet24 = Integer.parseInt(temp6[3]);
	            			
	            			result6 = (octet21 << 24) + (octet22 << 18) + (octet23 << 8) + octet24;
	            		}
	            		//System.out.println("Broadcast IP 2:" + result6);
	            		
	            		//Specify home and external networks
	            		if(result3 <= result1 && result1 <= result4 || result5 <= result1 && result1 <= result6) {
	            			sourceIP = "$HOME_NET";
	            			destinationIP = "$HOME_NET";
	            		}
	            		else {
	            			sourceIP = "$EXTERNAL_NET";
	            			destinationIP = "$EXTERNAL_NET";
	            		}
	                	
	            		//RETRIEVE IP PAYLOAD DATA
	                	byte [] ipMessage =  ip.getPayload();
	                	String msg = new String(ipMessage);
	                	//System.out.println("Payload information is: " + msg);
	                	//System.out.println("Payload information is: " + ip.getPayload());
	                	
	                    //System.out.println();
	                    count_ip ++;
	                    
	                    //Get the IP rules
	                    rules = parser.getRules("ip");
	                    //System.out.println("IP from pkt switch: " +rules.getRuleHeader().getProtocols());
	                    
	                }
	                else if (packet.hasHeader(udp)) {
	                	//IP address information of the packet
	                	sIP = ip.source();
	                	dIP = ip.destination();
	                	
	                	String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
	                	String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
	                	
	                	//copies to carry the actual values of the IPs
	                	String sourceIP_2 = sourceIP;
	                	String destinationIP_2 = destinationIP;
	                	
	                	//Classify the IP Addresses as either Home network or External Network
	                	String delimiter = "\\.";
	                	String range_1 = "10.0.0.0";
	                	String range_2 = "10.255.255.255";
	                	String range_3 = "172.20.0.0";
	                	String range_4 = "172.20.0.255";
	                	
	                	String[] temp1 = sourceIP.split(delimiter);
	                	String[] temp2 = destinationIP.split(delimiter);
	                	
	                	String[] temp3 = range_1.split(delimiter);
	                	String[] temp4 = range_2.split(delimiter);
	                	
	                	String[] temp5 = range_3.split(delimiter);
	                	String[] temp6 = range_4.split(delimiter);
	                	
	                	int octet1, octet2, octet3, octet4;
	            		int octet5, octet6, octet7, octet8;
	            		
	            		int octet9, octet10, octet11, octet12;
	            		int octet13, octet14, octet15, octet16;
	            		
	            		int octet17, octet18, octet19, octet20;
	            		int octet21, octet22, octet23, octet24;
	            		
	            		long result1 = 0; //Source IP
	            		long result2 = 0; //Destination IP
	            		long result3 = 0; //Network address 1
	            		long result4 = 0; //Broadcast address 1
	            		long result5 = 0; //Network address 2
	            		long result6 = 0; //Broadcast address 2
	            		
	            		for(int i = 0; i < temp1.length ; i++) {
	            			octet1 = Integer.parseInt(temp1[0]);
	            			octet2 = Integer.parseInt(temp1[1]);
	            			octet3 = Integer.parseInt(temp1[2]);
	            			octet4 = Integer.parseInt(temp1[3]);
	            			
	            			result1 = (octet1 << 24) + (octet2 << 18) + (octet3 << 8) + octet4;
	            		}
	            		//System.out.println("Source IP:" +result1);
	            		
	            		for(int i = 0; i < temp2.length ; i++) {
	            			octet5 = Integer.parseInt(temp2[0]);
	            			octet6 = Integer.parseInt(temp2[1]);
	            			octet7 = Integer.parseInt(temp2[2]);
	            			octet8 = Integer.parseInt(temp2[3]);
	            			
	            			result2 = (octet5 << 24) + (octet6 << 18) + (octet7 << 8) + octet8;
	            		}
	            		//System.out.println("Dest IP:" + result2);
	                	
	            		for(int i = 0; i < temp3.length ; i++) {
	            			octet9 = Integer.parseInt(temp3[0]);
	            			octet10 = Integer.parseInt(temp3[1]);
	            			octet11 = Integer.parseInt(temp3[2]);
	            			octet12 = Integer.parseInt(temp3[3]);
	            			
	            			result3 = (octet9 << 24) + (octet10 << 18) + (octet11 << 8) + octet12;
	            		}
	            		//System.out.println("Network IP 1:" + result3);
	            		
	            		for(int i = 0; i < temp4.length ; i++) {
	            			octet13 = Integer.parseInt(temp4[0]);
	            			octet14 = Integer.parseInt(temp4[1]);
	            			octet15 = Integer.parseInt(temp4[2]);
	            			octet16 = Integer.parseInt(temp4[3]);
	            			
	            			result4 = (octet13 << 24) + (octet14 << 18) + (octet15 << 8) + octet16;
	            		}
	            		//System.out.println("Broadcast IP 1:" + result4);
	            		
	            		for(int i = 0; i < temp5.length ; i++) {
	            			octet17 = Integer.parseInt(temp5[0]);
	            			octet18 = Integer.parseInt(temp5[1]);
	            			octet19 = Integer.parseInt(temp5[2]);
	            			octet20 = Integer.parseInt(temp5[3]);
	            			
	            			result5 = (octet17 << 24) + (octet18 << 18) + (octet19 << 8) + octet20;
	            		}
	            		//System.out.println("Network IP 2:" + result5);
	            		
	            		for(int i = 0; i < temp6.length ; i++) {
	            			octet21 = Integer.parseInt(temp6[0]);
	            			octet22 = Integer.parseInt(temp6[1]);
	            			octet23 = Integer.parseInt(temp6[2]);
	            			octet24 = Integer.parseInt(temp6[3]);
	            			
	            			result6 = (octet21 << 24) + (octet22 << 18) + (octet23 << 8) + octet24;
	            		}
	            		//System.out.println("Broadcast IP 2:" + result6);
	            		
	            		//Specify home and external networks
	            		if(result3 <= result1 && result1 <= result4 || result5 <= result1 && result1 <= result6) {
	            			sourceIP = "$HOME_NET";
	            			destinationIP = "$HOME_NET";
	            		}
	            		else {
	            			sourceIP = "$EXTERNAL_NET";
	            			destinationIP = "$EXTERNAL_NET";
	            		}
	            		
	            		//System.out.println("Source port of the udp packet is: " +udp.source());//prints out source port of udp packet
	                	//System.out.println("Destination port of the udp packet is: " +udp.destination());//prints out source port of udp packet
	                	
	            		//RETRIEVE UDP PAYLOAD DATA
	                	byte [] udpMessage =  udp.getPayload();
	                	String msg = new String(udpMessage);
	                	//System.out.println("Payload information is: " + msg);
	                	//System.out.println("Payload information is: " + udp.getPayload());
	                	
	                    //System.out.println();
	                    count_udp ++;
	                    
	                  //Get the UDP rules
	                    rules = parser.getRules("udp");
	                    //System.out.println("UDP from pkt switch: " +rules.getRuleHeader().getProtocols());
	                    
	                }
	            }
	        };
	        //we enter the loop and capture the packets here.You can  capture any number of packets just by changing the first argument to pcap.loop() function below
            pcap.loop(-1, jpacketHandler, "jnetpcap sucks!");
            System.out.println();
            System.out.println("The total number of icmp rules triggered is:" +icmp_count);
            System.out.println("The total number of tcp rules triggered is:" +tcp_count);
            System.out.println("The total number of ip rules triggered is:" +ip_count);
            System.out.println("The total number of udp rules triggered is:" +udp_count);
            //Close the pcap
            pcap.close();
		} 
		
		catch (Exception ex) {
			System.out.println(ex);
	
		}
		
	}//end of action
	
	public int icmpFinal = 115;
	public int tcpFinal = 101;
	public int ipFinal = 1;
	public int udpFinal = 23;
	
	public int icmpCount = 301;
	public int tcpCount = 3036;
	public int ipCount = 22;
	public int udpCount = 125;
	
	
	public boolean done() {
		return true;
	}
}
