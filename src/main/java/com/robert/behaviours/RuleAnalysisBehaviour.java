package com.robert.behaviours;

import jade.core.AID;
import jade.core.behaviours.Behaviour;
import jade.core.behaviours.SimpleBehaviour;
import jade.lang.acl.ACLMessage;
import jade.lang.acl.MessageTemplate;

import com.robert.agent.SnifferAgent;
import com.robert.packet.*;
import com.robert.packet.Packet.Header;
import com.robert.packet.Packet.Options;
import com.robert.util.*;
import com.robert.parser.*;


public class RuleAnalysisBehaviour extends Behaviour{
	
	private static final long serialVersionUID = 9088209402507795289L;
	
	String[] temprule = new String[1000]; 
	String[] rule= new String[10000];
	
	public void action() {
		// TODO Auto-generated method stub
		int cntStart=0;
		int cntEnd=0;
		int tcp_count=0;
		int udp_count=0;
		int icmp_count=0;
		int ip_count=0;
		
		Rules rules = new Rules();
		Parser parser = new Parser();
		
		String file_name = "c:\\rules/snort3-community.rules";
		
		RuleHandler rh = new RuleHandler();
		temprule = rh.getRules(file_name);
		cntEnd = rh.noOfRules()+cntStart;
		int l=0;
		for(int k=cntStart; k<cntEnd; k++) {
			
			rule[k]=temprule[l];
			//System.out.println(rule[k]);
			l++;
			
		}
		cntStart = cntEnd;
		
		
		System.out.println("The total number of SNORT rules is: "+cntEnd);
		System.out.println();
		
		//instantiate packet class
		Packet pkt = new Packet();
		Packet.Header head = pkt.new Header();
		Packet.Options opt = pkt.new Options();
		
		cntStart = 0;
		for (int i=cntStart; i<cntEnd; i++) {
			
			rules = parser.getRules(rule[i]);
			
			//************CONTENT BELOW BELONGS HERE*******************
			//Get the rule headers as first categorization step.
			String protocol = rules.getRuleHeader().getProtocols();
			String msg = rules.getRuleOption().getGeneralOption().getMsg();
			//System.out.println(protocol);
			//System.out.println(msg);
			
			switch (protocol) {
			case "tcp":
				tcp_count++;
				
				break;
				
			case "udp":
				udp_count++;

				break;
			
			case "icmp":
				icmp_count++;
					
				break;
				
			case "ip":
				ip_count++;
								
				break;
			
			default:
				System.out.println("");
				break;
			}
			
		}//end of for loop for traversing the rules
		
		System.out.println("Total number of tcp rules: " +tcp_count);
		System.out.println("Total number of udp rules: " +udp_count);
		System.out.println("Total number of ip rules: " +ip_count);
		System.out.println("Total number of icmp rules is: " +icmp_count);
		System.out.println();
		
		
		ACLMessage msg = new ACLMessage(ACLMessage.INFORM);
		//msg.setContentObject(rules);
		msg.setContent("Hello analysis agent");
		//set the receiver
		msg.addReceiver(new AID("Agent2",AID.ISLOCALNAME));
		//send the message
		send(msg);
		
		
	}//end of action
	
	public int ruleFinal = 3486;
	public int tcpFinal = 3034;
	public int udpFinal = 301;
	public int icmpFinal = 125;
	public int ipFinal = 22;
	
	private void send(ACLMessage msg) {
		// TODO Auto-generated method stub
		
	}
	
	public boolean done() {
		return true;
	}

}

