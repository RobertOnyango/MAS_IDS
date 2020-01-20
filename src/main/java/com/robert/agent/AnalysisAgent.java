package com.robert.agent;

import com.robert.behaviours.NetworkCaptureBehaviour;
import jade.core.Agent;
import jade.lang.acl.ACLMessage;

import com.robert.packet.Packet;

public class AnalysisAgent extends Agent {
	
	public static Packet pkt;
	
	protected void setup() {
	    
		System.out.println("Analysis Agent "+getLocalName()+" is started.");
	    			
	    // Add the behaviour: rule analysis
	    addBehaviour(new NetworkCaptureBehaviour(this));
	    
	}
	
	
	protected boolean takedown() {
		return true;
	}

}
