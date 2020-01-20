package com.robert.agent;

import com.robert.behaviours.RuleAnalysisBehaviour;
import jade.core.Agent;
import jade.core.behaviours.Behaviour;
import jade.core.behaviours.CyclicBehaviour;
import jade.core.behaviours.SimpleBehaviour;


public class SnifferAgent extends Agent {
	
	
	  private static final long serialVersionUID = 1410401284578853709L;

	  protected void setup() {
	    System.out.println("Sniffer Agent "+getLocalName()+" is started.");

	    // Add the behavior: rule analysis
	    addBehaviour(new RuleAnalysisBehaviour());
	    
	  }
	  
	 
	  /**
	   * This method is automatically called after doDelete()
	   */
	  protected boolean takedown() {
		  return true;
	  }
}
