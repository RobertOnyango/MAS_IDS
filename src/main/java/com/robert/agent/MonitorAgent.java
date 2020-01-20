package com.robert.agent;

import com.robert.behaviours.MonitorResultsBehaviour;

import jade.core.Agent;

public class MonitorAgent extends Agent{

	/**
	 * 
	 */
	private static final long serialVersionUID = 8844980834348115888L;
	
	protected void setup() {
	    System.out.println("Monitor Agent "+getLocalName()+" is started.");

	    // Add the behavior: rule analysis
	    addBehaviour(new MonitorResultsBehaviour());
	    
	  }
	  
	 
	  /**
	   * This method is automatically called after doDelete()
	   */
	  protected boolean takedown() {
		  return true;
	  }

}
