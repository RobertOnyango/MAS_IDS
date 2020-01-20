package com.robert.parser;

import java.io.Serializable;

public class Rules implements Serializable {
	
	private RuleHeader ruleHeader;
	private RuleOption ruleOption;
	
	//getters
	public RuleHeader getRuleHeader(){
		return ruleHeader;
	}

	public RuleOption getRuleOption(){
		return ruleOption;
	}	
			
	//setters
	public void setRuleHeader(RuleHeader s){
		ruleHeader=s;
	}
	
	public void setRuleOption(RuleOption s){
		ruleOption=s;
	}

}
