package com.robert.util;

import java.io.*;

public class RuleHandler {
	
	int i=0;
	public  String[] getRules(String filename) {
		// TODO Auto-generated method stub
		String[] rules=new String[100000];
		
		try{
			
			File file=new File(filename);
			FileReader fileReader=new FileReader(file);
			
			BufferedReader reader=new BufferedReader(fileReader);
			
			String line="";
			
			while((line=reader.readLine())!=null){
				if(line.length()!=0){
					if(line.charAt(0)!='#'){
						
						rules[i]=line;
					
						//System.out.println(rules[i]);
						i++;
						
					}
				}
				
			}
			
			reader.close();	
			//System.out.println(rules.);
		}catch(Exception ex){
			
			ex.printStackTrace();
		}
		return rules;
		//System.out.println(rules);

	}
	public int noOfRules(){
		return i;
	}

}
