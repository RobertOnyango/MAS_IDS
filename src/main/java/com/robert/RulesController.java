package com.robert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.robert.behaviours.RuleAnalysisBehaviour;
import com.robert.parser.Parser;
import com.robert.parser.Rules;
import com.robert.util.RuleHandler;

@Controller
public class RulesController {

	@RequestMapping("/rules")
	public ModelAndView add(HttpServletRequest request, HttpServletResponse response) {
		
		ModelAndView mv = new ModelAndView();
		mv.setViewName("rules.jsp");
		mv.addObject("msg", "This is the rules page");
		
		RuleAnalysisBehaviour rules = new RuleAnalysisBehaviour();
		
		String[] temprule = new String[1000]; 
		String[] rule= new String[10000];
		
		int cntStart=0;
		int cntEnd=0;
		
		String file_name = "c:\\rules/snort3-community.rules";
		
		RuleHandler rh = new RuleHandler();
		temprule = rh.getRules(file_name);
		cntEnd = rh.noOfRules()+cntStart;
		int l=0;
		for(int k=cntStart; k<cntEnd; k++) {
			
			rule[k]=temprule[l];
			//System.out.println(rule[k]);
			mv.addObject("rule1", rule[cntStart]);
			mv.addObject("rule2", rule[1]);
			mv.addObject("rule3", rule[2]);
			mv.addObject("rule4", rule[3]);
			mv.addObject("rule5", rule[4]);
			mv.addObject("rule6", rule[5]);
			mv.addObject("rule7", rule[6]);
			mv.addObject("rule8", rule[7]);
			mv.addObject("rule9", rule[8]);
			mv.addObject("rule10", rule[9]);
			mv.addObject("rule11", rule[10]);
			mv.addObject("rule12", rule[11]);
			mv.addObject("rule13", rule[12]);
			mv.addObject("rule14", rule[13]);
			mv.addObject("rule15", rule[14]);
			mv.addObject("rule16", rule[15]);
			mv.addObject("rule17", rule[16]);
			mv.addObject("rule18", rule[17]);
			mv.addObject("rule19", rule[18]);
			mv.addObject("rule20", rule[19]);
			mv.addObject("rule21", rule[20]);
			mv.addObject("rule22", rule[21]);
			mv.addObject("rule23", rule[22]);
			mv.addObject("rule24", rule[23]);
			mv.addObject("rule25", rule[24]);
			mv.addObject("rule26", rule[25]);
			mv.addObject("rule27", rule[26]);
			mv.addObject("rule28", rule[27]);
			mv.addObject("rule29", rule[28]);
			mv.addObject("rule30", rule[29]);
			mv.addObject("rule31", rule[30]);
			mv.addObject("rule32", rule[31]);
			mv.addObject("rule33", rule[32]);
			mv.addObject("rule34", rule[33]);
			mv.addObject("rule35", rule[34]);
			mv.addObject("rule36", rule[35]);
			mv.addObject("rule37", rule[36]);
			mv.addObject("rule38", rule[37]);
			mv.addObject("rule39", rule[38]);
			mv.addObject("rule40", rule[39]);
			mv.addObject("rule41", rule[40]);
			mv.addObject("rule42", rule[41]);
			mv.addObject("rule43", rule[42]);
			mv.addObject("rule44", rule[43]);
			mv.addObject("rule45", rule[44]);
			mv.addObject("rule46", rule[45]);
			mv.addObject("rule47", rule[46]);
			mv.addObject("rule48", rule[47]);
			mv.addObject("rule49", rule[48]);
			mv.addObject("rule50", rule[49]);
			mv.addObject("rule51", rule[50]);
			mv.addObject("rule52", rule[51]);
			mv.addObject("rule53", rule[52]);
			mv.addObject("rule54", rule[53]);
			mv.addObject("rule55", rule[54]);
			mv.addObject("rule56", rule[55]);
			mv.addObject("rule57", rule[56]);
			mv.addObject("rule58", rule[57]);
			mv.addObject("rule59", rule[58]);
			mv.addObject("rule60", rule[59]);
			mv.addObject("rule61", rule[60]);
			mv.addObject("rule62", rule[61]);
			mv.addObject("rule63", rule[62]);
			mv.addObject("rule64", rule[63]);
			mv.addObject("rule65", rule[64]);
			mv.addObject("rule66", rule[65]);
			mv.addObject("rule67", rule[66]);
			mv.addObject("rule68", rule[67]);
			mv.addObject("rule69", rule[68]);
			mv.addObject("rule70", rule[69]);
			mv.addObject("rule71", rule[70]);
			mv.addObject("rule72", rule[71]);
			mv.addObject("rule73", rule[72]);
			mv.addObject("rule74", rule[73]);
			mv.addObject("rule75", rule[74]);
			mv.addObject("rule76", rule[75]);
			mv.addObject("rule77", rule[76]);
			mv.addObject("rule78", rule[77]);
			mv.addObject("rule79", rule[78]);
			mv.addObject("rule80", rule[79]);
			mv.addObject("rule81", rule[80]);
			mv.addObject("rule82", rule[81]);
			mv.addObject("rule83", rule[82]);
			mv.addObject("rule84", rule[83]);
			mv.addObject("rule85", rule[84]);
			mv.addObject("rule86", rule[85]);
			mv.addObject("rule87", rule[86]);
			mv.addObject("rule88", rule[87]);
			mv.addObject("rule100", rule[cntEnd]);
			l++;	
		}

		cntStart = cntEnd;
		
		int ruleCount = rules.ruleFinal;
		
		int tcpCount = rules.tcpFinal;
		int udpCount = rules.udpFinal;
		int icmpCount = rules.icmpFinal;
		int ipCount = rules.ipFinal;
		
		//mv.addObject("rules", rule[0]);
		
		mv.addObject("rule", ruleCount);
		mv.addObject("tcp", tcpCount);
		mv.addObject("udp", udpCount);
		mv.addObject("icmp", icmpCount);
		mv.addObject("ip", ipCount);
		
		
		return mv;
	}
}
