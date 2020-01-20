package com.robert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.robert.behaviours.MonitorResultsBehaviour;

@Controller
public class HomeController {
	@RequestMapping("/home")
	public ModelAndView add(HttpServletRequest request, HttpServletResponse response) {
		
		ModelAndView mv = new ModelAndView();
		mv.setViewName("home.jsp");
		mv.addObject("msg", "This is the home page");
		
		MonitorResultsBehaviour monitor = new MonitorResultsBehaviour();
		
		//Rules triggered
		int tcpCount = monitor.tcpFinal;
		int udpCount = monitor.udpFinal;
		int icmpCount = monitor.icmpFinal;
		int ipCount = monitor.ipFinal;
		
		//Total rules per protocol
		int tcpFinal = monitor.tcpCount;
		int udpFinal = monitor.udpCount;
		int icmpFinal = monitor.icmpCount;
		int ipFinal = monitor.ipCount;
		
		
		mv.addObject("tcp", tcpCount);
		mv.addObject("udp", udpCount);
		mv.addObject("icmp", icmpCount);
		mv.addObject("ip", ipCount);
		
		mv.addObject("tcpF", tcpFinal);
		mv.addObject("udpF", udpFinal);
		mv.addObject("icmpF", icmpFinal);
		mv.addObject("ipF", ipFinal);
		
		return mv;
	}
}
