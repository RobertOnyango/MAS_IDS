package com.robert;

import java.io.File;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class LogsController {
	
	static String filepath = "C:\\pcap packets\\wrccdc.regionals.2019-03-01.083858000050000.pcap";
	static double count = 0;
	static double count_tcp = 0;
	static double count_ip = 0;
	static double count_udp = 0;
	static double count_icmp = 0;
	static double globalcount = 0;
	
	@SuppressWarnings("unchecked")
	@RequestMapping("/logs")
	public ModelAndView add(HttpServletRequest request, HttpServletResponse response) {
		
		ModelAndView mv = new ModelAndView();
		mv.setViewName("logs.jsp");
		mv.addObject("msg", "This is the logs page");
		
		try {
		
			File file = new File(filepath);
			
			final StringBuilder errbuf = new StringBuilder();
			
			Pcap pcap = Pcap.openOffline(filepath, errbuf);
			
			//Create packet handler which will receive packets
	        PcapPacketHandler jpacketHandler = new PcapPacketHandler <String>() {
	            Icmp icmp = new Icmp();
	            Tcp tcp = new Tcp();
	            Ip4 ip = new Ip4();
	            Udp udp = new Udp();
	            
	            byte[] sIP = new byte[4];
	            byte[] dIP = new byte[4];
	            int sPrt;
	            int dPrt;
	            
	            @Override
	            public void nextPacket(PcapPacket packet, String user) {
	            	count ++;
	            	if(packet.hasHeader(tcp)) {
	            		/**sIP = ip.source();
	                	dIP = ip.destination();
	                	String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
	                	String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
	                	
	                	byte [] tcpMessage =  tcp.getPayload();
	                	String msg = new String(tcpMessage);
	                	
	                	String[] pkt_info = {sourceIP,destinationIP, msg};
	                	
	                	mv.addObject("tcps",pkt_info);
	                	*/
	            		JPacket tcp_;
	            		sIP = ip.source();
	                	dIP = ip.destination();
	                	
	                	tcp_ = tcp.getPacket();
	            		mv.addObject("tcp",tcp_);
	            	}
	            	else if(packet.hasHeader(icmp)) {
	            		JPacket icmp_;
	            		sIP = ip.source();
	                	dIP = ip.destination();
	                	
	                	icmp_ = icmp.getPacket();
	            		mv.addObject("icmp",icmp_);
	            	}
	            	else if(packet.hasHeader(ip)) {
	            		JPacket ip_;
	            		sIP = ip.source();
	                	dIP = ip.destination();
	                	
	            		ip_ = ip.getPacket();
	            		mv.addObject("ip",ip_);
	            	}
	            	else if(packet.hasHeader(udp)) {
	            		JPacket udp_;
	            		sIP = ip.source();
	                	dIP = ip.destination();
	                	
	            		udp_ = udp.getPacket();
	            		mv.addObject("udp",udp_);
	            	}
	            		
	            }
	        };
	        pcap.loop(-1, jpacketHandler, "jnetpcap rocks!");
	        //System.out.println("The total number of packets from controller is:" + count);
	        mv.addObject("logs",jpacketHandler);
	       //Close the pcap
            pcap.close();
		}
		
		catch (Exception ex) {
			System.out.println(ex);
	
		}
		
		return mv;
	}
}
