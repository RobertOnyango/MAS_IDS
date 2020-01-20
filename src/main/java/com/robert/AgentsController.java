package com.robert;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import jade.core.Profile;
import jade.core.ProfileImpl;
import jade.core.Runtime;
import jade.wrapper.AgentContainer;
import jade.wrapper.AgentController;
import jade.wrapper.ContainerController;
import jade.wrapper.ControllerException;
import jade.wrapper.StaleProxyException;


@Controller
public class AgentsController{
	
	/**
	 * IP (or host) of the main container
	 */
	private static String PLATFORM_IP = "127.0.0.1"; 
	
	/**
	 * Port to use to contact the AMS
	 */
	private static int PLATFORM_PORT=8888;
	
	/**
	 * ID (name) of the platform instance
	 */
	private static String PLATFORM_ID="MAS";
	
	private static HashMap<String, ContainerController> containerList=new HashMap<String, ContainerController>();// container's name - container's ref
	private static List<AgentController> agentList;// agents's ref
	private static Runtime rt;
	
	//MODEL AND VIEW:
	@RequestMapping("/start")
	public static ModelAndView start(HttpServletRequest request, HttpServletResponse response) {
		
		ModelAndView mv = new ModelAndView();
		mv.setViewName("home");
		mv.getView();
		
		//Create platforms
		rt=emptyPlatform(containerList);
		
		//Create containers
		agentList=createAgents(containerList);

		//Launch agents
		startAgents(agentList);
		
		return mv;
	}
	
	/**********************************************
	 * 
	 * Methods used to create an empty platform
	 * 
	 **********************************************/

	/**
	 * Create an empty platform composed of 1 main container and several containers.
	 * 
	 * @param containerList the HashMap of (container's name,container's ref)
	 * @return a ref to the platform and update the containerList
	 */
	private static Runtime emptyPlatform(HashMap<String, ContainerController> containerList){

		Runtime rt = Runtime.instance();

		// 1) create a platform (main container+DF+AMS)
		Profile pMain = new ProfileImpl(PLATFORM_IP, PLATFORM_PORT, PLATFORM_ID);
		System.out.println("Launching a main-container..."+pMain);
		AgentContainer mainContainerRef = rt.createMainContainer(pMain); //DF and AMS are include

		// 2) create the containers
		containerList.putAll(createContainers(rt));

		// 3) create monitoring agents : rma agent, used to debug and monitor the platform; sniffer agent, to monitor communications; 
		createMonitoringAgents(mainContainerRef);

		System.out.println("Plaform ok");
		return rt;

	}
	
	/**
	 * Create the containers used to hold the agents 
	 * @param rt The reference to the main container
	 * @return an Hmap associating the name of a container and its object reference.
	 * <p>
	 * note: there is a smarter way to find a container with its name, but we go straight to the goal here. Cf jade's doc.
	 */
	private static HashMap<String,ContainerController> createContainers(Runtime rt) {
		String containerName;
		ProfileImpl pContainer;
		ContainerController containerRef;
		HashMap<String, ContainerController> containerList=new HashMap<String, ContainerController>();//bad to do it here.


		System.out.println("Launching containers ...");

		//create the container1	
		containerName="Mycontainer1";
		pContainer = new ProfileImpl(PLATFORM_IP, PLATFORM_PORT, PLATFORM_ID);
		pContainer.setParameter(Profile.CONTAINER_NAME,containerName);

		System.out.println("Launching container "+pContainer);
		containerRef = rt.createAgentContainer(pContainer); //ContainerController replace AgentContainer in the new versions of Jade.
		containerList.put(containerName, containerRef);

		//create the container2	
		containerName="Mycontainer2";
		pContainer = new ProfileImpl(PLATFORM_IP, PLATFORM_PORT, PLATFORM_ID);
		pContainer.setParameter(Profile.CONTAINER_NAME,containerName);
		System.out.println("Launching container "+pContainer);
		containerRef = rt.createAgentContainer(pContainer); //ContainerController replace AgentContainer in the new versions of Jade.
		containerList.put(containerName, containerRef);

		//create the container3	
		containerName="Mycontainer3";
		pContainer = new ProfileImpl(PLATFORM_IP, PLATFORM_PORT, PLATFORM_ID);
		pContainer.setParameter(Profile.CONTAINER_NAME,containerName);
		System.out.println("Launching container "+pContainer);
		containerRef = rt.createAgentContainer(pContainer); //ContainerController replace AgentContainer in the new versions of Jade.
		containerList.put(containerName, containerRef);

		System.out.println("Launching containers done");
		return containerList;
	}
	
	/**
	 * create the monitoring agents (rma+sniffer) on the main-container given in parameter and launch them.
	 * <ul>
	 * <li> RMA agent's is used to control, debug and monitor the platform;
	 * <li> Sniffer agent is used to monitor communications
	 * </ul>
	 * @param mc the main-container's reference
	 */
	private static void createMonitoringAgents(ContainerController mc) {

		System.out.println("Launching the rma agent on the main container ...");
		AgentController rma;

		try {
			rma = mc.createNewAgent("rma", "jade.tools.rma.rma", new Object[0]);
			rma.start();
		} catch (StaleProxyException e) {
			e.printStackTrace();
			System.out.println("Launching of rma agent failed");
		}

		System.out.println("Launching  Sniffer agent on the main container...");
		AgentController snif=null;

		try {
			snif= mc.createNewAgent("sniffeur", "jade.tools.sniffer.Sniffer",new Object[0]);
			snif.start();

		} catch (StaleProxyException e) {
			e.printStackTrace();
			System.out.println("launching of sniffer agent failed");

		}		
	
	}
	
	/**
	 *  Creates the agents and add them to the agentList. The agents are NOT started.
	 *@param containerList :Name and container's ref
	 *@return the agentList
	 */
	private static List<AgentController> createAgents(HashMap<String, ContainerController> containerList) {
		ContainerController c;
		String agentName;
		String containerName;
		List<AgentController> agentList=new ArrayList<AgentController>();
		
		//Agent0 on container1
		containerName="Mycontainer1";
		c = containerList.get(containerName);
		agentName="Agent1";
		
		List<String> data=new ArrayList<String>();
		data.add("This");data.add("is");data.add("a");data.add("test");
		Object[] objtab=new Object[]{data};// Example regarding how to give information to an agent at creation. These "data" will be processed in the setup() method of agent0 
		createOneAgent(c, agentName, com.robert.agent.SnifferAgent.class.getName(),agentList, objtab);
		
		agentName="Agent0";
		objtab=new Object[]{};//used to give informations to the agent (in that case, nothing)
		//createOneAgent(c, agentName, com.robert.agent.SnifferAgent.class.getName(), agentList, objtab);
		
		//Agent1 and Agent3 on Mycontainer2
		containerName="Mycontainer2";
		c = containerList.get(containerName);
		
		agentName="Agent2";
		objtab=new Object[]{};//used to give informations to the agent (in that case, nothing)
		createOneAgent(c, agentName, com.robert.agent.AnalysisAgent.class.getName(),agentList, objtab);

		//Agent2 on Mycontainer3
		containerName="Mycontainer3";
		c = containerList.get(containerName);
		agentName="Agent3";
		objtab=new Object[]{};//used to give informations to the agent (in that case, nothing)
		createOneAgent(c, agentName, com.robert.agent.MonitorAgent.class.getName(), agentList, objtab);
		
		System.out.println("Agents launched...");
		return agentList;
		
	}
	
	/**
	 * Create one agent agentName of class className wit parameters  objtab on container c
	 * @param c containerObject
	 * @param agentName name of the agent
	 * @param className class of the agent
	 * @param agentList list that store the agents'references 
	 * @param objtab agent's initial parameters
	 */
	private static void createOneAgent(ContainerController c, String agentName, String className, List<AgentController> agentList, Object[] objtab) {
		try {						
			AgentController	ag=c.createNewAgent(agentName,className,objtab);
			agentList.add(ag);
			try {
				System.out.println(agentName+" launched on "+c.getContainerName());
			} catch (ControllerException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (StaleProxyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Start the agents
	 * @param agentList
	 */
	private static void startAgents(List<AgentController> agentList){

		System.out.println("Starting agents...");


		for(final AgentController ac: agentList){
			try {
				ac.start();
			} catch (StaleProxyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		System.out.println("Agents started...");
	}
		
}
				
				