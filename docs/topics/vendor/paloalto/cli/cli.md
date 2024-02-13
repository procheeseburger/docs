# Commandline

	Routing Protocol
	
		BGP
		
		
			Commands:
			
				> show routing protocol bgp

				> loc-rib          show BGP local-rib

				> loc-rib-detail   show BGP local-rib

				> peer             show BGP peer status

				> peer-group       show BGP peer group status

				> policy           show BGP route-map status

				> rib-out          show BGP routes sent to BGP peer

				> rib-out-detail   show BGP routes sent to BGP peer

				> summary          show BGP summary information
				
				
	Interface commands:
	
		show system state filter-pretty sys.s1.ha2*
		show system state filter-pretty sys.s1.ha2.status
		```
		show high-availability interface <ha1|ha1-backup|ha2|ha2-backup|ha3|ha4|ha4-backup>
		```
- Show the HSCI Link Speed:
		show system state filter * | match ha.net.s4.hsci
		
		
	Logging:
	
		debug log-collector log-collection-stats show incoming-logs
		
		
	
	URL DB:
	
		> show url-cloud status
		
		


K8s

	Restart the K8s Plugin:
	
	  > request plugins reset-plugin only plugin plugin-name kubernetes
		