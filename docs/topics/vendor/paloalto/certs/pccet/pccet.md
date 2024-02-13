# PCCET

- Pale Alto Networks Certified Cybersecurity Entry-level Technician

## Resources

- [All Certifications](https://paloaltonetworks.exceedlms.com/student/catalog/list?category_ids=20262-certifications)
- [PCCET technical documentation](https://beacon.paloaltonetworks.com/)
- [PCCET Study Guide](https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/datasheets/education/pccet-study-guide.pdf)
- Cyber Security Foundation digital learning courses:
  - [Introduction to Cybersecurity](https://paloaltonetworks.com/EDU-001)
  - [Fundamentals of Network Security](https://paloaltonetworks.com/EDU-010)
  - [Fundamentals of Cloud Security](https://paloaltonetworks.com/EDU-040)
  - [Fundamentals of Security Operations Center (SOC)](https://paloaltonetworks.com/EDU-070)
- [PaloAlto Networks Cyber Security Academy Cybersecurity Survival Guide](https://paloaltonetworks.com/resources/techbriefs/cybersecurity-survival-guide)

## Blueprint

- [Exam Blueprint](https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/datasheets/education/pccet-blueprint.pdf)

- Domain Weight (%)
  - Fundamentals of Cybersecurity 30%
  - Network Security Components 30%
  - Cloud Technologies 20%
  - Elements of Security Operations 20%

## Domain 1 - Fundamentals of Cybersecurity

- After you complete this training, you should be able to:
  - Describe the current cybersecurity landscape
  - Identify cybersecurity threats
  - Evaluate different malware types and cyber attack techniques
  - Describe the relationship between vulnerabilities and exploits
  - Identify how spamming and phishing attacks are performed
  - Describe Wi-Fi vulnerabilities, attacks, and advanced persistent threats
  - Explain perimeter-based Zero Trust security models
  - Identify capabilities of the PaloAlto Networks prevention-first architecture

### Cybersecurity Landscape

- Web 2.0 and Web 2.0 Applications
  - File Sync and Sharing
  - Instant Messaging
  - Microblogging
  - Office Productivity Suites
  - Remote Access Software

- Web 3.0
  - The vision of Web 3.0 is to return the power of the internet to individual users
  - AI and Machine Learning
  - blockchain
  - Data Mining
  - Mixed Reality
  - Natural Language Search

- Managed Security Services
  - The global shortage of cybersecurity professionals – estimated by the International Information System Security Certification Consortium (ISC) squared to be 2.72 million in 2021

- Work-from-Home (WFH) and Work-from-Anywhere (WFA)
  - many organizations have implemented remote working models that include WFH and WFA

- New Application Threat Vectors
  - Exploiting vulnerabilities in core business applications has long been a predominant attack vector
  - threat actors are constantly developing new tactics, techniques, and procedures (TTPs)
  - Protect Networks and Cloud Environments
    - To effectively protect their networks and cloud environments, enterprise security teams must manage the risks associated with a relatively limited, known set of core applications
  - Application Classification
    - Many applications are designed to circumvent traditional port-based firewalls
    - Many organizations use social networking applications such as Facebook for important business functions such as recruiting, research and development, marketing, and consumer advocacy. However, these same applications can be used to leak sensitive information or cause damage to an organization’s public image – whether inadvertently or maliciously.
    - Tactics, Techniques, and Procedures (TTPs)
      - Port Hopping
        - Randomly change ports and protocols during a session
      - Non-Standard Ports
        - Running apps over port 80 instead of its standard port
      - Tunneling
        - Peer-to-peer file sharing
      - SSL Encryption
        - Running apps over HTTPs

- Turbulence in the Cloud
  - Cloud computing technologies help organizations evolve their data centers from a hardware-centric architecture to a dynamic and automated environment. Cloud environments pool computing resources for on-demand support of application workloads that can be accessed anywhere, anytime, and from any device.
  - Cloud trade offs
    - Simplicity or Function
    - Efficiency or Visibility
    - Agility or Security

- Software-as-a-service (SaaS) Application Risks
  - The average employee uses at least eight applications
  - Introduction to SaaS
    - Data is located everywhere in today’s enterprise networks
    - With SaaS applications, data is often stored where the application resides – in the cloud
    - Thus, the data is no longer under the organization’s control, and visibility is often lost

  - SaaS Security Challenges
    - Malicious Outsiders
      - Some malware will even target the SaaS applications themselves, for example, by changing their shares to “public” so that the data can be retrieved by anyone.
    - Malicious Insiders
      - The least common but real SaaS application risk is the internal user who maliciously shares data for theft or revenge purposes.
    - Accidental Data Exposure
      - Accidental data exposure by end users is surprisingly common and includes accidental share, promiscuous share, and ghost share
    - Accidental Share
      - An accidental share happens when a share meant for a particular person is accidentally sent to the wrong person or group
    - Promiscuous Share
      - a legitimate share is created for a user, but that user then shares with other people who shouldn’t have access
    - Ghost (or Stale) Share
      - the share remains active for an employee or vendor that is no longer working with the company or should no longer have access

- Compliance Challenges
  - Compliance and security are not the same thing
  - Change and Complicity
    - Many laws and regulations are obsolete or ambiguous and are not uniformly supported by international communities.
  - Compliance and Security
    - An organization can be fully compliant with all applicable cybersecurity laws and regulations, yet still not be secure.
    - Conversely, an organization can be secure, yet not fully compliant.
    - To further complicate this point, the compliance and security functions in many organizations are often defined and supervised by separate entities.

  - Standards and Regulations
    - The Payment Card Industry's Data Security Standard (PCI DSS)
      - establishes its own cybersecurity standards and best practices for businesses and organizations that allow payment card purchases
    - The European Union (EU) General Data Protection Regulations (GDPR)
      - apply to any organization that does business with EU citizens

- Attacker Profiles
  - Cyber criminals
  - State-Affiliated Groups
  - Hacktivists
  - Cyber terrorists
  - Script Kiddies
  - Cyber crime Vendors

- Cyber attack Lifecycle
  - Reconnaissance
  - Weaponization
  - Delivery
  - Exploitation
  - Installation
  - Command and Control
  - Act on Objective

- High-Profile Attacks
  - SolarWinds
        In December 2020, the cybersecurity firm FireEye and the U.S. Treasury Department both reported attacks involving malware in a software update to their SolarWinds Orion Network Management System perpetrated by the APT29 (Cozy Bear/Russian SVR) threat group. This attack is one of the most damaging supply chain attacks in history, potentially impacting more than 300,000 SolarWinds customers, including the U.S. federal government and 425 of the Fortune 500 companies.  

  - Colonial Pipeline
        In May 2021, the Colonial Pipeline Company – which operates one of the largest fuel pipelines in the U.S. – was hit by the DarkSide threat actor group with a Ransomware-as-a-Service (RaaS) attack. Although the company acted quickly to shut down its network systems and paid the $4.4 million ransom, operations were not fully restored for six days, which caused major fuel shortages and other supply chain issues along the U.S. eastern seaboard. Additionally, the personal information –including the health insurance information, social security numbers, driver’s licenses, and military identification numbers – of nearly 6,000 individuals were compromised.

  - JBS S.A.
        In May 2021, Brazil-based JBS S.A. – the largest producer of beef, chicken, and pork worldwide – was hit by a ransomware attack attributed to the REvil  threat actor group. Although the company paid the $11 million ransom, its U.S. and Australia beef processing operations were shut down for a week.

  - Government of Ukraine
        In January 2022, several Ukrainian government websites including the ministry of foreign affairs and the education ministry were hacked by suspected Russian attackers. Threatening messages were left on the websites during a period of heightened tensions between the governments of Ukraine and Russia.

- MITRE ATT&CK Framework
  - [MITRE](https://en.wikipedia.org/wiki/Mitre_Corporation)
  - a comprehensive matrix of tactics and techniques designed for threat hunters, defenders, and red teams to help classify attacks, identify attack attribution and objective, and assess an organization's risk.
  - Organizations can use the framework to identify security gaps and prioritize mitigation's based on risk.

  - MITRE Started ATT&CK Against Enterprise Networks
    - Started in 2013 to document TTPs that APTs use against enterprise networks

  - Pre-ATT&CK
    - Focuses on “pre-exploit” adversarial behavior

  - MITRE ATT&CK matrix
    - contains a set of techniques used by adversaries to accomplish a specific objective

- Sub-Techniques
  - more specific description of the adversarial behavior used to achieve a goal
  - They describe behavior at a lower level than a technique.
  - an adversary may dump credentials by accessing the Local Security Authority (LSA) secrets.

### Cyber attack Types

- Malware
  - malicious software - is a file or code that typically takes control of, collects information from, or damages an infected endpoint.

  - Malware is an inclusive term for all types of malicious software
    - To provide remote control for an attacker to use an infected machine
    - to send spam from the infected machine to unsuspecting targets
    - to investigate the infected users local network
    - to steal sensitive data

  - types of Malware
    - Logic Bombs
      - Malware that is triggered by a specified condition
    - Spyware and Adware
      - Collect information such as internet behavior
      - Can change browser and software settings
    - Bootkits
      - Kernel-mode variant of a rootkit
      - commonly used to attack computers that are protected by full-disk encryption
    - Rootkit
      - malware that provides privileged (root-level) access to a computer
    - Back doors
      - malware that allows an attacker to bypass auth to gain access
    - Anti-AV
      - malware that disables legit installed antivirus software
    - Ransomware
      - ransomware is not a single family of malware but is a criminal business model in which malware is used to hold something of value for ransom.
        - Locker
          - Malware that locks a computer
          - Reveton and LockeR are two examples of locker ransomware
        - Crytpo
          - Encrypts data
          - Locky, TeslaCrypt/EccKrypt, Cryptolocker, and Cryptowall are examples of crypto ransomware.
    - Trojan Horses
      - Malware that is disguised as harmless
    - Worms
      - Malware that targets a network by replicating itself to spread rapidly
    - Virus
      - Malware that is self-replicating

- Advanced Malware
  - Advanced or modern malware leverages networks to gain power and resilience

  - Obfuscation
    - Advanced malware often uses common obfuscation techniques to hide certain binary strings that are characteristically used in malware and therefore easily detected by anti-malware signatures.
    - Advanced malware might also use these techniques to hide an entire malware program.

  - Polymorphism
    - Some advanced malware has entire sections of code that serve no purpose other than to change the signature of the malware, thus producing an infinite number of unique signature hashes.
    - Techniques such as polymorphism and metamorphism are used to avoid detection by traditional signature-based anti-malware tools and software.
    - For example, a change of just a single character or bit of the file or source code completely changes the hash signature of the malware.

  - Distributed
    - Advanced malware takes full advantage of the resiliency built into the internet itself.
    - Advanced malware can have multiple control servers distributed all over the world with multiple fallback options.
    - Advanced malware can also leverage other infected endpoints as communication channels, thus providing a near-infinite number of communication paths to adapt to changing conditions or update code as needed.

  - Multi-Functional
    - Updates from C2 servers can also completely change the functionality of advanced malware.
    - This multifunctional capability enables an attacker to use endpoints strategically to accomplish specific tasks, such as stealing credit card numbers, sending spam containing other malware payloads (such as spyware), or installing ransomware for the purpose of extortion.

- Vulnerabilities and Exploits
  - Vulnerabilities and exploits can be leveraged to force software to act in ways it’s not intended to

  - Vulnerability
    - Vulnerabilities may exist in software when the software is initially developed and released
    - vulnerabilities may be inadvertently created, or even reintroduced, when subsequent version updates or security patches are installed.

  - Exploit
    - Malware that takes advantage of a vulnerability

- Patching Vulnerabilities
  - Security patches are developed by software vendors as quickly as possible after a vulnerability has been discovered in their software.  

- How Exploits Are Executed
  - Exploits can be embedded in seemingly innocuous data files
  - Exploits are particularly dangerous because they are often packaged in legitimate files that do not trigger anti-malware

  - Creation
    - Step one: embed a small piece of malicious code within the data file
    - Step two: typically involves memory corruption

  - Action
    - After the exploit data file is created, a legitimate application, such as a document viewer or web browser, will perform actions on behalf of the attacker, such as establishing communication and providing the ability to upload additional malware to the target endpoint.
    - Because the application being exploited is a legitimate application, traditional signature-based antivirus and whitelisting software have virtually no defense against these attacks.

  - Techniques
    - Although there are thousands of exploits, they all rely on a small set of core techniques.
    - Some attacks may involve more steps, and some may involve fewer, but typically three to five core techniques must be used to exploit an application.
    - Regardless of the attack or its complexity, for the attack to be successful the attacker must execute a series of these core exploit techniques in sequence.

  - Heap Spray
    - Heap spray is a technique used to facilitate arbitrary code execution by injecting a certain sequence of bytes into the memory of a target process.

- Timeline of Eliminating a Vulnerability
  - Vulnerabilities can be exploited from the time software is deployed until it is patched.

  - Software Deployed
    - For local systems, the only way to eliminate vulnerabilities is to effectively patch systems and software.

  - Vulnerability Discovered
    - Security patches are developed by software vendors as quickly as possible after a vulnerability has been discovered in their software.

  - Exploits Begin
    - The process of discovery and patching will continue. According to research by Palo Alto Networks, 78 percent of exploits take advantage of vulnerabilities that are less than two years old, which implies that developing and applying patches is a lengthy process.

  - Announcement of Vulnerability
    - An attacker may learn of a vulnerability and begin exploiting it before the software vendor is aware of the vulnerability or has an opportunity to develop a patch.

  - Patch Released
    - This delay between the discovery of a vulnerability and development and release of a patch is known as a zero-day threat (or exploit).

  - Patch Deployed
    - Months or years could pass by before a vulnerability is announced publicly.
    - After a security patch becomes available, time inevitably is required for organizations to properly test and deploy the patch on all affected systems.

  - Protected by Vendor Patch
    - During this time, a system running the vulnerable software is at risk of being exploited by an attacker.

### Cyber attack Techniques

- Business Email Compromise (BEC)
  - one of the most prevalent types of cyber attacks that organizations face today

  - Spam:
    - Process of spreading unsolicited content to target endpoints

  - Spim:
    - Spam via IM

  - Vishing
    - Spam via Voicemail

- Phishing Attacks

  - Spear Phishing
    - targeted phishing campaign that appears more credible to its victims
    - may spoof an organization
    - It may also contain very specific information (such as the recipient’s first name, rather than just an email address).

  - Whaling
    - Whaling is a type of spear phishing attack that is specifically directed at senior executives or other high-profile targets within an organization.
    - A whaling email typically purports to be a legal subpoena, customer complaint, or other serious matter

  - Watering Hole
    - Watering hole attacks compromise websites that are likely to be visited by a targeted victim

  - Pharming
    - A pharming attack redirects a legitimate website’s traffic to a fake site
    - typically with DNS Poisoning

- Bots and Botnets
  - Bots and botnets are notoriously difficult for organizations to detect and defend against using traditional anti-malware solutions.

  - Bots
    - Zombies are endpoints that are infected with advanced malware

  - Botnets
    - A group of bots working together

- Disabling a Botnet
  - Botnets themselves are dubious sources of income for cyber criminals.

  - Botnets are created by cyber criminals to harvest computing resources (bots). Control of botnets (through C2 servers) can then be sold or rented out to other cyber criminals.

- Actions for Disabling a Botnet

  - Disabling Internet Access
    - The first response to discovery of infected devices is to remove them from the network, thus severing any connections to a C2 server and keeping the infection from spreading.

  - Monitor Network Activity
    - ensure current patches and updates are applied

  - Remove Infected Devices Software
    - Some botnet software may go dormant
    - Re-image these devices

  - Install Current Patches
    - Keep all software up to date

- Spamming botnets
  - The largest botnets are often dedicated to sending spam.
  - The premise is straightforward: The attacker attempts to infect as many endpoints as possible, and the endpoints can then be used to send out spam email messages without the end users’ knowledge.

- Example Botnets

  - Rustock Botnet
    - The Rustock botnet is an example of a spamming botnet.
    - Rustock could send up to 25,000 spam email messages per hour from an individual bot.
    - At its its peak, it sent an average of 192 spam emails per minute per bot.
    - Rustock is estimated to have infected more than 2.4 million computers worldwide.
    - In March 2011, the U.S. Federal Bureau of Investigation (FBI), working with Microsoft and others, was able to take down the Rustock botnet. By then, the botnet had operated for more than five years.
    - At the time, it was responsible for sending up to 60 percent of the world’s spam.

- Distributed Denial-of-Service Attack (DDOS)

  - type of cyber attack in which extremely high volumes of network traffic such as packets, data, or transactions are sent to the target victim’s network to make their network and systems unavailable

### APTs and WI-FI Vulnerabilities

- a class of threats that are far more deliberate and potentially devastating than other types of cyberattacks.
- APTs are generally coordinated events that are associated with cybercriminal groups.

  - Advanced
    - Attackers use advanced malware and exploits. They typically also have the skills and resources necessary to develop additional cyberattack tools and techniques.

  - Persistent
    - An APT may take place over a period of several years. Attackers pursue specific objectives and move slowly and methodically to avoid detection.

  - Threat
    - An APT is deliberate and focused, rather than opportunistic. APTs are designed to cause real damage.

  - Example
    - Lazarus
      - Attacks against nation-states and corporations are common, and the group of cybercriminals that may have done the most damage is Lazarus. The Lazarus group is known as an APT. The Lazarus group has been known to operate under different names, including Bluenoroff and Hidden Cobra. They were initially known for launching numerous attacks against government and financial institutions in South Korea and Asia. In more recent years, the Lazarus group has been targeting banks, casinos, financial investment software developers, and crypto-currency businesses. The malware attributed to this group recently has been found in 18 countries around the world.

- Wi-Fi Challenges
  - for the average user, the unfortunate reality is that Wi-Fi connectivity is more about convenience than security

  - Public Airwaves
    - Wifi uses 2.4 and 5GHz frequency ranges

  - Wi-Fi Network
    - You should hide your SSID's

- Wireless Security
  - Wi-Fi security begins—and ends—with authentication

  - Limit Access through Auth
  - Secure Content via Encryption
  - Participate in Known or Contained Networks

- Wifi Protected Access

  - Security Protocols
    - Wi-Fi Protected Access (WPA)
      - WPA2
        - WPA2-PSK supports 256-bit keys, which require 64 hexadecimal characters.
      - WPA3
        - Its security enhancements include more robust brute force attack protection, improved hot spot and guest access security, simpler integration with devices that have limited or no user interface (such as IoT devices), and a 192-bit security suite.
        - Newer Wi-Fi routers and client devices will likely support both WPA2 and WPA3 to ensure backward compatibility in mixed environments.
    - Wired Equivalent Privacy (WEP)
      - Bad.. don't use.

- Evil Twin

  - Bad access point
  - Usually "Free Wifi"
  - Mimic a real access point

- SSLstrip

  - After a user connects to a Wi-Fi network that’s been compromised–or to an attacker’s Wi-Fi network masquerading as a legitimate network–the attacker can control the content that the victim sees.
  - The attacker simply intercepts the victim’s web traffic, redirects the victim’s browser to a web server that it controls, and serves up whatever content the attacker desires.
  - SSLstrip strips SSL encryption from a “secure” session.
  - When a user connected to a compromised Wi-Fi network attempts to initiate an SSL session, the modified access point intercepts the SSL request.
  - With SSLstrip, the modified access point displays a fake padlock in the victim’s web browser.
  - Webpages can display a small icon called a favicon next to a website address in the browser’s address bar.
  - SSLstrip replaces the favicon with a padlock that looks like SSL to an unsuspecting user.

- Wi-Fi Attacks

  - Doppelganger
    - The attacker spoofs the source MAC address of a device that is already connected to the Wi-Fi network and attempts to associate with the same wireless access point.
  - Cookie Guzzler
    - Muted Peer and Hasty Peer are variants of the cookie guzzler attack which exploit the Anti-Clogging Mechanism (ACM) of the Simultaneous Authentication of Equals (SAE) key exchange in WPA3-Personal.

### Security Models

- Issues with Perimeter based security
  - strategy relies on the assumption that everything on the internal network can be trusted
  - Remote users accessing internal resources
  - If a user bypasses perimeter security they are now free to move about

- Unwanted traffic from Legacy Firewalls
  - Application Control
    - Cannot definitively distinguish good applications from bad ones
    - Do not adequately account for encrypted application traffic
    - Do not accurately identify and control users
    - Do not filter allowed traffic for known application-borne threats or unknown threats
    - Re-architecture defenses to create pervasive internal trust boundaries is, by itself, insufficient

- Zero Trust Security Model

  - The Zero Trust security model addresses some of the limitations of perimeter-based network security strategies by removing the assumption of trust from the equation.

  - security capabilities are deployed in a way that provides policy enforcement and protection for all users, devices, applications, and data resources, as well as the communications traffic between them, regardless of location

  - No Default Trust Zone
    - No device is by default trusted

  - Monitor and Inspect
    - The need to "always verify" requires ongoing monitoring and inspection of associated communication traffic for subversive activities

  - Compartmentalize
    - Zero Trust models establish trust boundaries that effectively compartmentalize the various segments of the internal computing environment.
    - The general idea is to move security functionality closer to the pockets of resources that require protection.
    - In this way, security can always be enforced regardless of the point of origin of associated communications traffic.

  - Benefits
    - verification that authorized entities are always doing only what they’re allowed to do is not optional: It's mandatory.

  - Design Principles
    - least privilege
      - in network security requires that only the permission or access rights necessary to perform an authorized task are granted.
    - Ensure Resource Access
    - Enforce Access Control
    - Inspect and Log All Traffic

  - Architecture
    - The Zero Trust model identifies a protect surface made up of the network’s most critical and valuable data, assets, applications, and services (DAAS).
    - Protect surfaces are unique to each organization.
    - Because the protect surface contains only what’s most critical to an organization’s operations, the protect surface is orders of magnitude smaller than the attack surface–and always knowable
    - Identify the Traffic
      - team should put controls in place as close to the protect surface as possible
      - This micro-perimeter moves with the protect surface, wherever it goes

  - Zero Trust Segmentation Platform

    - Secure
      - Enables secure network access

    - Control
      - Granularly controls traffic flow to and from resources

    - Monitor
      - Continuously monitors allowed sessions for threat activity

  - Fundamental Assertions
    - The network is always assumed to be hostile.
    - External and internal threats exist on the network at all times.
    - Network locality is not sufficient for deciding trust in a network.
    - Every device, user, and network flow is authenticated and authorized.
    - Policies must be dynamic and calculated from as many sources of data as possible.

- Least Privilege
  - Have visibility of and Control Over the applications and their functionality
  - Be able to allow specific applications and block everything else
  - Dynamically define access to sensitive applications
  - Dynamically define access from devices or device groups to sensitive applications and data from users to specific devices
  - Validate a Users Identity through Authentication
  - Dynamically define the resources that are associated with the sensitive data
  - control data by file type and content
  - Segmentation Platform
  - Trust zones

- Zero Trust Capabilities
  - Criteria and Capabilities
    - Secure Access
      - Secure IPsec and SSL VPN connectivity is provided
    - Inspection of All Traffic
      - App ID identifies all traffic
    - Least Privilege
      - Granular access control that safely enables the correct applications for the correct set of users
    - Cyber threat Protection
      - comprehensive protection against both known and unknown threats
    - coverage for all security domains
      - Covering all devices in any zone

- Zero Trust Implementation
  - A Zero Trust design architecture can be implemented with only incremental modifications to the existing network
  - Configure Listen-Only Mode
  - Define Zero Trust Zones
  - Establish Zero Trust Zones
  - Implement at Major Access Points

- Security Operating Platform
  - Automation and Big Data
    - Internal employees will often expose data without knowing it
  - Decentralization of IT
    - With applications moving to the cloud, the decentralization of IT infrastructure, and the increased threat landscape, organizations have lost visibility and control
  - Traditional Security Products
    - Border protection alone is not enough
  - Complex Network
    - applications are increasingly accessible. The result is an incredibly complex network that introduces significant business risk.
    - Organizations must minimize this risk without slowing down the business.

- Prevention Architecture
  - Provide Full Visibility
  - Reduce the Attack Surface
  - Prevent all Known Threats
  - Detect and PRevent New and Unknown Threats with Automation

- Prevention-First Architecture
  - Secure the Enterprise with Strata
    - PANOS
      - Runs on the NGFW set of appliances
      - APPID
      - ContentID
      - DeviceID
      - UserID
    - Panorama
      - Central Management and logging
    - Cloud-Based Subscriptions
      - DNS Security
      - URL Filtering
      - Threat Prevention
      - WildFire
  - Secure the cloud with Prisma
    - Prisma Cloud
      - Provides all of Strata in the cloud
  - Secure the Future wit Cortex
    - Cortex XDR
      - Host Based Protections
    - Cortex XSOAR
      - security orchestration, automation, and response (SOAR)
      - Automated management and orchestration
    - Cortex Data Lake
      - Normalizing an enterprises data
      - automatically collects, integrates and normalizes data across an organizations security infrastructure
    - AutoFocus
      - Threat Intelligence service
      - Instant access to community-based threat data from WildFire
      - enhanced with deep context and attribution from the PaloAlto Networks Unit 42 threat research team

## Domain 2 - Network Security Components

### The Connected Globe

![connected](docs/topics/vendor/paloalto/certs/pccet/img/Connection.png)

- Common Network Devices
  - Routers
    - Physical or Virtual
    - Use various routing protocols to determine the best path
  - access point (AP)
    - allows endpoints to connect to the network via Wi-Fi
  - Hub
    - connections multiple devices via a wired connection
    - Traffic is forwarded out all ports
  - Switch
    - Physical connection
    - Each port is its own broadcast domain
    - Can use virtual LANs (VLANs)
      - VLANS allow you to create segmentation within a network.

- Routed and Routing Protocols
  - Routing protocols are defined at the Network layer of the OSI model and specify how routers communicate with one another on a network. 
  - Routing protocols can either be static or dynamic.

  - Static Routing
    - Routes are created manually
    - Traffic can not be automatically rerouted unless multiple static routes exist
  - Dynamic Routing
    - Can automatically learn new routes
    - Routing table is updated with new routes

- Dynamic Routing Protocol Classifications
- [Dynamic-routing](docs/topics/vendor/paloalto/certs/pccet/img/Dynamic-routing.png)
  - Distance Vector
    - Based on two factors
      - The Distance (Hop Count)
      - The Vector (The Exit router Interface)
    - Examples
      - Routing Information Protocol (RIP)
  - Link State
    - Every router calculates and maintains a complete map
    - Example
      - Open Shortest Path First (OSPF)
  - Path Vector
    - Similar to Distance Vector without the limitations
    - Each router table entry in the protocol contains path information that gets dynamically updated
    - Example
      - Border Gateway Protocol (BGP)

- Area Network Topologies
  
  - Local Area Network (LAN)
  - [LAN](docs/topics/vendor/paloalto/certs/pccet/img/Lan.png)
    - A LAN can be wired, wireless, or a combination of wired and wireless
    - Star
      - each node is directly connected to a switch
    - Mesh
      - All nodes are interconnected to provide multiple paths
  
  - Wide Area Network (WAN)
  - [LAN](docs/topics/vendor/paloalto/certs/pccet/img/Lan.png)
    - A network to connect multiple WANS
  
  - Software-Defined WAN (SD-WAN)
  - ![SDWAN](docs/topics/vendor/paloalto/certs/pccet/img/SDWAN.png)
    - Separates the control and management processes from the underlying networking hardware
    - better user experience by allowing efficient access to cloud based resources without the need to back haul traffic to centralized locations

  - Other Types of networks
    - Campus Area Networks (CANs)
    - Wireless Campus Area Networks (WCANs)
    - Metropolitan Area Networks (MANs)
    - Wireless Metropolitan Area Networks (WMANs)
    - Personal Area Networks (PANs)
    - Wireless Personal Area Networks (WPANs)
    - Value-Added Networks (VANs)
    - Wireless Local-Area Networks (WLANs)
    - Wireless Local-Area Networks (WLANs)
    - Storage Area Networks (SANs)

- Domain Name System (DNS)
  - is a protocol that translates (resolves) a user-friendly domain name to an IP address
  - A root name server is the authoritative name server for a DNS root zone.
  - Root Name Server
    - Thirteen root name servers (actually, 13 networks comprising hundreds of root name servers) are configured worldwide.
    - They are named a.root-servers.net through m.root-servers.net.
    - DNS servers are typically configured with a root hints file that contains the names and IP addresses of the root servers.

  - Record Types
    - A
      - A (IPv4) or AAAA (IPv6) address maps a domain or subdomain to an IP address or multiple IP addresses.

    - AAAA
      - A (IPv4) or AAAA (IPv6) address maps a domain or subdomain to an IP address or multiple IP addresses.

    - CNAME
      - Canonical Name (CNAME) maps a domain or subdomain to another hostname.

    - MX
      - Mail Exchanger (MX) specifies the hostname or hostnames of email servers for a domain.

    - PTR
      - Pointer (PTR) points to a CNAME and is commonly used for reverse DNS lookups that map an IP address to a host in a domain or subdomain.

    - SOA
      - Start of Authority (SOA) specifies authoritative information about a DNS zone such as primary name server, email address of the domain administrator, and domain serial number.

    - NS
      - The Name Server (NS) record specifies an authoritative name server for a given host.

    - TXT
      - Text (TXT) stores text-based information.

- Internet of Things (IoT)
  - IoT connectivity technologies are broadly categorized into five areas:
    - Cellular
    - Satellite
    - Short-Range Wireless
    - LP-WAN and WWAN
      - low-power WAN (LP-WAN) and other wireless WAN (WWAN)
    - IDoT
      - IDoT refers to identity and access management (IAM) solutions for the IoT

- Hybrid IoT Security
  - the general security posture of IoT devices is declining

- Mitigating Issues with IoT Security
  - IoT Devices Unencrypted and Unsecured
    - traffic is unencrypted
    - subject to C2 attacks
  - IoMT Devices Running Outdated Software
    - Most IoT Devices run on outdated software
  - Healthcare Orgs Practicing Poor Security Hygiene
  - IoT-Focused Cyberattacks Target Legacy Protocols

### Addressing and Encapsulation

- TCP/IP Protocol Stack
  - ![TCP/IP Stack](docs/topics/vendor/paloalto/certs/pccet/img/tcp-ip-stack.png)

- Ip Addresses
  - IPv4
    - 32 Bit Logical IP address
  - Loopback Address
    - Reserved for Troubleshooting
  - Private Addresses
    - Not routed on the internet

- Subnet Mask
  - A subnet mask is a number that hides the network portion of an IPv4 address
  - in the subnet mask 255.255.255.0, the first three octets represent the network portion and the last octet represents the host portion of an IP address

- OSI Model
  - ![Layers](docs/topics/vendor/paloalto/certs/pccet/img/Layers.png)
  - Application
  - Presentation
  - Session
  - Transport
  - Network
  - Data Link
  - Physical
- TCP/IP Protocol Layers
  - ![Layers](docs/topics/vendor/paloalto/certs/pccet/img/Layers.png)
  - Application
  - Transport
  - Internet
  - Network Access

- Data Encapsulation
- ![Diagram](docs/topics/vendor/paloalto/certs/pccet/img/Encapsulation.png)
  - wraps protocol information from the (OSI or TCP/IP) layer immediately above in the data section of the layer below.

  - Encapsulation
    - The Sending Host

  - PDU
    - The Receiving Host

### Network Security Technologies

- Packet Filtering Firewall
  - ![Firewall](docs/topics/vendor/paloalto/certs/pccet/img/Firewall.png)
  - Basic border protection that provides some security

- Stateful Packet Inspection Firewalls
  - ![Stateful Firewall](docs/topics/vendor/paloalto/certs/pccet/img/Stateful-Firewall.png)
  - Port based firewalls
  - Maintain state sessions that have been established

- Application Firewalls
  - ![Application Firewalls](docs/topics/vendor/paloalto/certs/pccet/img/Application-Firewall.png)
  - Operate Up to L7
  - Control Access to Specific Applications
  - can identify and block specified content, malware, exploits, websites, and applications or services that use hiding techniques such as encryption and non-standard ports.

- Intrusion detection systems (IDSs) and intrusion prevention systems (IPSs)
- ![IDS and IPS](docs/topics/vendor/paloalto/certs/pccet/img/IDS%20and%20IPS.png)
  - Provide Real-Time Monitoring of Network Traffic
- Classifications
  - Knowledge-Based
    - Uses a database of known vulnerabilities and attack profiles
    - Lower false-alarm rates
    - Receives new attack signatures
  - Behavior-Based
    - Baseline of normal network activity to identify unusual patterns
    - better at detecting new attacks against unknown vulnerabilities

- Web Content Filters
  - restrict the internet activity of users on a network

- Virtual Private Networks
  - ![VPN](docs/topics/vendor/paloalto/certs/pccet/img/vpn.png)
  - A Secure, Encrypted connection across the internet between two endpoints
  - Client VPN
    - End user connecting to a corporate network
  - Site-to-Site VPN
    - Two networks being connected over an encrypted tunnel

  - Layer 2 Tunneling Protocol (L2TP)
  - Secure Socket Tunneling Protocol (SSTP)
  - Microsoft Point-to-Point Encryption (MPPE)

- Internet Protocol Security (IPsec)
  - secure communications protocol that authenticates and encrypts IP packets in a communication session

- Secure Sockets Layer (SSL)
  - an asymmetric/symmetric encryption protocol that secures communication sessions

- Data Loss Prevention
  - inspect data that is leaving, or egressing, a network, such as data that is sent via email and or file transfer

- Unified Threat Management
  - combines multiple cybersecurity functions into one appliance 

### Endpoint Security and Protection

- Endpoint protection
  - ![EndPoint](docs/topics/vendor/paloalto/certs/pccet/img/endpoint.png)
- Anti-Malware
- Anti-Spyware
- Firewalls
- host-based intrusion prevention systems (HIPSs)
- mobile device management (MDM)
- Server Management

- Container-Based Endpoint Protection
  - Container-based endpoint protection wraps a protective virtual barrier around vulnerable processes while they are running.

- Application Allow Listing
  - Application allow listing is another endpoint protection technique that is commonly used to prevent end users from running unauthorized applications–including malware–on their endpoints.

- Anomaly-Based Detection
  - Anomaly-based detection refers to detecting patterns in datasets that do not conform to an established normal behavior.
  
    - Heuristic-based analysis detects anomalous packet and traffic patterns, such as port scans and host sweeps.

    - Behavior-based malware detection evaluates an object based on its intended actions before it can actually execute that behavior.

- Golden Image
  - image that ensures consistent configuration of devices across the organization

- Firewalls and HIPSs
  - Network firewalls protect an enterprise network against threats from an external network, such as the internet.
  - HIPSs are another approach to endpoint protection that rely on an agent installed on the endpoint to detect malware.

### Secure the Enterprise

- Prevention-First Architecture
  - Simplifying your security posture allows you to reduce operational costs and infrastructure while increasing your ability to prevent threats to your organization

- Next-Generation Firewall
  - ![NGFW](docs/topics/vendor/paloalto/certs/pccet/img/NGFW.png)
  - The Palo Alto Networks Next-Generation Firewall is the foundation of our product portfolio.
  - The firewall is available in physical, virtual, and cloud-delivered deployment options, and it provides consistent protection wherever your data and apps reside.
  - Organizations deploy next-generation firewalls at the network perimeter and inside the network at logical trust boundaries.
  - All traffic crossing the firewall undergoes a full-stack, single-pass inspection, which provides the complete context of the application, associated content, and user identity.
    - ![Single-Pass Architecture](docs/topics/vendor/paloalto/certs/pccet/img/Single-Pass-arch.png)
  - The next-generation firewall functions as a segmentation gateway in a Zero Trust architecture.

- Subscription Service
  - ![Subscriptions](docs/topics/vendor/paloalto/certs/pccet/img/Subscriptions.png)
  - Subscription services add enhanced threat services and next-generation firewall capabilities, including 
    - DNS Security
    - URL Filtering
    - Threat Prevention
    - WildFire malware prevention

- Panorama
  - ![Panorama](docs/topics/vendor/paloalto/certs/pccet/img/Panorama.png)
  - Panorama provides centralized network security management.
  - It simplifies administration while delivering comprehensive controls and deep visibility into network-wide traffic and security threats
  - Deployment modes
    - Panorama mode
      - ![Panorama Mode](docs/topics/vendor/paloalto/certs/pccet/img/Panorama-mode.png)
    - Management Only and Log collector Mode
      - ![Panorama MGMT Mode](docs/topics/vendor/paloalto/certs/pccet/img/Panorama-mgmt-mode.png)

- Templates and Template Stacks
  - ![Template-Stack](docs/topics/vendor/paloalto/certs/pccet/img/Template-Stack.png)
  - Controls the Network and Device Tabs within a firewall
  - Allows you to layer configurations across multiple devices

- Device Groups
  - ![Device Groups](docs/topics/vendor/paloalto/certs/pccet/img/Device-Groups.png)
  - 

- App-ID
  - accurately identifies applications regardless of port, protocol, evasive techniques, or encryption. It provides application visibility and granular, policy-based control

- User-ID
  - ![USER-ID](docs/topics/vendor/paloalto/certs/pccet/img/User-ID.png)
  - accurately identifies users for policy control
  - Visibility into the application activity at a user level, not just at an IP address level, allows you to more effectively enable the applications traversing the network

- Content-ID
  - Content identification controls traffic based on complete analysis of all allowed traffic

- NGFW Deployments
  - Physical Appliances Firewalls (PA-Series)
    - (These are probably outdated)
    - ![Physical Firewalls](docs/topics/vendor/paloalto/certs/pccet/img/physical-firewalls.png)

  - Virtual Firewalls
    - VM-Series virtual firewalls provide all the capabilities of Palo Alto Networks next-generation physical hardware firewalls (PA-Series) in a virtual machine form factor

  - CN-Series Container Firewall
    - cloud-native environments pose unique challenges that next-generation firewalls were not designed to handle, especially when it comes to looking inside a Kubernetes environment.

  - K2-Series Firewalls
    - ![K2-Series](docs/topics/vendor/paloalto/certs/pccet/img/k2-series.png)
    - The K2-Series firewalls are 5G-ready next-generation firewalls designed to prevent successful cyberattacks from targeting mobile network services.

- IronSkillet
  
  - set of day-one, next-generation firewall configuration templates for PAN-OS that are based on security best practice recommendations

- Expedition Migration Tool
  
  - enables organizations to analyze their existing environment, convert existing security policies to Palo Alto Networks next-generation firewalls, and assist with the transition from proof of concept to production

- Best Practice Assessment (BPA)
  
  - a free tool used to quickly identify the most critical security controls for an organization to focus on.

- Subscription Services
  
  - IoT Security Services
  
  - SD-WAN Service
  
  - DNS Security Service
  
  - URL Filtering Service
  
  - Advanced URL Filtering Service
    - Advanced URL Filtering uses a cloud-based ML-powered web security engine to perform ML-based inspection of web traffic in real-time
  
  - Threat Prevention Service
  
  - Advanced Threat Prevention Service
    - In addition to all of the features included with Threat Prevention, the Advanced Threat Prevention subscription provides an inline cloud-based threat detection and prevention engine, leveraging deep learning models trained on high fidelity threat intelligence gathered by Palo Alto Networks, to defend your network from evasive and unknown command-and-control (C2) threats by inspecting all network traffic.
  
  - WildFire Overview
    - ![WildFire](docs/topics/vendor/paloalto/certs/pccet/img/Wildfire.png)
    - The WildFire cloud-based malware analysis environment is a cyberthreat prevention service that identifies unknown malware, zero-day exploits, and advanced persistent threats (APTs) through static and dynamic analysis in a scalable, virtual environment. 
  
  - WildFire Verdicts
    - ![verdicts](docs/topics/vendor/paloalto/certs/pccet/img/Wildfire-verdicts.png)

    - Benign
      - Safe

    - Grayware
      - No Security risk but might display obtrusive behavior

    - Malware
      - Malicious

    - Phishing
      - Malicious attempt to trick the recipient

  - Wildfire Analysis
    - If the firewall does not have a previous verdict for a file, it will be submitted for analysis

  - AutoFocus
    - Provides a graphical analysis of firewall traffic logs and identifies potential risks to your network using threat intelligence from the AutoFocus portal.
    - With an active license, you can also open an AutoFocus search based on logs recorded on the firewall.

  - Cortex Data Lake
    - Provides cloud-based, centralized log storage and aggregation.
    - The Cortex Data Lake is required or highly-recommended to support several other cloud-delivered services, including Cortex XDR, IoT Security, and Prisma Access, and Traps management service.

  - GlobalProtect Gateway
    - Provides mobility solutions and/or large-scale VPN capabilities

  - Virtual Systems
    - Each hardware platform has a limit of free virtual systems

  - Enterprise Data Loss Prevention (DLP)
    - Provides cloud-based protection against unauthorized access, misuse, extraction, and sharing of sensitive information

  - SaaS Security Inline
    - The SaaS Security solution works with Cortex Data Lake to discover all of the SaaS applications in use on your network
    - SaaS Security Inline can discover thousands of Shadow IT applications and their users and usage details
    - SaaS Security Inline also enforces SaaS policy rule recommendations seamlessly across your existing Palo Alto Networks firewalls
    - App-ID Cloud Engine (ACE) also requires SaaS Security Inline

## Domain 3 - Cloud Technologies

### Cloud Computing

- Cloud Computing Service Models
- NIST defines three distinct cloud computing service models:
- ![NIST 3 Models](docs/topics/vendor/paloalto/certs/pccet/img/NIST-3-Models.png)
  - Software as a Service (SaaS)
    - Customers are provided access to an application, such as Google Docs, running on a cloud infrastructure and the application is accessible from internet-connected client devices.
    - The customer does not manage the application or underlying cloud infrastructure that delivers the application.
    - The customer can only create and store user specific data using the provided SaaS application.
  - Platform as a Service (PaaS)
    - Using PaaS, customers can deploy supported applications onto the Cloud Service provider’s (CSP) infrastructure without the burden of fully managing and controlling the underlying cloud infrastructure.
  - Infrastructure as a Service (IaaS)
    - Using IaaS, customers securely configure, manage, and deploy the virtual environment running their applications

- Cloud Computing Deployment Models
  - Public Cloud
    - Public cloud is a cloud infrastructure that is open to use by the general public.
  - Community Cloud
    - Community cloud is a cloud infrastructure that is used exclusively by a specific group of organizations.
  - Private Cloud
    - Private cloud is a cloud infrastructure that is used exclusively by a single organization.
  - Hybrid
    - Hybrid cloud is a cloud infrastructure that comprises two or more of these deployment models and is, therefore, the best of both worlds: private data center for static, older workloads and public cloud for newer apps, agility, and scalability.

- Shared Responsibility model
  - IaaS
    - The IaaS model is the responsibility of the cloud provider
  - PaaS
    - A cloud customer deploying a platform-as-a-service (PaaS) model is responsible for the security of the applications and data, and the cloud provider is responsible for the security of the operating systems, middleware, and runtime.
  - SaaS
    - A cloud customer deploying a software-as-a-service (SaaS) model is responsible only for the security of the data, and the cloud provider is responsible for the full stack from the physical security of the cloud data centers to the application.

- Network Security vs. Cloud Security
  - Network security
    - Isolation and Segmentation
    - Process-Oriented
    - Incompatible with Serverless applications
  - Cloud Security
    - Shared Resources
    - Dynamic Computing
    - Multi-Tenancy is Important

- Securing the Cloud
  - As organization's transition from a traditional data center architecture to a public, private, or hybrid cloud environment, enterprise security strategies must be adapted to support changing requirements in the cloud.
  - Consistent Security
  - Zero Trust Principles
  - Centralized Management

### Cloud Native Technologies

- Cloud Native Technology Properties
  - Container Packaged
    - Running applications and processes in software containers as isolated units of application deployment, and as mechanisms to achieve high levels of resource isolation
  - Dynamically Managed
    - Actively scheduled and actively managed by a central orchestrating process.
  - Microservices
    - Loosely coupled with dependencies explicitly described

- Virtualization
  - Virtualization is the foundation of cloud computing. You can use virtualization to create multiple virtual machines to run on one physical host computer.

  - Hypervisors
    - Type 1
      - software installs directly on hardware computer hosts, which are referred to as bare metal machines.
    - Type 2
      - software runs within the operating system installed on a bare metal host. Open source Linux KVM is an example of a type 2 hypervisor.

- Container Orchestration
  - Kubernetes is an open-source orchestration platform that provides an application programming interface (AP) that enables developers to define container infrastructure in a declarative fashion, that is, infrastructure as code (IaC).
  - ![K8s-01](docs/topics/vendor/paloalto/certs/pccet/img/k8s-01.png)

- Containers-as-a-service (CaaS)
  - platforms manage the underlying compute, storage, and network hardware by default and, although assembled from many more generic components, are highly optimized for container workloads.

- Micro-VMs
  - For some organizations, especially large enterprises, containers provide an attractive app deployment and operational approach but lack sufficient isolation to mix workloads of varying sensitivity levels
  - Regardless of recently discovered hardware flaws such as Meltdown and Spectre, VMs provide a much stronger degree of isolation but at the cost of increased complexity and management burden
  - Micro-VMs such as Kata containers, VMware vSphere Integrated Containers, and Amazon Firecracker seek to accomplish this by providing a blend of a developer-friendly API and abstraction of app from the OS while hiding the underlying complexities of compatibility and security isolation within the hypervisor.

- Serverless Computing and Function as a Service
  - Serverless architectures, also referred to as function as a service (FaaS), enable organizations to build and deploy software and services without maintaining or provisioning any physical or virtual servers
  - Applications made using serverless architectures are suitable for a wide range of services and can scale elastically as cloud workloads grow.

- Common Scanning Tools
  - Dynamic Application Security Testing (DAST)
  - Static Application Security Testing (SAST)
  - Interactive Application Security Testing (IAST)

### Cloud Native Security

- The Four Cs of Cloud Native Security
  - Cloud
    - The cloud (and data centers) provide the trusted computing base for a Kubernetes cluster.
  - Clusters
    - Securing Kubernetes clusters requires securing both the configurable cluster components and the applications that run in the cluster.
  - Containers
    - Securing the container layer includes container vulnerability scanning and OS dependency scanning, container image signing and enforcement, and implementing least privilege access.
  - Code
    - The application code itself must be secured.

- Prioritizing Software Security in the Cloud
  - The customer is ultimately responsible for providing security for the data, hosts, containers, and serverless instances in the cloud.

- DevOps Software Development Model
  - DevOps unites the development and operations teams throughout the entire software delivery process, enabling them to discover and remediate issues earlier, automate testing and deployment, and reduce time to market. 

- DevOps CI/CD Pipeline
  - DevOps is a cycle of continuous integration and continuous delivery (or continuous deployment), otherwise known as the CI/CD pipeline

- DevSecOps Software Development Model
- ![Dev-Sec-Ops](docs/topics/vendor/paloalto/certs/pccet/img/devsecops.png)
  - One problem in DevOps is that security often ends up falling through the cracks because developers move quickly and their workflows are automated
  - To mitigate this problem, security should be shifted into code development before code deployment.

### Hybrid Data Center Security

- The Hybrid Cloud
  - Many organizations are using public cloud compute resources to expand private cloud capacity rather than expand compute capacity in an on-premises private cloud data center.

  - Traditional Data Center vs. Hybrid Cloud
    - ![Traditional DC](docs/topics/vendor/paloalto/certs/pccet/img/traditional-DC.png)
      - Limited Visibility
      - No concept of Unknown Traffic
      - No policy Reconciliation Tools
      - Cumbersome Security Policy Update Process
    - ![Hybrid Cloud](docs/topics/vendor/paloalto/certs/pccet/img/Hybrid-Cloud.png)
      - Optimizes Resources
      - Reduces Costs
      - Increases Operational Flexibility
      - Maximizes Efficiency

- Private Cloud Traffic Types and Compute Clusters
  - Virtual Data Center Design
  - ![Virtual-DC](docs/topics/vendor/paloalto/certs/pccet/img/virtual-dc.png)
    - In a virtual data center (private cloud), there are two different types of traffic, each of which is secured in a different manner: north-south and east-west.

### Prisma Access SASE Security

- What Is SASE Security
  - designed to help organizations embrace cloud and mobility by providing network and network security services from a common cloud-delivered architecture

- Cloud Native Security Platform (CNSP)
  - The cloud native approach takes the best of what cloud has to offer – scalability, deployability, manageability, and limitless on-demand compute power – and applies these principles to software development, combined with CI/CD automation, to radically increase productivity, business agility, and cost savings.

- Continuous Integration/Continuous Delivery (CI/CD)
  - CI/CD is a new approach that offers a multitude of benefits, such as shorter time to market and more efficient software delivery.  

- Cloud Native Architectures
  - 

### Prisma SaaS

### Prisma Cloud Security

## Domain 4 - Elements of Security Operations

- Task 4.1 Describe the main elements included in the development of SOC
- business objectives
- Task 4.2 Describe the components of SOC business management and
- operations
- Task 4.3 List the six essential elements of effective security operations
- Task 4.4 Describe the four SecOps functions
  - 4.4.1 Identify
  - 4.4.2 Investigate
  - 4.4.3 Mitigate
  - 4.4.4 Improve
- Task 4.5 Describe SIEM
- Task 4.6 Describe the purpose of security orchestration, automation, and
- response (SOAR)
- Task 4.7 Describe the analysis tools used to detect evidence of a security
- compromise
- Task 4.8 Describe how to collect security data for analysis
- Task 4.9 Describe the use of analysis tools within a security operations
- environment
- Task 4.10 Describe the responsibilities of a security operations engineering
- team
- Task 4.11 Describe the Cortex platform in a security operations
- environment and the purpose of Cortex XDR for various
- endpoints
- Task 4.12 Describe how Cortex XSOAR improves security operations
- efficiency
- Task 4.13 Describe how Cortex Data Lake improves security operations
- visibility
- Task 4.14 Describe how XSIAM can be used to accelerate SOC threat
- response

## Common Terms

- software-as-a-service (SaaS)
- Containers-as-a-service (CaaS)
- function as a service (FaaS)
- International Information System Security Certification Consortium (ISC)
- managed security service providers (MSSPs)
- security operations centers (SOCs)
- security information and event management (SIEM)
- Work-from-Home (WFH)
- Work-from-Anywhere (WFA)
- tactics, techniques, and procedures (TTPs)
- The Payment Card Industry's Data Security Standard (PCI DSS)
- The European Union (EU) General Data Protection Regulations (GDPR)
- The MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK)
- advanced persistent threats (APTs)
- command-and-control (C2)
- remote access Trojans (RATs)
- Business Email Compromise (BEC)
- FBI Internet Crime Complaint Center (IC3)
- Data Breach Investigations Report (DBIR)
- Distributed Denial-of-Service Attack (DDOS)
- Service Set Identifier Broadcast (SSID)
- Wi-Fi Protected Access (WPA)
- Wired Equivalent Privacy (WEP)
- Anti-Clogging Mechanism (ACM)
- Simultaneous Authentication of Equals (SAE)
- remote job entry (RJE)
- data, assets, applications, and services (DAAS)
- security orchestration, automation, and response (SOAR)
- Transmission Control Protocol/Internet Protocol (TCP/IP)
- Domain Name System (DNS)
- U.S. Defense Advanced Research Projects Agency (DARPA)
- local area networks (LAN)
- wide area network (WAN)
- access point (AP)
- virtual LANs (VLANs)
- software-defined WAN (SD-WAN)
- Campus Area Networks (CANs)
- Wireless Campus Area Networks (WCANs)
- Metropolitan Area Networks (MANs)
- Wireless Metropolitan Area Networks (WMANs)
- Personal Area Networks (PANs)
- Wireless Personal Area Networks (WPANs)
- Value-Added Networks (VANs)
- Wireless Local-Area Networks (WLANs)
- Wireless Local-Area Networks (WLANs)
- Storage Area Networks (SANs)
- Internet of Things (IoT)
- low-power WAN (LP-WAN)
- wireless WAN (WWAN)
- Intrusion detection systems (IDSs)
- intrusion prevention systems (IPSs)
- Layer 2 Tunneling Protocol (L2TP)
- Secure Socket Tunneling Protocol (SSTP)
- Microsoft Point-to-Point Encryption (MPPE)
- Generic Routing Encapsulation (GRE)
- Password Authentication Protocol (PAP)
- Challenge-Handshake Authentication Protocol (CHAP)
- Microsoft CHAP versions 1 and 2 (MS-CHAP v1/v2)
- Internet Protocol Security (IPsec)
- Secure Sockets Layer (SSL)
- data loss prevention (DLP)
- host-based intrusion prevention systems (HIPSs)
- mobile device management (MDM)
- machine-to-machine (M2M)
- multi-access edge computing (MEC)
- Best Practice Assessment (BPA)
- The Cloud Native Computing Foundation’s (CNCF)
- continuous integration and continuous delivery (CI/CD)
- Secure Access Service Edge (SASE)
- Cloud Native Security Platform (CNSP)
