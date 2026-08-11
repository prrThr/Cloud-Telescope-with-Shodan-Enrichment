Received 15 February 2025, accepted 4 March 2025, date of publication 10 March 2025, date of current version 19 March 2025.

Digital Object Identifier 10.1109/ACCESS.2025.3549623

## Cloud Telescope: An Ephemeral, Distributed, and Cloud-Native Architecture for Collecting Internet Background Radiation

FABRICIO BORTOLUZZI 1,2, BARRY IRWIN 1,3, AND CARLA MERKLE WESTPHALL 2

Corresponding author: Carla Merkle Westphall (carla.merkle.westphall@ufsc.br)

The Article Processing Charge of this research publication was funded by the Brazilian Federal Agency for Support and Evaluation of Graduate Education—CAPES, under Grant 00x0ma614.

ABSTRACT For two decades, cyber security researchers have been looking to answer one major question: what threats affect the Internet at large? In addition, what malicious traffic patterns would emerge if we could sample the unsolicited traffic - termed Internet Background Radiation (IBR) - arriving at devices directly connected to the Internet? The standard approach to collecting malicious traffic is the Network Telescope: a computer device assigned with a public IP address range, configured to passively listen to incoming packets. The deployment of Network Telescopes has helped to detect and quantify major cyberspace outbreaks, from the rise of the Conficker malware, to uncovering massive botnet propagation activity, such as performed by Mirai and its variants, against the Internet-of-Things. This paper introduces the Cloud Telescope: an ephemeral, cloud-native architecture, described as Infrastructure-as-Code, enabling for geographically distributed capture of the IBR, along with a discussion of a 5-month-long validation experiment, in which a sensor fleet comprising 130 cloud instances was launched across twenty-six regions of the world. The result is a quantitative and qualitative analysis of 530 million captured packets. This includes traffic breakdown by protocol: TCP (80%), UDP (3%), ICMP (17%), and by source country. We also discuss traffic aggregation by destination country and by affected cloud region, enabling novel forms of geopolitical influence analysis.

INDEX TERMS Cloud telescope, cloud computing, network telescopes, cyber threat intelligence, internet background noise, internet background radiation, darknet traffic analysis.

## I. INTRODUCTION

In the last twenty years, a reasonably small yet persistent group of cyber security researchers has been looking for answers to one broad question: What threats affect the Internet at large? What could be learned if we sampled Internet traffic at a point in time? How could this knowledge contribute to a safer cyberspace?

One term used to describe the unsolicited portion of traffic targeting hosts directly connected to the Internet is Internet Background Radiation (IBR) [1]. The term is an

The associate editor coordinating the review of this manuscript and approving it for publication was Chi-Tsun Cheng .

analogy, or a reference to Cosmic Background Radiation, an electromagnetic radiation that fills the space, including the Cosmic Microwave Background. The IBR is incessant, even though low-traffic. It arrives at any computer, host or device for which a public, Internet-facing IP address has been assigned [2], [3], [4], [5]. Unused, unproductive, and previously unassigned public address ranges are also affected [6].

The analysis of IBR has helped both the academic community and commercial venturers to detect, quantify and qualify malicious traffic linked to important threats affecting the Internet globally. Each incoming packet can be considered either benign or potentially malicious, depending on the


reasons motivating its generation. An observed network packet is considered as benign if it falls under one of the following conditions:

- Misconfiguration. This refers to misconfigured sys- tems and network services that attempt to initiate connection to non-existent hosts. It also refers to faulty hardware and software that sends packets to arbitrary destinations or to bad Network Address Translation (NAT) implementations incorrectly mapping RFC 3330 [7] addresses into public ones [8].

- Census platforms. A number of packets seen in radiation samples can be clearly linked to platforms aiming at conducting continuous Internet census assess- ments. They map the amount of computers currently connected to the public Internet. These platforms usually perform host and port scanning to determine the host’s architecture, operating system, uptime, open service ports, and relevant metadata, including source country, domain name, and autonomous system number, among others. Shodan and Censys are two popular examples of platforms profiting from this type of activity [9].

The benign nature is determined when packet inspection is unable to detect malicious intent, even if attackers will make use of census as part of their Open Source Intelligence acquisition strategy. Otherwise, it is assumed that themajority of IBR traffic is inherently of a malicious nature [10], in which case it is categorised as follows:

- Host and port scanning. One of the most preva- lent activities refers to a range of automated tools and techniques employed by attackers to enumerate live hosts potentially exploitable due to known or recently disclosed vulnerabilities [11]. The analy- sis of scanning-related background radiation enables researchers to learn about enumeration patterns, ulti- mately contributing to the development ofmore effective firewall rules and intrusion detection signatures to quickly suppress emerging threats;

- Backscatter. This is the traffic resulting as the moni- tored address space being used for spoofing elsewhere, most often as decoy scans, as denial-of-service attacks, or as a result of misconfiguration. Backscatter primarily comprises certain ICMP types, RST-enabled TCP data- grams, or other forms ofoddly set TCP flag combination [2], [12];

- Malware propagation. A worm is a particular type of malware capable of propagating itself and infecting new hosts without human intervention. The self-propagating nature of this attack class results in considerable amounts of radiation attributed to malware. Throughout the years, IBR analysis has helped to reveal propagation patterns attributed to CodeRed, Blaster, Sasser, SQL Slammer, Conficker, and many others [4]; and

- Botnet spreading. Botnets ultimately aim at causing large-scale denial-of-service attacks for various reasons, ranging from simple hacktivism to business profit.

It may carry geopolitical and nation-state interests. The building of a botnet fleet requires the infection of as many hosts as possible, turning them into zombies, which will, in turn, accept attack orchestration commands. Botnet infection attempts generate a consid- erable amount of vestiges in the background radiation and configure a major reason for conducting new IBR analyses. The most prevalent botnet is currently the Mirai family, including variants Moobot, Sora, and Mozi [13].

A sample of the Internet Background Radiation, as cap- tured by the Cloud Telescope in cloud region sa-east-1, Sao Paulo, Brazil, is depicted in Figure 1.

*FIGURE 1. Sample of internet background radiation.*

The figure highlights four interesting event sets as decoded and displayed by Wireshark: Packets in 1 belong to probing activity generated by well-known benign Internet scanners: Censys, BufferOverRun, and the Recyber Project. Intelligence about the origin is gathered by a simple reverse DNS query using the captured public IP source address as the argument. Arrows in 2 point to packets originated in systems within Google Cloud Platform, apparently conducting a distributed-source scan against the cloud telescope sensor node, targeting non-linear enumeration of potentially open TCP ports. The enabled SYN flag indicates the use of the common SYN-scan technique. Activity in 3 reveals contin- uous Network Time Protocol (NTP) exploitation attempts against one of its implementations, allowing the attacker to achieve an amplification factor of 100x or more. The amplification factor is the metric used to represent the ratio of the server-generated response size in contrast to the number of bytes spent by the attacker to generate the request, as documented since CVE-2013-5211 [14]. Lastly, 4 reveals the arrival ofRST-flagged TCP datagrams, evidencing typical forged-source backscatter activity.

## A. NETWORK TELESCOPE

The standard mechanism for Internet Background Radiation collection is the Network Telescope. The Network Telescope


is a combination of hardware and software put together to passively receive and record network packets routed to it [1], [2], [15], [16]. The appliance is strategically inserted onto a network topology to collect unsolicited traffic, as illustrated in Figure 2.

*FIGURE 2. Network telescope topology.*

The figure shows the Network Telescope as a standard computer server or workstation to which a range of public IP addresses were assigned. Productive traffic is routed through the firewall towards the Local Area Network. Only the idle portion of the IP address range is actually forwarded to the Network Telescope, which records arriving packets in the PCAP file format, on secondary storage, for later analysis.

Ordinary computer hardware can be used for the deploy- ment of a Network Telescope. The requirement is that the system should be powerful enough to avoid packet drop events: a situation that results from the inability to capture a packet due to a busy system, or due to insufficient memory buffer to handle incoming traffic by the network stack. The literature evidences the use of the following software components [17]:

- A Unix-like operating system, commonly FreeBSD or Linux;

- Libpcap-based tcpdump utility, running in promiscuous mode, as a daemon, enabled to record incoming traffic into the PCAP file format;

- Storage facility comprised of a combination of large internal drive units, and external network-attached mount points; and

- Secondary systems used to process the PCAP-formatted recordings, which can include the common Unix toolset, including Bash scripts, TShark, CSV (Comma Separated Values) manipulation tools, and Perl or Python-based transformation pipelines for all sorts of data enrichment procedures.

A Network Telescope is essentially passive. However, it can be tailored to certain interaction levels to enable deeper cyber threat intelligence acquisition, better fitting the behaviour of a Honeypot system. This will affect the Network Telescope’s noise - the traffic that will be detected by radiation sources, potentially revealing its existence - and will impact CPU and storage needs. Honeypots can be considered as active-response counterparts to Network Telescopes. Network Telescopes and Honeypots have many

characteristics in common, but they vary in the level of interaction implemented, as discussed by [10].

- Passive. The standard operational mode for a Network Telescope. All incoming traffic is recorded and none is answered. This is undetectable and requires the least amount of processing power and storage;

- Low interaction. This is deployed with a configuration that will answer the TCP three-way handshake to evaluate how the radiation source behaves right after that event. Once the first payload packet arrives, the established connection is simply dropped by the telescope;

- Medium interaction. These implement the standard behaviour of a honeypot. Portions of selected applica- tion layer protocols are implemented, such as HTTP’s GET method, or FTP’s list command, to learn what exploiting actions attackers would take upon successful connection to the target; and

- Full interaction. This variant contains a virtualised implementation of intentionally vulnerable services, allowing the observer to record the infection commands taking place beyond transport-layer handshake, i.e. during protocol message exchange and data/payload transfer.

Regarding the infrastructure that is required to operate the Network Telescope, key aspects described in the litera- ture [18] include:

- Aperture size. The telescope must be allocated with a public IP address block. The address range can vary from small subnets within a single /24 CIDR block, referred to as a Small Aperture Telescope, to one or more /8 (≈ 16 million) address assignments, such as the one operated by CAIDA, in which case, it is called a Large Aperture Telescope;

- Address continuity. Any combination of multiple IP addresses will work as a source to collect radiation. For example, a full /24 address block containing 256 addresses, as well as the use ofmultiple /28 subnets within one or more IP ranges. These decisions might, however, affect specific continuity analyses, but are otherwise equivalent in terms of statistical significance;

- Storage. The amount of storage required by medium to full interaction honeypots is many times greater than the less interactive approaches. Post-processing tasks also demand more CPU power and will take much longer to complete; and

- Capture duration. Related works report a capture length ranging from a few weeks up to a time frame of five years. Capture length is impacted by costs related to running the research-oriented infrastructure and the use of scarce IPv4 addresses for non-productive, non- business-oriented purposes. Duration also impacts the Network Telescope in terms of storage needs, and more importantly, in terms of computing power needed to transform, enrich and load events onto an analytics


platform from which meaningful information can be ultimately revealed.

## B. NETWORK TELESCOPE LIMITATIONS

The Network Telescope is the de facto mechanism to collect Internet Background Radiation. The rise of both the phenomenon, (the radiation), and the instrument, (the network telescope), are linked together.

Any conceivable method intended to observe cybernetic activity affecting the Internet at large will necessarily incur some form of limitation, essentially because it is not possible to observe all existing IP addresses at all times. In principle, it is only possible to observe idle addresses, i.e., which are not currently being put to productive use. In practice, researchers can only observe a very small, ever-decreasing idle fraction of the addressable IP space [18], [19].

Inherent limitations of a Network Telescope must consider the following key points for a discussion:

- 1) Limited IP address coverage;

- 2) Homogeneous IP address distribution;

- 3) Static monitoring locations; and

- 4) Biased geopolitical influence.

Primary IPv4 allocation is generally no longer available because the address field of the protocol header only accommodates 32 bits [20]. This leads to roughly 4 billion addresses, significantly fewer than required to uniquely address the 5.4 billion Internet users and 30 to 50 billion devices making up the Internet-of-Things [21]. Throughout the years, address exhaustion has been tackled in two ways: IPv6 and NAT. IPv6 extends the routeable address space by orders of magnitude. While it represents the ultimate natural solution for the problem, IPv6 adoption is comparably small and frequently problematic [22]. Despite community attempts to promote its usage, it demands complex transition mechanisms to ensure compatibility. Alternatively, technical manoeuvres such as Network Address Translators (NAT) and Carrier-Grade NAT have been successfully implemented to cope with exhaustion.

The only way to deploy a newNetwork Telescope currently is through the acquisition of an after market subnet range, which is either expensive, unachievable, or only feasible for researchers linked to a few institutions willing to share their idle address space for such luxurious, or even questionable use.

Network Telescopes are constrained, bound, and tied to a statically allocated, limited range of IP addresses. Consider the moment a hacker writes their first port scanner aiming at determining how many hosts have an open Remote Desktop Protocol port at 3389 TCP. They are likely to implement the scanner in a sequential fashion, i.e. after probing 203.0.113.20, the next obvious address is 203.0.113.21. Nmap operates the same way as a default, as in nmap -sS -p 3389 203.0.113.0-255 , which would sequen- tially scan the whole /24 segment. In case the Network Telescope is configured to listen to the full 203.0.113.0/24

subnet, it would capture the scan attempt completely and sequentially. However, what does that tell about all other port scans taking place beyond the captured block? In this case, the non-contiguous allocation could provide better statistical significance. Non-continuity remains bound to the geographic region, country and continent, and could be biased.

To summarise, the combination of IPv4 address scarcity, ever-shrinking address availability, pressure to put remainder IP addresses to productive use, and the fact idle, observable IPv4 address blocks are only available to few researchers within few institutions worldwide, configure the essential motivation to look at novel, distributed ways of collecting Internet Background Radiation.

## C. CLOUD COMPUTING

Cloud computing has become a highly viable service model for convenient, on-demand access to compute, storage and network resources globally. The remarkable characteristics of cloud-based systems deployment include [23], [24]:

- On-demand self-service. The cloud provider should contain enough resources to provide consumers with the perception that they have access to infinite computing power. This includes the need to possess more IPv4 addresses than currently allocated to the clients in each of the Cloud Service Provider (CSP) regions;

- Broad network access. The Internet stands as the common channel to both service configuration and service access, regardless ofhowpowerful the client side is, ranging from mobile phones to fully-fledged work stations;

- Resource polling. The CSP reuses computing, storage and network power to serve multiple consumers using a multi-tenant model. Resources are dynamically assigned and reassigned according to consumer demand. Clients are not fully aware ofthe exact place location where their systems are actually deployed;

- Rapid elasticity. Cloud-based systems are elastic in the sense they can scale in and out in terms of computer configuration, computer fleet size, storage space and networking capabilities; and

- Measured service. Cloud users are billed for the exact amount of services actually consumed, and system monitoring and reporting are available to both the provider and the consumer for the sake of transparency.

Clients expect the CSP to provide them with the physical infrastructure required to deploy Internet-wide information systems and applications. The amount of involvement expected from the cloud provider dictates the service model that should be adopted:

- Software-as-a-Service. Ready-to-use systems, for which the CSP transparently provides all the required infrastructure in exchange for a periodic service bill;

- Platform-as-a-Service. The CSP provides the con- sumer with all the hardware-based stack and some


of the software-based stack, commonly including the operating system, the database of choice and the programming libraries required to build an application; and

- Infrastructure-as-a-Service. This service model gives access to the configuration of the most fundamental aspects of computing resources. The consumer can fully manage computing power, storage needs and network functions, including the Virtual Private Cloud (VPC) design: IP addressing, DHCP setup, and NAT-based, or fully routed public exposure, with public IP addresses fetched from a common address pool.

The Cloud Computing model’s characteristics suggest it could be a viable foundation for developing a distributed architecture to collect Internet Background Radiation data. The most notable aspects ofCloud Computing linking to such possibility encompasses the following key properties:

- Distributed by design;

- Geographical capillarity;

- Ephemerity; and

- Idle capacity.

Service provision within CSPs is distributed by design. Computing power is provided in the form of virtualised compute instances, for which CPU models are divided into generation and class. Object-based storage is available through programmable repositories, such as the bucket. Network resources are distributed. For each cloud region, there is a Virtual Private Cloud enabled with cloud-based counterparts to routers, firewall state-tables, internet gate- ways, and one or more elastic, public IPv4 addresses that can be temporarily or permanently attached to the virtualised compute instance.

Cloud Service Providers operate in many regions world- wide. They offer unmatched capillarity when compared to on-premises deployments. For the experiment reported here, Amazon Web Services (AWS) enabled twenty-six cloud regions in the following Countries: The United States of America, Canada, Germany, Ireland, England, France, Sweden, Italy, Switzerland, Spain, China, Japan, India, Indonesia, Singapore, Bahrain, UAE, Israel, South Africa, Brazil, Australia and New Zealand.

The deployment of cloud-based systems is programmat- ically achievable via modern, service-oriented, declarative languages, termed Infrastructure-as-Code (IaC). CloudFor- mation and Terraform are notable examples and the most frequently used. IaC enables programmers to orchestrate the end-to-end life-cycle of cloud-based distributed systems in a programmatic, reliable fashion. These deployments are ephemeral. They are launched upon request and will endure for as long as the cloud architect wants, or for as long as there is a budget to keep the systems running. From a research perspective, IaC architectures are reproducible in the sense other researchers can relaunch the same architecture and compare or validate their method and results.

Because CSPs must comply with ‘‘on-demand self- service’’, they must hold more resources than the current sum of their consumers’ demands. This leads to a business phenomenon of auctioning the idle capacity. Cloud providers offer their idle capacity, especially in terms of computing power, at heavily discounted prices, of up to 90%, as long as the consumer accepts to enter a bidding scheme - whoever pays the most - to temporarily consume these otherwise more expensive resources. In order to benefit from the scheme, the cloud architect must accept the sudden termination of the allocated systems in a very short time frame, i.e., two minutes, and prepare to bid slightly higher to restore the desired computing capacity.

## D. SUMMARYOF CONCERNS

This work addresses three primary arguments concerning the reliance on Network Telescopes as the only method for acquiring Internet Background Radiation.

- 1) IPv4 address availability is scarce. There are very limited IPv4 address blocks allocable for IBR capture and analysis. Not only are the addresses scarce, but they are constrained to very few researchers within limited research institutions assigning IP addresses to radiation collection and analysis;

- 2) The Network Telescope is inherently bound to a specific geographical location. Even when assigned with frac- tions of multiple IP subnets. It is bound to the Country or IANA (Internet Assigned Numbers Authority) region it belongs to. This impacts, to a debatable extent, the diversity of cyber threat intelligence that can be acquired; and

- 3) There is little to learn about the geopolitical influence of malicious Internet traffic by investigating country- bound radiation. There is research to support the fact it is only a matter of time until the Network Telescope will be the target for an Internet-wide malicious threat, such as in [18]. However, until today, there is no clear way to establish a cause-and-effect relationship between nation-state-sponsored campaigns and how this affects the targeted countries, as there is no effective distributed method to capture the radiation they emit to provide the grounds for analysis.

The research documented in this paper provides two main contributions: a) a detailed description of the Cloud Telescope, which uses the global infrastructure within Cloud Service Providers, such as Amazon Web Services, to enable distributed capture of Internet Background Radiation, both in the form of a functioning cloud architecture, described as Infrastructure-as-Code, and b) the results of a five- month-long observation of Internet Background Radiation to validate the method.

The remainder of this text is organised as follows. Section II provides a reasonably extensive compilation of related works, including methodological aspects: motivating research question, keyword and related work selection


strategy, a discussion of seven directly related works, and a brief discussion on the advancements with the proposed Cloud Telescope to the date. Section III describes the essen- tial aspects of the Cloud Telescope architecture, including overall characteristics, the sensor design, functional and non- functional requirements, business rules, architectural imple- mentation, and a brief comparison of Network Telescopes in contrast to the Cloud Telescope counterpart. Section IV details the experiment setup, ethical considerations, resulting dataset, and a quantitative/qualitative analysis split into two sub-sections: radiation sources and distributed analysis. Section V provides a discussion of the results focusing on the benefits introduced by the Cloud Telescope. Section VI concludes this research, while providing four fronts of future works: capture reproduction/expansion, dataset enrichment, enhanced methods for geopolitical influence, and data visualisation/analysis.

## II. RELATED WORK

This section contains a discussion of the systematic procedure employed to identify relevant works and a discussion of eleven related Network Telescope experiments, to support and contrast with our proposed model. These works were used to support most decisions around the Cloud Tele- scope’s architectural design, implementation, aim, goals and expected results. Firstly, seminal papers formalising IBR capture and analysis were identified, selected, and summarised. They were used as a starting point to a forward snowballing, in accordance with the fundamental aspects of the method as established by [25].

## A. RESEARCH QUESTION

The fundamental question when designing the selection criteria to pick up the most pertinent, relevant, and pro- ductive related works, summarises as ‘‘Is it relevant to collect cybernetic threat intelligence on Internet Background Radiation, by means of a geographically distributed, cloud- based architecture?’’. In support, ‘‘how does the method or data presented in the candidate paper directly or indirectly endorse, or refute, the use of a cloud-native approach to this purpose?’’. The following selection criteria are discussed:

- The strategy used to choose the most suitable keywords, the query string, to submit to each research databases;

- The strategy used to select each related work, and each viable research database;

- An accounting of the number of publications found; and

- The inclusion or exclusion criteria used as the final filter to select the most relevant papers discussed along this section.

## B. KEYWORD SELECTION STRATEGY

The initially selected search engine keywords were extracted from a straightforward four-step criterion:

- 1) The use of existing keywords found on the seminal papers;

- 2) Use of quotes with all compound terms, such as in ‘‘Internet Background Radiation’’;

- 3) Identification of synonym terminologies; and

- 4) Use of the OR operator to assess the effective amount of research publications associated with the purpose of this research.

Keywords were then collected from primary works:

- Pang et al. [8]: internet background radiation, network telescope;

- Wustrow et al. [6]: darknet, internet background traffic, network pollution;

- Benson et al. [26]: internet background radiation; network telescope; opportunistic network analysis; and

- Chindipha et al. [18]: internet background radiation, net- work telescope, threat intelligence, network scanning.

The result is the following main search string:

```
‘‘internet background radiation’’ OR
‘‘internet background noise’’ OR
‘‘network telescope’’ OR
‘‘network telescopes’’ OR
‘‘darknet’’ OR ‘‘darknets’’
```

## C. STRATEGY FOR SELECTING RELATED WORK

The search strategy aimed at two main goals. First, the rebuilding of the historical timeline of the most relevant con- tributions to the Internet Background Radiation field. Second, a structured, time-constrained, selection was conducted to find the most relevant recent advancements in IBR analysis, constrained to the last five years.

The main research databases considered to quantitatively assess the number of works in the field, focused on the most frequently used repositories in Computer Science:

- 1) RESEARCH DATABASE REPOSITORIES

- ACM Digital Library

- IEEE Xplore

- Science Direct

2) SEMINAL WORKS CONSIDERED FOR THE SNOWBALLING PHASE

- Technical report by Moore [1];

- Primary research work Pang [8];

- Long-term IBR analysis by Wustrow [6]; and

- Long-term IBR analysis by Irwin [2].

Forward snowballing was performed upon the four seminal works, which enabled the identification of a range of relevant, interconnected research contributions. Table 1 shows the publication count found on each selected research database, considering the most relevant keywords linked to IBR analysis.

A total amount of 950 papers were found on ACM’s Digital Library, out of which 727 fall into the 5-year cut, and 421 were published on or after 2022. IEEE’s Xplore sourced 1,200 papers, out of which 981 fall into the 5-year cut, and 472 into the 3-year constraint. Finally, Elsevier’s Science


*TABLE 1. Publication count for the most relevant search keywords supporting the literature review.*

Direct indicated the existence of up to 1,895 potentially related works, of which 1,654 are recent contributions. 1,079 falling into the 3-year cut.

## D. SELECTION OF RELATED WORKS

Any existing related work was considered as a potential candidate to figure in this literature review. A set of four questions was used to prioritise an inclusion:

Does the candidate related work:

- 1) present a characterisation of Internet Background Radi- ation? Alternatively, does it present a mechanism for its collection?

- 2) present a quantitative analysis of the captured traffic, the number of packets observed, the capture length and/or an accounting of affected network-layer, transport-layer and/or application layer protocols and service ports?

- 3) provide some sort of qualitative analysis of cyber threat intelligence acquisition based on IBR-originated data?

- 4) contain any methodological similarity, or divergence, that could contribute to, or refute, the intent to design a cloud-based, distributed architecture for IBR collection?

All candidate-works figuring among the first 30 (thirty) result items on each research database, for which the abstract indicated reasonable signs alignment with one or more of those questions, were set apart for a critical reading.

Research papers indicated on seminal works, or cited by the seminal works, were also given priority. In those cases, even if the related work did not figure on the three research databases, they were fetched, and included regardless of any constraint.

## E. MOORE’S CHARACTERISATION OF IBR

Moore et al. [1] pioneered the characterisation of the Internet Background Radiation centred on a discussion of a proposed method for its capture. They determined the criteria used to operate a Network Telescope, including its dimension, the procedures for event detection, a discussion of attack duration, and formal method for data evaluation and visualisation. Many practical considerations are given to those interested in reproducing their approach. Most of the considerations revolve around the probabilistic nature of

statistical nature shaping the observed data, including the following:

- Any observed IP address range represents a fraction, a very small fraction, of the productive address space effectively used on the Internet;

- Generally speaking, there is p chance of capturing an unique event generated by an unique source host.

- If the source host generates many packets, the number of packets observed by the telescope fits under a binomial distribution, where p represents the hit rate, and q = 1− p, the opposing failure rate.

- If this same source host defines its targets by using an uniformly random communication fashion, then the probability ofcapturing the event falls under a geometric distribution that can be described as (1 − p)k−1p. This way, each generated packet falls under a Bernoulli trial in which the probability of each of the two outcomes (captured, not captured) remains the same every time the experiment is conducted.

The straightforward implication is that the average time taken to observe at least one packet originating from a source host, at random, is 25 seconds if the telescope observes a whole /8, or 224IPs.

It should take ≈ 2 hours to observe the same event if capture scope is narrowed down to /16, or 216 IPs (the

equivalent to a Class B address block), or up to ≈ 19 days, if capturing over a /24 subnet, containing only 28 hosts.

These statistical parameters directly influence the Cloud Telescope’s aperture and capture length. Any experiment lastingmore than 20 days should suffice in terms ofproducing minimally viable results.

## F. PANG’S IBR CAPTURE AND ANALYSIS

Pang et al. [8] conducted the first IBR capture ever published in the rigour of a peer-reviewed research paper. Pang’s research group obtained access to two distinct network segments, named iSink and LBL.

- iSink segment: comprised by a) a whole Class A block, containing 224 observable addresses; and b) two /19 subnets, adding 16K addresses to the sum; and

- LBL segment: containing two 10x /24 contiguous net- work blocks, accounting for 5,120 additional addresses.

The capture was performed during a non-contiguous time- frame, between 11March and 4May 2004. The work presents both the method, focused on the Network Telescope, and the achieved results. Regarding the method, they discussed the passive versus active nature of the capturing device. One single active responder was coded to simulate a vulnerable device prone to SAMR-exe, a malware spreading on-the- wild at the time. Authors provide a detailed quantitative and qualitative analysis of the captured traffic. The more exten- sive, passive analysis, focused on the following quantitative aspects:

- TCP, UDP, and ICMP, traffic distribution, including port and ICMP packet type aggregations;


- An accounting of the unique radiation sources sending one or more packets to each of the network segments;

- A ranking of the most probed application-layer applica- tions.

*Figure 3 shows the most relevant findings.*

*FIGURE 3. Results of Pang.*

A shows TCP as the most prevalent captured traffic, accounting for 56% and 95% of the received packets. B shows the number ofunique IP addresses generating radiation against the observed network segments. C shows the most probed TCP ports, highly concentrated towards 445/TCP, the Windows-based file-sharing protocol suite (SMB/CIFS), followed by 80/TCP, which serves HTTP; and by Remote Procedure Call, RPC, which initiate authentication ses- sions for Server Message Block, SMB. The three together accounted for the majority of traffic captured in the LBL network segment.

From a qualitative perspective, the authors analysed the captured radiation against potential reasons for its emanation. The smaller, active portion of the capture enables for payload inspection, in particular to enable an analysis of TCP datagram payloads. They focused on the three most exploited ports at the time to conclude the following:

- Port 445: Contained six prevalent exploitation forms, all aiming at accessing potential file-sharing resources without authentication, as in \\<dst-IP>\IPC\$ \samr

- Port 80: Index acquisition attack patterns, such as GET /, followed by attacks against HTTP’s SEARCH method to exploit badly formed strings, such as in SEARCH /\x90\x02\xb1\x02\xb1. . . .

- Port 135: Also presenting six exploitation patterns, out of which three were clearly linked to malware propaga- tion belonging to Blaster, Welchia, and Exploit1624a.

While the results presented are no longer directly relevant due to the timewhich has passed since the capture, themethod and approach used to report the results are of interest:

- The quantitative analysis focuses on traffic distribution and aggregation of busiest network-layer and transport- layer protocols;

- Consideration is given to the recoverable metadata that can be found based on the radiation’s source IP address; and

IEEE Access

- The most prevalent radiation target ports found in the quantitative analysis may influence the deployment of an active responder on selected protocols and destination ports.

## G. WUSTROW’S LONG-TERM CAPTURE

Wustrow et al. [6] extended Pang et al.’s method [8] to conduct a two-step analysis that resulted in two distinct datasets. The first was in the form of a 5-year-long capture of the IBR, targeting a full, unused /8 network block. The second being a short-term capture, following a weekly pattern, containing three fractions of another recently allocated /8 network block.

Their work provide several tools, practices, and procedures that system administrators could use to conduct new observa- tions. Key contributions include:

- Unique characterisation of IBR as received by an unallocated /8, for which, a priori, no traffic should ever get routed to;

- A differential analysis of the traffic arriving to the unused network block, in opposition to the traffic affecting the productive network range;

- Long-term analysis of the unallocated network block, revealing pattern and behavioural changes throughout the years;

- Discussion and differentiation of the most prevalent activities, including port scanning, from other forms of traffic, combined with a clear definition of back-scatter; Focus on scanning versus back-scatter affecting TCP. Formalisation of flag state, such as:

- Port scanning →TCP SYN

- Backscatter: → TCP SYN+ACK, TCP SYN+ACK, RST, RST+ACK, ACK among other considerations, including the use of forged IP addresses.

A summary of results is shown in Figure 4.

*FIGURE 4. Results of Wustrow.*

A, shows the quantitative distribution of traffic destined to the most frequently probed TCP ports. There is a decline of interest for port 445 starting in 2007, followed by a new surge in 2009, achieving its peak in 2010. It is also possible to perceive a spike of interest for port 4662, which matches the increasing interest for peer-to-peer networks as implemented on that port by the family of protocols including emule, edonkey, and e2k.


B, aggregates TCP traffic by detected header flag state. SYN scans grew considerably during the period, but anoma- lous or uncommon flag combinations were also detected, and match, to a large portion, the behaviour of backscatter activity.

C shows a fairly stable packet rate arriving to 35.0.0.0/8 during a one-week long time span. The sample denotes an

average captured packet count of ≈ 40Ks (forty thousand packets per second), while the consumed bandwidth was of ≈ 20Mbs (twenty megabits per second), for the entire set of ≈ 16 million addresses, resulting in an average bandwidth

baseline of ≈ 1, 25bit per second, per IP address, also indicating a little less than 1 packet per second, per destined IP address.

Finally, D plots the protocol distribution between TCP, UDP, and ICMP, arriving to 1.0.0.0/8. The chart shows TCP as the most prevalent, while ICMP is seen to minor extent. Application-layer exploitation was clearly more attempted than denial-of-service based attacks, which tend to generate loads and spikes of ICMP and UDP noise.

This study reinforces the use of aggregation tables in combination with speculative charts to plot the radiation in interesting manners.

## H. IRWIN’S TELESCOPE AT RHODES UNIVERSITY

Irwin [2] thoroughly documented the deployment of a Network Telescope at Rhodes University for the consecutive period of 50 months: from August 2005 until September 2009. The telescope was prepared to capture and observe one full /24 address block belonging to the University, within AFRINIC’s address space.

The author reported the collection of a resulting dataset containing 40 million network events. They present different traffic analysis methods for each relevant network-layer, transport-layer and application-layer protocol. At the same time, they provide the introduction to geopolitical analysis influencing radiation emission. There is a discussion around the need for new approaches to data summarising and visualisation, culminating with two visualisation tools, one thought to plot and condense observed data over time, and another more towards near real-time analysis.

The results include a quantitative analysis of the produced dataset, and a qualitative analysis focusing on the rise of Conficker, a major self-propagating worm that used to propagate on port 445/TCP, and was first detected by the telescope fairly before public awareness, on the second half of 2008.

Figure 5 aggregates some of the most interesting findings.

A shows the same TCP/UDP/ICMP summarising as seen in previous works. On this report, 81% of packets belonged to TCP, followed by UDP, 12%. ICMP was seen in 5% of the incoming traffic.

B shows packet fragmentation. Fragmentation is a compute intense task, as the target needs to spend CPU cycles on packet reassembling, which might lead to denial-of-service.

Only 3,454 matched such criterion (≈ 001%), but the ability

*FIGURE 5. Results of Irwin at Rhodes.*

to extract this measurement is a remarkable example of cyber threat intelligence that can be acquired from radiation samples.

C ranks the most frequently probed destination ports, preceded by a source port analysis. The source port analysis enables to infer and detect intentionally erratic behaviour, such as source ports <1024 being used to establish connec- tions. Port 80/TCP was used as the source port in 7% of the packets. The most probed destination ports contain half of the radiation towards 445/TCP, followed by other Windows- server file-sharing related ports: 135/TCP, 139/TCP. SSH (22/TCP) also figures on the list.

D shows a plot of traffic distribution targeting 445/TCP. The spike starting at the beginning of 2009 is linked to Conficker, for which a comprehensive analysis was provided in the manuscript.

This work confirms that each Internet Background Radi- ation capture should reveal trends and patterns that can be linked to certain vulnerabilities and attack types on-the-wild during the observed time frame. New observations, in com- bination with new architectures and new data visualisation techniques, should reveal new threat intelligence and new perspectives over the observation of the phenomenon.

## I. BENSON’S FRAMEWORK

Benson et al. [26] proposed a framework towards expanding the understanding of the motivation behind radiation emitters and used that knowledge to infer the macroscopic properties of the Internet, as perceived through Internet Background Radiation collection.

Using darknet as a central terminology, authors revisit, update, and refresh IBR collection methods, clearly defining or redefining relevant terminology, including:

- Darknet: the IP address block configured to run in passive mode, occasionally returning ‘‘unreachable’’ messages (such as a TCP-RST datagram) to radiation sources;

- IP gray space: used to refer to devices or network setups intermittently performing IBR capture and productive Internet access. The goal is to learn how the radiation is affected by the existence of addresses assigned to productive use;


B reveals the number of hours it took to obtain the first packet associated with each observed IP address, autonomous system, /24 network block, Country and Internet prefix. It took around 800 hours, or 33 days, to collect at least one packet from each existing radiation source on the internet. This is around double the amount of time predicted by [1] eleven years earlier, but still a very short time frame, in case the telescope is kept running for a decent amount of time. They also provide some relevant discussion on:

- Honeypot: reinforces the honeypot as an active respon- der, to a certain interaction level (low, medium, full/high), while also referring to them as ‘‘distributed trap-based network monitoring system’’, for data collec- tion and analysis; and

- Greynet: A network that is populated with active IP addresses interspersed with darknet addresses, com- bining darknets, honeypots and productive computers altogether.

Among the most relevant methodological aspects of their work, they shed light on key aspirations of the Cloud Telescope, including:

- the use and exploitation of open DNS servers to reversely learn about radiation sources; including their system names and geographic location;

- The use of datasets coming from more than one source;

- reverse scanning, in which each radiation source is scanned by nmap to find counter-intelligence regarding source’s uptime, fingerprint and open communication ports and services; and

- Data analysis ranging from July 2012 to August 2013;

- 10 terabytes worth of compressed, PCAP-formatted dataset;

- Hybrid collection combining spike detection within traf- fic, associated with heuristics designed by [27], and later improved in [28], to identify source address spoofing, to map and aggregate radiation sources to the ASN they belong to, and the inclusion of geolocation metadata, with the support of Maxmind’s GeoIP database;

- an evaluation of how aperture size and capture length affect IBR analysis.

Among the conclusions, three are of interest to the design and implementation of a Cloud-based Telescope:

- The larger the telescope’s aperture, the least relevant is an individually observed IP address;

Authors conclude that the precision of the results with darknet observations vary in proportion to the telescope’s aperture and capture duration. They also state they have received traffic from virtually all the countries in the world (N = 245), and from all existing autonomous systems at the

- Halving a darknet’s size shall retain 89% of its fidelity in the ability to capture a fair sample of what radiation is affecting the Internet at a given time. This shall hold true for smaller darknets; and

- The comparison of radiation properties affecting two distinct Network Telescopes promotes a better under- standing of Internet Background Radiation. Compar- isons promote more consistent measurement proce- dures, allowing better inference to extrapolate observed samples to what should happen at a global scale.

time (≈ 46K), reinforcing the perception that telescopes tend to provide a fair, evenly distributed sample of what threats affect the Internet at large.

Figure 6 summarises one tabular and another chart-style

result.

## J. SHAIKH’S CORRELATION: THE IoT AFFECTS IBR

Shaikh et al. [29] predicted that the low-power, low-cost, and rushed time-to-market nature of the Internet-of-Things would foster a new generation of attacks tailored to exploit such inherent design characteristics. They proposed the use of Internet Background Radiation analysis to passively and actively measure the presence of IoT-enabled devices on the Internet, along with a method to account the radiation targeting this class of computer devices.

Their work is based on data collected by the Center for Applied Internet Data Analysis - CAIDA’s telescope. The capture range was two months, starting in December 2016, and lasting until the end of January 2017. They analysed dataset worth the amount of 1,5 terabyte of compressed, PCAP-formatted capture recording. This hybrid (active, passive) analysis consisted of the individual inspection of each packet in the dataset against patterns, fingerprints, or footprints, that could have been generated by typical, constrained resource, embedded devices, carrying minimal firmware or operating system. Dataset entries had the source IP address enriched with data available on two open source intelligence platforms: Shodan [30] and Censys [31]. These

*FIGURE 6. Results of Benson.*

A summarises the received traffic in three different categories. UCSD-2012 refers to the quantitative analysis performed on UCSD’s telescope during the year of 2012 at University of California in San Diego. UCSD-2013 refers to the same place, but during 2013. MERIT-2013 refers to the collection that took place at Merit Networks the same year.

Findings were categorised into four sections: Miscon- figurations, Scanning, Backscatter and unclassified. Traffic attributable to P2P was highly prevalent under the misconfig- uration aggregation. Conficker, alongside with Bro network scanner, were the main source of radiation affecting the scanning category. Backscatter was individually aggregated as the third most prevalent activity, followed by encrypted transit, among others.


Access

continuously scan the entire public IPv4 address space and collect any available metadata, including the hardware and software stack embedded to the host.

The effort resulted in the identification of 285,478 IoT devices within the dataset. These were aggregated under five classes: Digital Video Recorders, DVRs, SCADA, Thermostat, Webcam (or IP camera), and Bluetooth-enabled IoT.

Results are shown in Figure 7.

*FIGURE 7. Results of Shaikh.*

A shows that more than half of the attack patterns found on the dataset aimed at exploiting vulnerabilities targeting digital video recorders. SCADA systems figure on the second position, followed by thermostats, bluetooth-enabed IoT and IP cameras.

B shows attack type distribution per world region. There is a high concentration of attacks aiming at exploiting SCADA vulnerabilities in Europe, which is the same target for most of the thermostat, or smart home, oriented attacks. Asia faced the majority of attacks targeting surveillance devices, DVR and webcams included.

## K. CHINDIPHA ON SMALL-APERTURE TELESCOPES

[18] quantified the accuracy of smaller apperture Network Telescope configurations. The main argument of the authors is that radiation capture by means of large darknets is no longer feasible due to pressure to put unallocated IPv4 addresses to productive use. They made use of capture samples taken from two very large network blocks, 146/8 and 155/8. Dataset down-sampling was generated by segmenting each /8 into many /24. These were then sub-divided into smaller samples ranging from /27 until /30, named ‘‘subnet equivalents’’.

Their statistically sound method provide an strategy to establish the error margin associated with each ‘‘aperture stop’’. This involves four calculations, three of which are relevant to present:

- MAPE: The Mean Absolute Percentage Error;

- SMAPE: The Symmetric Mean Absolute Percentage Error; and

- MASE: Mean Absolute Scaled Error, or the measure- ment to predict the accuracy of MAPE. The closer to zero, lower the error margin.

*TABLE 2. Smaller aperture telescope accuracy [18].*

| Subnet | MAPE(%) | SMAPE(%) | MASE |
| --- | --- | --- | --- |

Accuracy is reported as a percentage relative to the amount of observed IP addresses in the whole /24 block against the subnet equivalent under consideration, as reported in Table 2.

According to Chindipha [18], down-sampling telescope aperture from /24 to /27 shall retain 92% accuracy, which is represented by a low MASE score of 0,68. Down-sampling to /28, or even /29 shall retain 89% accuracy. A down-sample to /30 (from 256 to only 8 observed IP addresses), shall retain 83% accuracy.

This work provides a safe ground for the research hypothesis in the sense that experimenting with smaller-than- usual IPv4 address ranges should still result in meaningful findings. A longer time frame should also compensate smaller apertures, as previously discussed.

## L. ZAKROUM’S PREDICTION MODEL

[32] uses Internet Background Radiation data to propose a framework enabling to predict global cyber threat activity based on current and past traffic behaviour.

The approach proposes the use of inferring groups con- taining transport-layer ports grouped by scanning frequency and by temporal and and semantic similarity. The scan- ning/probing rate arriving on each grouped transport-layer port is used to feed a neural Long-Short Term Memory (LSTM) network. This results in a prediction model deter- mining the probability of an attack within a one-hour time- frame and for the next twenty-four hours.

They have used a dataset comprised of IBR arriving to two /20 networks, 8,192 IP addresses, one located in France and another in Japan. Data was collected for three and a half years, between 2017 and 2020.

The most relevant findings are displayed in Figure 8.

*FIGURE 8. Results of Zakroum.*

A shows a dataset summary, which contained 80 billion packets, out of which 94% TCP and 5% UDP. Average daily


packet rate was of ≈ 60% million. All destinations were probed at least once a day during the capture time-span.

A reveals the Russian segment under observation is mostly hit by unsolicited TCP traffic, comprising 89% of their sample, followed by ICMP (7%) and UDP (4%). B breaks- downTCP traffic per destination port, revealing that the telnet port is the most frequently probed (3%), followed by SSH and Microsoft’s SMB and SQL service ports accumulating at least 1% of the traffic each.

B shows a reasonably stable traffic growth rate towards the two darknets. The green line stacks the sum of both telescopes. The spike in March 2020 accounted 1,75 billion packets.

C shows the range of destination ports probed during the building of the dataset. This confirms the empirical thought that a small portion of all destination ports are frequently probed, while many unassigned ports are of much lower interest for radiation emitters.

Back to overall traffic, C lists the most active radiation sources, identified by the Autonomous System owner, revealing that a Netherlands-based AS has generated 6% of the noise, followed by a mix ofrussian-based and baltic-based ISPs which together accounted to 24% of all seen packets, in other words, locally attributed radiation corresponds to one fourth of all seen traffic.

D shows a word cloud, or port number cloud, containing the most frequently probed ports for each semantic-temporal, inferring group aggregation:

The time of the day was also evaluated. In D they indicate a peak of incoming traffic arriving to the capture mechanism between 5pm and 7pm GMT.

- The leftmost group refers to remote administration services, for which traffic on ports 22 (SSH) and 23 (Telnet) were more prevalent. Frequently used alternate ports, such as 2222, and 2323, also stand out;

## N. KORI’S ANALYSIS OFAN ACTIVE NETWORK TELESCOPE

Kori [34] recently reported the deployment of an Active Network Telescope to which 210 IP addresses within a /24 network block were assigned. The experiment was deployed in March 2022, and endured for one year. They focused on providing a TCP-centric quantitative and qualitative analysis of the received radiation. 1.1 billion network events were recorded. Relevant findings are reproduced in Figure 10.

- The central group shows ports related to HTTP-based services, highlighting the prevalence of ports 80, 81, 88, 8080, 443, among other; and

- The rightmost group aggregates manyVPN protocol and service ports as implemented by L2TP, PPTP, IPSec, among other.

Tools, procedures and aggregation techniques found on this work shall contribute to drive decisions regarding how to handle and aggregate the datasets envisaged by this research effort.

## M. ZOLOTYKH’S LOOK FROM THE RUSSIAN SEGMENT

Zolotykh [33] reported what they termed the dark collector: ‘‘trap for background noise’’. Different from a honeypot, the trap is comprised oftwo elements: a collector and an analyser. The collector is set up with two interface cards, one of which is publicly exposed, and receives background noise. The analyser is implemented bound to the second, private network card, on top ofwhich a toolset is built, including reverse-DNS solvers, which contributes to identifying the most active noise generators.

Their capture experiment was conducted during four consecutive months, between late 2019 and early 2020. A summary of findings is reproduced in Figure 9.

*FIGURE 10. Results of Kori.*

A shows a combined bar graph reporting the most active TCP destination ports combined with the number of weeks each particular port remained in the Top 5 aggregation. Port 22 SSHwas the busiest, followed by Telnet 23, HTTP 80, Xsan Filesystem Access at 62897 and Microsoft RDP 3390, among others.

B shows a plot of radiation sources which actively interacted with the network telescope. The apparently even traffic distribution was accounted in terms of the five most active countries, reported as: United States of America, China, Russia, The Netherlands and Great Britain.

C shows three time lines: The grey curve depicts how long it took to receive at least one packet from each of the 19,778 Autonomous Systems seen. The blue line shows a linear growth in terms of the diversity of IP sources, 2,883,366, exchanging a connection initiation packet with the sensor,

*FIGURE 9. Results of Zolotykh.*


while the orange one depicts the subset exchanging one or more payload with the active collector, 1,531,522 (53%).

## O. ANH AND NAKAMURA ON MIRAI AND HAJIME

Anh and Nakamura [35] conducted a baseline investigation into the evolution and prevalence of Mirai and Hajime utilizing datasets as collected by The Network Incident Anal- ysis Center for Tactical Emergency Response (NICTER), operated since 2005 in Japan, and collecting unsolicited traffic arriving to an undisclosed amount of more than 300,000 IP addresses. The dataset was filtered to only contain traffic on ports of botnet prevalence, 23 and 2323. AMySQL- backed method was employed to aggregate data on a daily basis, where malicious sources of interest were added to a list, after which duplicates were removed.

Among the results, researchers were able to rank the most infected countries, by either Mirai or Hajime, and rebuild a timeline of activity belonging to each of these botnets, as aggregated in Figure 11.

*FIGURE 11. Results of Anh and Nakamura.*

A shows that China, Brazil, Egypt, India, and Vietnam, among others, host the most infected sources attempting to propagate Mirai, as perceived by the Network Telescope. B summarizes the propagation of Hajime, where Brazil, Iran, India, Russia and Vietnam, among others, show up as the most prevalent probing sources.

A Mirai evolution timeline, summarised in C, shows the authors were able to identify the rise of the most important sub-variants, including Moobot, Sora, and Mozi.

D depicts the peak activity for one of the two Hajime strains discussed on the work. This second strain is slowly ceasing activity, whereas the first one was no longer seen by that telescope after April 2018.

## P. RELATED WORKS DISCUSSION

Revised related works confirm the need of a certain agreement between the research entity, an University, for example, within one or more Internet number authorities, IANA or another, to obtaining access to an observable IPv4 address range, such as seen in [6] and [8]. Alternatively, one could make use of address ranges already allocated for universities, as in [2], or in [32]. Finally, it is also possible to make use of openly available datasets, such as the one provided by CAIDA’s network telescope, as in [29]. It is paramount to consider IPv4 address absolute exhaustion

in terms of primary allocation [22] and the debate around unfair and unauthorised use ofapparently unallocated address blocks, also called IP squatting [36].

The dataset resulting from each documented research effort directly result from the main factors affecting its quality, size and resolution: the telescope’s aperture, the capture length, and the point in time when the capture experiment was conducted. Fewworks report the final dataset size, using different accounting approaches. [2] reported the number of events, in millions, (40M). [26] reported the collection of a total amount of 10 terabytes worth of compressed PCAPs. [29] made use of a telescope half the aperture of [32]’s, obtaining 1,5 TB worth of data. [32] performed their work eleven years after [2], with a 32x larger telescope, and obtained a dataset 2 thousand times larger for very similar time-frames, of 50 and 42 months respectively.

Each related work has reported an objective, quantitative analysis. The accounting approach revealed the most essen- tial characteristics of each Internet Background Radiation capture. This can be considered the minimal standard on any work intending to contribute to the field, typically in the form of Top 10 rankings containing the most active radiation sources, the most scanned transport-layer ports, the most intensely seen ICMP packets, and so on. In most cases some sort of data visualisation technique was also employed to provide visually appealing artefacts, such as time-series distribution, pie and bar charts, and other interesting forms of radiation interpretation.

The most prevalent form of traffic seen across all resulting datasets belongs to TCP. This has to do with the fact the majority ofcore Internet services require transmission control reliability features found on this key transport-layer protocol. It is reasonable to assume most of the malware wanting to self-propagate in global scale will attempt to exploit the most popular (and vulnerable) services widely implemented on the Internet. On the other hand, amplification attacks targeting UDP-based services, such as the DNS, is also detected and discussed on the literature.

The lack of of denial-of-service-oriented attacks is surpris- ing to an extent. The past and current decades saw a range of elaborated attacks against major Internet content providers, such as Spamhaus, in 2013, Github in 2015 and 2018, Dyn in 2016, and Amazon Web Services, in 2020 [37], [38]. One plausible explanation could be that these attacks are very well crafted against particular targets, and therefore, out of the range observable by Network Telescopes.

Qualitative-wise, the analyses vary. Less recent works, ranging from 2004 to 2011, tend to discuss one or few key malware-spreading activity on-the-wild during the capture time-frame, from Sasser to Blaster, from SQL Slammer to problematic Conficker, which caused immense loss at the time [39] and until Windows-based computers worldwide were effectively patched. The more recent works tend to focus on botnet propagation activity, while linking the motivation for this shift, to the rise of the Internet-of-Things,


and how it negatively impacted the Internet from a cyber security perspective. Newer works also make use of newer computer techniques, able to produce more meaningful data visualisation methods in reasonable computing time.

This research therefore proposes a cloud-native archi- tecture to enable distributed capture of Internet Back- ground Radiation, by discussing potential advantages of this approach, and by providing fresh, updated quantitative and qualitative data fostering method comparison. The ultimate goal is to provide a novel, perhaps better approach to IBR-based cyber threat intelligence acquisition, under an ephemeral, reproducible fashion.

## Q. CLOUD TELESCOPE ADVANCEMENTS

We introduced the Cloud Telescope as a ‘‘cloud native framework for globally distributed capture and analysis of internet background radiation’’ in [40]. The work explains

that:

- Internet adoption growth and IPv4 address exhaustion could render present and future IBRobservation unfeasi- ble or restricted to organisations holding early, generous internet address block allocations;

- The diversity of regions and availability zones offered by cloud service providers provide unparalleled geo- graphical capillarity to the establishment of cause-and- effect correlations in malware propagation and denial- of-service attacks impacting the Internet infrastructure globally; and

- Costs related to the framework deployment could be minimised with proper use of tiny-sized, virtualised cloud instances benefiting from the bidding scheme offered by the ‘‘spot’’ price model, with up to 90% discount, as long as the cloud telescope fleet can rearrange and relaunch in response to CSP-generated termination request events.

We deployed the Cloud Telescope architecture to conduct a preliminary proof-of-work, one-month-long observation to distributedly capture Internet Background Radiation, as depicted in Figure 12.

*FIGURE 12. Instance of a cloud telescope sensor.*

The experiment resulted in 21 million packets captured across the 26 commercially available regions of AWS, in North America (5), South America (1), Europe (8), Africa (1), Middle-East (2), Asia (8) and Oceania (1). At the

transport layer, traffic distribution was 78% TCP, 14% ICMP and 8% UDP. The most active TCP port was 23/telnet (3%). A clear sign of the Mirai botnet was found with pattern- based analysis. Due to the geographically distributed nature, we introduced a new form of correlation: the country where the sensor is placed in contrast to the country originating malicious activity. We found Russia to be the most active radiation source, while the sensor fleet located in eu-west- 2, London region, received the most significant amount of

traffic, 10%, where X≈3%. The dataset is available for public use on IEEE Dataport, at [41].

The prevalence of botnet activity led to the need to design a repurposed Cloud Telescope deployment that could help to identify, quantify and analyse infection patterns belonging to the Mirai botnet and its variants. To accomplish this, we launched a Cloud Telescope sensor fleet comprised of 260 sensors, ten per AWS region, in a hybrid pas- sive/active response configuration implementing a custom- made medium-interaction Honeypot bound to selected TCP ports: Telnet (23), 2323 and HTTP (80) were programmed to pretend to accept Mirai infection attempts. Recorded traffic reveals infection sources, infection patterns, command-and control sources, and payload distribution hosts. A correlation ofCVE entries andMirai variants was established, and copies of the malicious binaries used to run the botnet attacks right after the infection were investigated in [13]. The resulting second dataset containing 10 billion network events is also available on Dataport at [42].

## III. CLOUD TELESCOPE

This section describes the architecture of the Cloud Tele- scope. We present the key functional and non-functional requirements, the most significant business rules for the deployment within a cloud service provider, and insights into operational costs. Some of the terminology follows Amazon Web Service naming scheme, which can be adapted for other cloud service providers with same functionality.

The Cloud Telescope is fundamentally based on the following assumptions:

- 1) A cloud-based architecture shall enable for Internet Background Radiation collection in a similar, yet substantially different approach, than used for the deployment of a standard Network Telescope;

- 2) The geographic topology of a CSP shall provide unmatched, distributed cyber threat observability, ofevents taking place in different regions of the world; A Cloud Service Provider materialises an ideal approach in terms of globally distributed capillarity for any purpose, including unsolicited packet capture; The distributed architecture, made possible by the operational nature associated with the geographical dispersion of cloud providers, should enhance the detection of events that are also carried out in a distributed fashion. An example is the botnet, aimed at compromising targets on a global


- scale, potentially motivated by geopolitical events originating outside the cyberspace.

- 3) The availability of IPv4 network blocks is scarce. Primary allocations are no longer available and there is pressure to put idle blocks to productive use [19];

- 4) Idle computing capacity inherent to the cloud computing model shall provide a relevant mix of geographically distributed IPv4 address ranges for radiation collection, at acceptable cost;

- 5) Small aperture telescopes should retain acceptable statistical relevance for IBR capture, as long as increased observation duration compensates for potential address deficit [18]; and

- 6) The ephemeral and reproducible properties inherent to the design of the Cloud Telescope enables peer validation of its implementation.

Figure 13 summarises the final Cloud Telescope Archi- tecture. IBR capture sensors are deployed within each cloud region to enable the capture in a distributedmanner, fromboth geographical and topological perspectives.

*FIGURE 13. Architecture of the cloud telescope.*

Each viable cloud region is configured to contain the right set of architectural elements to support the distributed capture. The most relevant setup aspects include the Virtual Private Cloud, the Internet Gateway, Routing Table, Security Group, Access Control List, sensor setup, and persistent storage setup, with the use of one single global cloud bucket. AWS terminology is used when needed, i.e. bucket instead of blob storage, but the architecture itself is designed vendor- neutral. The VPC is enabled to logically group virtualised capturing infrastructure resources, and to which the routing table, access control list and security settings should be applied. A single, internet-facing Internet Gateway is enabled and attached to the VPC. This should be configured with the addition of the corresponding route to sub-net’s route table that directs unsolicited internet-bound traffic to the sensor sitting in the sub-net’s range.

The capture sensor, which must be virtualised in a cloud environment, receives a non-public, internal address, according to RFC 3330 [7], as an imposed default. It is optional to enable one or more external, public, or elastic IP addresses. As it pertains to the capturing platform, every sensor should receive one IPv4 address from the CSP region’s address pool. The question of whether each sensor should have only one public IP address is open for experimentation

and is mainly implemented as such due to a cost-related perspective. From a performance perspective, one sensor should be able to handle IBR affecting a number of public IP addresses, especially when considering the performance associated with the variety of virtual computer classes offered by cloud providers. Launching a number of small, individually-sized sensors with a single public address each is significantly more cost-effective than assigning multiple IP addresses to a single instance, especially when dealing with tiny-sized virtual machines where the cost of an additional public IP address is greater than that of launching a second instance.

The approach for the security group and related ACLs in the cloud is not as permissive as the on-premises counterpart, in which typical network telescopes operate under a default-allow policy posture. Internet-Gateway- enabled VPCs default to a security group that blocks all internet-originated traffic, with the exception of certain web and remote admin port ranges: 22/TCP (SSH), 80/TCP (HTTP), 443/TCP (HTTPS), and 3389/TCP (RDP). Another exception is the traffic that is originated within the very VPC’s subnet, which is usually allowed, for many reasons, including serving end-user applications, systems update, among others. Radiation capture demands a fully-open, default-allow rule-set. The sensor must get fully exposed to incoming, unsolicited Internet traffic. Therefore, a fully-open security group must be declared and attached to the VPC so

that:

- All IP types are allowed in via the public interface. This should include all forms ofexotic and unexpected traffic, also SCTP and IPSec packets, among others;

- All ICMP traffic is allowed in via the public interface. This should include all known types, free from any sort of rate limiting technique, either imposed by the Cloud Provider or implicitly defined as a best practice default;

- All transport-layer protocols are allowed in via the public interface. While TCP and UDP are the most prevalent, the capturing scheme should remain open for exotic types, such as the emerging QUIC proto- col, among others. State filtering should be rejected, in the sense that malformed TCP flags are allowed. No kind of normalisation or traffic conditioning, such as the normalisation procedure thoroughly documented by [43] should be implemented, either by explicit user- accessible commands, or by enforced measure resulting from the shared responsibility model within the Cloud Service Provider;

- The Cloud telescope inherits the behaviour of a Network Telescope, in which no application-layer communica- tion is effectively established. Therefore, no special configuration is required for the application layer. As a default, there is no engagement with any sort of application-layer. However, it shall be easy to implement high-level responders as widely documented [44], [45], [46]; and


- Conversely, in case there is a need to implement active, application-layer responders, this should be possible with the use of commodity software stacks, including bash, python and/or rust-based solutions configurable via Infrastructure-as-Code.

## A. CLOUD SENSOR DESIGN

The design choices for the Cloud Sensor revolve around decisions affecting instance type, machine class, pricing model, and the ephemeral nature of the method. These are accompanied by software component choices including the selection of an operating system, application stack and automation of the capture life-cycle.

AWS offers a low-cost, general-purpose T3 instance class that is powerful enough to handle Internet Background Radiation acquisition. The T3.nano class, equipped with only 512MB of RAM, provides an acceptable performance at the lowest cost. The main challenge associated with this decision is to ensure no data loss occurs due to small memory size, leading to potential packet capture drop. To minimise the associated risk, Alpine Linux, rather than Amazon Linux, was assigned as a suitable light weight solution. Alpine is a minimalist Linux distribution based on musl, a lightweight libc interface implementation, and the compact busy-box user-land, instead of a regular fully-fledged Linux stack, resulting in a practical choice for operating system virtualisation and containerisation [47].

To keep sensor costs at a minimum, EC2 virtual instances must be acquired under the spot pricing model. The scheme provides predictable prices that adjust to current offer and demand, per cloud region. Typical savings are of 70- 90 percent when compared to the standard on-demand offer [48]. This comes with the need to properly handle termination requests on the Cloud Service Provider’s (CSP) side, where the price currently paid for an instance is outbid by concurrent clients or a momentary lack of spot instances. Each sensor is therefore prepared to receive and handle the EC2 Spot Instance Interruption Notice, available through each instance’s internal metadata service. Upon interruption request, and during the 2-minute grace period, the sensor will adequately terminate the capture process. It will then move the last chunk of recorded data to the external persistent stor- age: the global S3 bucket. Orchestration will subsequently launch a replacement instance, updating the winning bid price accordingly, returning the collection platform to the desired operational state. Despite the inevitable momentarily continuity loss caused by the method, it is found to be acceptable as a newly launched instance replaces the older sensor. The fact that the new sensor will acquire a new IPv4 address contributes to a wider diversity of observed addresses.

During normal operation, each sensor is configured to comply with the following fundamental requirements:

- R1 A fixed number of sensors should be deployed in each viable region of the cloud service provider.

- R2 There should exist a single, global, and private storage target, in the form of cloud storage, or bucket, to which recorded data must be moved to;

- R3 tcpdump is demonised, and shall rotate capture files every 24 hours;

- R4 Capture files should be uploaded to the target bucket immediately after rotation; and

- R5 SSH service is reassigned to port 65535/TCP and should be omitted from the capture.

The resulting fleet of N sensors per region, multiplied by the number of viable cloud regions should simultaneously listen and record the arriving radiation. The Stockholm region was chosen as the target for the unified data storage because Sweden implements strong GDPR (General Data Protection Regulation) enforcement, regulated by Datainspektionen [49], within the European Union. This can be changed as an environment variable. Implementation of the PCAP file rotation can be achieved via -G parameter in tcpdump. Capture chunk upload is done by activating a native API interaction with the global bucket, backed by internal role-based access and authorisation, preventing unnecessary public bucket exposure. Finally, in case administrative access is needed to one sensor, for occasional inspection, that can be done via port 65535/TCP, using SSH configured to require strong key-based authentication.

The design and implementation of the Cloud Telescope is described as a set of functional requirements, non-functional requirements, one business rule, and key aspects of its architectural implementation.

## B. FUNCTIONAL REQUIREMENTS

These are the key functional requirements applicable to the Cloud Telescope.

- FR1 All filtering capabilities provided by the cloud service provider must be disabled, including security group standard posture and default-deny access control lists implemented as part of the cloud computing shared- responsibility model;

- FR2 One cloud-native object storage facility: a cloud bucket, must receive and aggregate all traffic recorded by each sensor within the sensor fleet;

- FR3 Any packet arriving to a cloud telescope sensor must be recorded, except the traffic eventually generated by the sensor itself, when uploading packet recordings to the aggregation bucket;

- FR4 Packet capture recordings must be compressed and uploaded to the aggregation bucket every 24 hours, or configurable shorter time period;

- FR5 Port 65535/TCP should be assigned to the local, emergency-only SSH service, and kept out of radiation capture; and

- FR6 The format of the capture recording must be the PCAP file format, compressed with gzip, by the sensor, before bucket submission.


- FR7 A full EC2 metadata content snapshot dump should be recorded to a text-file to enable future investigation, including the public IP address, cloud region, and number of packed drops, if any;

- FR8 Each sensor date and time should be set to Universal Time Coordinated, UTC;

## C. NON-FUNCTIONAL REQUIREMENTS

The non-functional requirements refer to the most important technical decisions made to optimise the sensor fleet’s operation, in particular, the measurements put in place to take advantage of the spot pricing model allowing for up to 90% discount in instance/sensor deployment.

- NF1 Low-cost AWS EC2 t3.nano instance type should be employed to run the sensor stack;

- NF2 Low footprint Alpine Linux with lightweight musl library should be used to prevent packet drop;

- NF3 Sensors must implement code to respond to the ‘‘EC2 spot instance interruption warning’’ event.

- NF4 The sensor fleet should be launched under the spot pricing scheme.

- NF5 Architecture must be described in vendor-neutral lan- guage Terraform.

## D. BUSINESS RULES

There is one relevant business rule: Upon receiving the interruption warning notice, the sensor must stop the capture procedure, compress the last recorded chunk and upload the resulting file to the aggregation bucket. A new instance should be immediately launched by winning the highest bid of the spot pricing model again at a slightly higher hourly cost rate.

## E. ARCHITECTURE IMPLEMENTATION

The architecture was implemented using Terraform, and Bash. The former describes the building, launching and instance orchestration across the range of cloud regions, along with the dedicated cloud bucket allocation in eu-north- 1. The latter is employed to script the required automation within the virtualised operating system belonging to each sensor, including:

- SSH port redirection;

- Time-zone set up to UTC;

- Disabling unnecessary services that could generate unwanted traffic or noise;

- A daemon process that implementing metadata col- lection and reacting to potential instance termination requests;

- A demonised, start-stop script for the tcpdump binary, enabling re-initialisation in case of abnormal termina- tion;

- A customised packet drop monitoring service;

- Automation of data chunk uploading to the bucket every 24 hours, at most.

*TABLE 3. Network and cloud telescopes compared.*

Terraform automatically fetches the current list ofavailable cloud regions directly from the Cloud Service Provider’s back-end, so the telescope deployment can be set up to dynamically adjust to region growth if desired. Researchers wanting to reproduce the experiment should only need to setup a new IAM key/secret pair, followed by Terraform native commands to have the same architecture launched under their control. Code is as vendor-neutral as possible, however, changes will be required if moving from AWS to another Provider, especially in terms of bucket terminology, instance type and instance acquisition model, among other vendor-related technical and financial decisions.

## F. NETWORK TELESCOPE AND CLOUD TELESCOPE COMPARED

Network Telescopes and the Cloud Telescope both aim at the same purpose: to collect internet background radiation. The key difference is that the Cloud Telescope is geographically distributed, and meant for a deployment within cloud service providers. A summary of differences is itemised in Table 3 and discussed ahead.

Network Telescopes are usually deployed within research institutes and universities. This is not only due to the fact Internet Background Radiation is a research subject, but also because these are the places most likely to hold unused IPv4 address blocks, either partially or in full, and can afford to purpose these addresses for research intents. The Cloud Telescope is meant to be deployed within public Cloud Service Providers. This means any individual or organisation can benefit from the idle IP address ranges the CSP must hold as a business rule, and launch sensor fleets to conduct new observations.

As reviewed, the IPv4 address ranges assigned to Network Telescopes can vary from one or more large /8 blocks to interleaved portions of a single /24. On the other hand, the Cloud Telescope counterpart has been experimented with an IP address count as small as ‘‘one IP address per each of the 26 available cloud regions’’ (26 IP addresses) or as large as an aperture of ‘‘ten IP addresses per available cloud region’’ (260 IP addresses). The former is constrained by the network block assigned by the local Internet Authority, ultimately, IANA. The latter is constrained by the budget that will be allocated to support the Cloud Telescope deployment, and should appear to come froman infinite IP address pool provided by the cloud company chosen to host the experiment.

In terms of capillarity, Network Telescope deployments are physically bound to a single host institution and ultimately


to a single country to which the network block was initially assigned. The Cloud Telescope, on the other hand, benefits from the ability to distributedly listen and capture unsolicited traffic arriving to a mix of IP addresses belonging to many different regions of the world. This variation is relevant when discussing two potential aspects driving the background radiation: the coding practises used in the implementation of host scanners, malware and related threats, and geopolitical motivation. A common approach to the implementation of cybernetic threats is to probe the next host as increment to the current one. For example, after probing 203.0.113.20, the next obvious target is likely to be 203.0.113.21. After 203.0.113.255, the next is probably 203.0.114.1, and so on. While Network Telescopes listen to contiguous network blocks, they are likely to capture such scan attempts in whole, whereas the Cloud Telescope counterpart is more likely to capture only fragments of the same activity, but in increased quantity, as the IP ranges are scattered around the globe. Assuming that actors behind internet-wide attacks might be interested in one or few particular countries, the radiation sample coming from multiple regions of the world, as provided by the Cloud Telescope, is meant to enable the comparison and contrasting of how differently each region is attacked.

A discussion on Network Telescope deployment costs typically revolves around defining a budget to the hardware acquisition, in the form of a single capturing device, and attached on-premises data centre costs, usually shared with other, production oriented, server fleets, and attached costs such as electricity, cooling and physical security. Yearly rates applied to the concession of IP address blocks may also apply. These are typically diluted among common capital and oper- ational expenses within the hosting institution’s needs, and hardly detailed in peer research. On the other hand, the Cloud Telescope fits the ‘‘pay-as-you-go’’ consumption model that defines Cloud Computing. The cost is proportional to the sensor fleet size, or to the telescope’s aperture. In essence, the CSP charges for the virtualised compute instance, for which the cost vary according to CPU specification, RAM memory space, primary storage size, and the total amount of bytes exchanged over the public internet during the period. The target final storage bucket aggregating the captured sample is also of special interest, and charged by the amount of gigabytes effectively spent on a monthly basis. Accessory costs may include the cloud native secrets management service, traffic surcharge related to uploading data chunks to a bucket placed in a region other than the one hosting the sensor, and other management-related services. There is no charge for many pre-requisites, including the Virtual Private Cloud setup, Security Groups, Access Control Lists, Internet Gateway, and Terraform-related deployment and shutdown actions.

## G. BASELINE BUDGET

Operational costs related to running the required sensors to support the Cloud Telescope are mainly influenced by the

*TABLE 4. Architecture budget - monthly costs.*

pricing model being used, fleet size, capture duration, and the bucket-based persistent storage, to a smaller extent. AWS Pricing Calculator spreadsheet-based calculation tool was used for an estimation of costs associated with launching a given architecture. The final cost associated with running the month-long observation of IBR using 130 sensors per region, across the 26 commercially available regions of the Amazon Cloud was of 345.80 United States Dollars (USD) per month, as detailed in Table 4.

The final cost associated with launching the Cloud Telescope was, therefore, estimated at 1,729 USD for five months of capture. In February 2024, AWS announced they would start charging for the first public IPv4 associated with any deployed virtual machine, which doubled the cost of the architecture for that month. The effective final cost for the full-scale, 5-month-long (151 days) experiment, was of 2,429.29 USD, averaging to 16.08 USD per day.

## H. INFRASTRUCTURE-AS-CODE

Infrastructure-as-Code is a by-product of the Devops field. The concept refers to the purpose of using code to describe infrastructure elements, including virtual machines, and their CPU, RAM and storage needs, along with network cards, switches, and cloud resources. Cloud resources include, particularly, the setup ofaVirtual Private Cloud, internet gate- way, DHCP server, access control list, filtering/firewalling rules, and cloud-native resources, such as a storage bucket or a load balance, for instance [50].

The operating system of choice, along with configura- tion, package installation, setup and tweaking, can all be accomplished via IaC, using either operating system native scripting language, such as Bash and Powershell, or some sort of orchestration-specific language, such as Ansible. The Cloud Telescope is implemented in the Terraform IaC Language, tailored to operate within Amazon Web Services as a CSP. The resulting Terraform Infrastructure-As-Code artefact reflecting this architecture was implemented by Beiler [51], and is available.

Figure 14 illustrates the compute instance launch configu- ration for one of the cloud regions.

Line 1 indicates the configuration applies to the spot pricing scheme applicable to us-east-1 region in the United States ofAmerica. Common resources are imported in Line 2. The configuration then describes the need to launch five instances into that region, on Line 4. Lines 5 to 11 feed the configuration with global variables, including an Identity and Access Management profile, the bash script containing operating system automation, under user_data. Spot price


*FIGURE 14. Terraform compute instance launch definition.*

allocation is negotiated as rules within spot_price, CPU and RAM are described as a T3.nano instance class within instance_type, storage needs, in the amount of 8 GB, under volume_size_gb, and SSH keypair in key_name, followed by the corresponding public key onto variable ssh_public_key.

## IV. THE CLOUD TELESCOPE EXPERIMENT

This section documents the main experiment conducted towards validating the Cloud Telescope’s design and imple- mentation as a distributed method for collecting Internet Background Radiation.

We initially explain how the experiment was set up. Then, we characterise the resulting dataset in terms of overall collected events. Next, radiation is analysed in three perspectives: radiation sources, focusing on the quantitative distribution of probing origins, radiation targets, focusing on network-layer and transport-layer protocol distribution, and distributed analysis, where we discuss traffic dispersion towards the different countries and cloud regions hosting the experiment.

## A. EXPERIMENT SETUP

The Cloud Telescope was set to launch on October 1st 2023. The capture process lasted for full five months, ending 151 days later, on March 1st, 2024. Figure 15 shows the twenty-six commercially available AWS Regions in which the Cloud Telescope sensor fleet was deployed.

*FIGURE 15. The 26 AWS regions observed by the cloud telescope.*

A total of 130 cloud telescope sensors were deployed to simultaneously collect Internet Background Radiation. Five sensors per each AWS region. Five locations were covered in North America: Canada Central (ca-central-1), US West in Oregon (us-west-2), US West in Northern California (us-west-1), US East in Northern Virginia (us-east-1), US East in Ohio (us-east-2). One region in South America: Brazil/Sao Paulo (sa-east-1). Eight regions in Europe: Europe/Ireland (eu-west-1), UK/London (eu-west-2), Europe/Paris (eu-west-3), Europe/Spain (eu- south-2), Europe/Stockholm (eu-north-1), Europe/Frankfurt (eu-central-1), Europe/Zurich (eu-central-2), Italy/Milan (eu-south-1). Two regions in Middle East: Bahrain (me- south-1), United Arab Emirates (me-central-1). One region in Africa: South Africa/Cape Town (af-south-1). Nine regions in Asia and The Pacific: India/Hyderabad (ap-south- 2), India/Mumbai (ap-south-1), Jakarta (ap-southeast-3), Japan/Tokyo (ap-northeast-1), Japan/Osaka (ap-northeast-3), South Korea/Seoul (ap-northeast-2), Hong Kong (ap-east-1), Singapore (ap-southeast-1), and Australia (ap-southeast-2). The aggregation bucket was set up in Sweden.

## B. ETHICAL CONSIDERATIONS

Internet traffic collection, as performed by Network Tele- scopes and as intended by the Cloud Telescope, require responsible data handling, as these capture mechanisms intentionally record network packets arriving to sensors. The metadata that is required to describe a network packet always gets recorded. This necessarily includes: the source IP address, the target IP address, source and destination ports, if TCP or UDP, source and destination ports, if TCP or UDP, and message type, if ICMP. Payload collection, on the other hand, may or may not occur, depending on the strategy that is adopted to implement the capture, and varies according to the desired level of interaction. A fully passive sensor only captures these envelope metadata of each incoming packet, whereas a high-interaction, honeypot-style responders record a number of application-layer messages actively exchanged with the attacking source, revealing far greater details about the apparent attacking source.

Researchers at CAIDA [52] have proposed a comprehen- sive Internet data sharing framework aiming at balancing privacy and utility of network traffic measurements. We have conducted the experiment reported on this paper in alignment with the ethical considerations discussed by the framework, acknowledging its key properties:

Motivation: Internet researchers lack a legal framework that prescribes, incentivises or forbids the sharing of network measurement data. We share our results, in the form of this paper and the companion dataset as an effort to pragmatically contribute to a better understanding of current cybernetic threats, to foster the development of better defence mechanisms, and towards a generally safer cyberspace.

Challenges: Privacy is hard to quantify, as is the utility of empirical research. Both variables are dynamic and lack


normative understanding among domain professionals. Our understanding follows peer researchers in the sense that IBR or darknet traffic essentially contains non-productive, malicious, often artificially generated network packets. This is debatable, but supported by the literature.

Sharing Risks and Benefits: The framework proposes the addressing of three key questions to balance risks and benefits

in this type of research:

- Who is at risk when network data is shared? This refers to persons and their PII (personally identifiable information). ISO 27018 [53] defines PII as any information, such as name, social security number, physical and email addresses, certain biometric markers, which can be used to establish a link between the information and a natural person. Benign network traffic may contain PII, whereas malicious traffic is unlikely to contain such sensitive data;

- Which traffic data components are privacy-relevant? This splits into first-order and second-order identifiers. The former refers to data that functionally distinguishes an individual: first and last name, social security num- ber, government-issued and other account identifiers, physical and email addresses, certain biometric markers, and possibly the same information about immediate family. The latter refers to an IP address (IPA), machine access code (MAC) address, host name, birthdate, phone number, zip code, gender, and financial, health, or geographic information; and

- Under what conditions do these data types pose risk? Network traffic measurement data can present a privacy risk when information in packets can directly expose non-public information about persons - such as health, sexual orientation, political affiliation, religious affiliation, criminal activity, associations, behavioural activities, physical or virtual location.

The passive-only nature of the experiment constrains the ability to obtain personally identifiable data from the companion dataset. The enrichment procedure used in our intelligence extraction data pipeline is limited to the use of Open Source Intelligence libraries and APIs, enabling for some second-order identifiers, notably, the source and destination countries, obtained with libgeoip and the targeted AWS region, with the awsregions Python module. All results discussed ahead are aggregated by a high-level filter, such as by Country, or by AWS Region. There is no linking-back to any form offirst-order attribute that can identify an individual or company, or region of the world in closer detail.

## C. RESULTING DATASET

A characterisation of the resulting dataset, available on IEEE Dataport at [54], is summarised in Table 5. The experiment resulted in a total amount of530million unsolicited incoming network events, of which 425 million were TCP, 86 million consisted of ICMP packets, and 18 million UDP messages.

*TABLE 5. Protocol distribution.*

*TABLE 6. Unique radiation sources and destinations.*

The daily distribution of arriving packets behaved as depicted in Figure 16. On 8 November there was a peak of 6,721,467 incoming packets. The average packet count was of 3,515,992 events per day. The lowest daily packet count was seen on 19 December, with only 1,263,286 events.

*FIGURE 16. Temporal traffic distribution.*

The fact the majority of the captured traffic belongs to TCP indicates a prevalence of infection-oriented attacks, in which the attacking sources aim at finding vulnerable software running on probed targets, either with harmless intent, such as performed by benign scanners, including Censys and Shodan, or for malicious purposes, which is more prevalent and further discussed. This behaviour opposes service exhaustion oriented attacks, such as ping flooding, denial-of-service and amplification attacks, which usually exploit ICMP and UDP- based traffic. One hypothesis to justify this situation is that infection-oriented attacks are effective against any vulnerable target, whereas service-exhaustion attacks usually aim at specific address blocks belonging to each target companies, preventing a telescope placed elsewhere from capturing such events.

Table 6 shows the number of unique IP source and target addresses observed during the deployment phase of the experiment.

A total amount of1.8million different IP sources generated at least one network event against one or more cloud telescope sensor fleet instances. The number corresponds to 0.04% of IPv4’s theoretical 232 addressable space. EC2- based virtual machines had to recycle their IP addresses so many times that the diversity of observed IP destinations accounted 3.4 thousand distinct target addresses, 130 at any given time.


*TABLE 7. Most active radiation sources (Country).*

| Rank | United States | | Country | Count | | 31.88 | % |
| --- | --- | --- | --- | --- | --- |
| T |   |   | 51570308 | |   |   |
| 2 | China | | United Kingdom |   |   | 9.71 |
| 3 |   | Bulgaria | 37,510,860 | 8.86 |   |
| 4 |   |   |   | 7.07 |   |
| 5 |   | The Netherlands | 36,744,264 | 6.92 |   |
| 6 |   |   | Russia | 31,869,718 | 6.00 |   |
| 7 |   | Singapore | 29,909,254 | 5.63 |   |
| 8 |   | Germany | 29,267,184 |   | 5.51 |
| 9 | Indonesia | |   | 13,180,679 | 248 |   |
| 10 |   | Hong Kong | 10,005,851 |   | 1.88 |
| 11 |   |   | 7,268,133 6,420,366 |   | 1.37 |
| 12 |   | South Africa |   |   | 121 |
| 13 |   | India | 5.623.995 |   | 1.06 |
| 14 |   | Ireland | 5,167,944 | 0.97 |   |
| 15 |   | Romania | 5,013,302 | 0.94 |   |
| 16 |   | France | 4,808,674 |   | 0.91 |
| 17 |   | Australia | 4,130,374 | 0.78 |   |
| 18 |   | South Korea Brazil | 3,699,848 | 0.70 |   |
| 19 |   |   | 3.325.202 | 0.63 |   |
| 20 |   | Belgium | 2,209,498 | 042 |   |
|   |   | Sub-total | 504,038,771 | |   | 94.94 |   |
|   |   |   |   | Total | 530,914,922 | 100.00 |   |

## D. RADIATION SOURCES

The approach used to report radiation sources follows the method typically employed in related studies. The result series presented in this section is comprised of the twenty most active radiation source countries, followed by the most active sources propagating TCP-based traffic, UDP radiation sources, and ICMP radiation origins.

Table 7 shows that a total amount of 169 million network events had the United States of America as the radiation source. This corresponds to almost a third of the entire dataset. The United Kingdom came second, with almost 10%. China, Bulgaria, The Netherlands, Russia, Singapore and Germany were the source of at least 5% of the packets each. Indonesia, Hong Kong, Japan, South Africa and India contributed with 1%-2.5% of the incoming traffic. Other source countries were detected only by smaller fractions R < 1%.

A visual representation of the most active radiation sources, highlighting the ones that generated more than 30 million packets, is illustrated in Figure 17.

*FIGURE 17. Top radiation sources.*

*TABLE 8. Most prevalent TCP radiation sources.*

| Rank | United States | 150,732,082 | 35.41 | Country | Count | % |
| --- | --- | --- | --- | --- |
| T |   |   | | United Kingdom | 48,695027 | |   |
| 2 |   | Bulgaria | |   | 1144 |
| 3 |   |   |   | 8.80 |
| 4 |   | The Netherlands | 36,157,740 | 8.49 |
| 5 |   | Russia | 31,502,161 | 7.40 |
| 6 | 6.55 | Germany | | 27,881,298 |   |
| 7 | 331 | China | 14,079,601 |   |
| 8 | 3.15 | Singapore | 13,419,307 |   |
| 9 |   | Hong Kong | 6,671,238 | 1.57 |
| 10 |   | South Africa | 6,327,190 | 1.49 |
| 11 | 1.17 | Ireland | 4,997,185 |   |
| 12 |   | Romania | 4,965,994 | 117 |
| 13 |   | India |   | 1.02 |
| 14 | 1.01 | Japan France | 4,307,954 |   |
| 15 | 1.01 | Australia | 4,291,378 |   |
| 16 | 0.75 |   | 3.212286 |   |
| 17 | 0.73 | Brazil | 3,121,154 |   |
| 18 | 0.61 | South Korea | 2,594,847 |   |
| 19 |   | Belgium |   | 0.50 |
| 20 |   | Lithuania | 1,998,886 | 0.47 |
|   | 96.05 | Sub-total | 408,865,738 | |   |   |
|   |   |   |   | Total | 425,674,635 | 100.00 |

## 1) TCP RADIATION SOURCES

TCP radiation, which constitutes the largest portion of all observed traffic, is ranked in Table 8. The twenty most prevalent sources account for 96% of this traffic.

The United States alone originated slightly more than one third (35%) of all TCP radiation. The United Kingdom was second, with 11%, followed by Bulgaria, The Netherlands, Russia, and Germany also contributed with significant amounts of collected radiation.

Figure 18 contains a heat map summarising the most active TCP radiation sources in proportion to the amount of traffic originated by each country.

*FIGURE 18. TCP radiation source countries.*

## 2) UDP RADIATION SOURCES

UDP traffic accounted for approximately 19 million events. 94% of which concentrated on the twenty most active radiation generators, as summarised in Table 9.

The United States of America is the source country for more than half of all UDP radiation, 10 million packets,


*TABLE 9. Most prevalent UDP radiation sources.*

| Rank | United States | 10,509,012 | | Country | Count | % |
| --- | --- | --- | --- | --- |
| T 2 | United Kingdom | | 1715522 | |   |   | 55.36 |
|   | 818985 | |   |   | 9.04 |
| 3 | 652,682 | | ina |   | 4.31 |
| 4 |   | Sweden 5 | The Netherlands |   | 3.44 501429 | 2.64 |
| 6 |   | France | 395.117 | | 2.08 |
| 7 | 335084 | | Germany Malaysia | 346,891 | 183 |
| 8 |   |   | 313,142 | | 177 |
| 9 | 204493 | | Singapore Russia |   | 165 |
| 10 | 268,899 | |   |   | 1.55 |
| 1 | 248886 | | Hong Kong |   | 1.42 |
| 12 | 248287 | | Japan |   | 131 |
| 13 | 229352 | | Thailand Philippines |   | 131 |
| 14 |   |   |   | 121 |
| 15 | 201.809 | | Indonesia | 203.811 | 1.07 |
| 16 | 178807 | | Canada |   | 1.06 |
| 17 | 178330 | | India |   | 094 |
| 18 | 141.838 | | Poland Brazil |   | 094 |
| 19 | 126749 | |   |   | 075 |
| 20 | | | Taiwan Sub-total | |   | 0.67 |
|   |   |   |   | 94.34 Total | 18982971 | 100.00 |

or 55%. The United Kindgom is the second most prevalent radiation generator, 1.7 million events, or 9%. China, Sweden and The Netherlands have also generated at least half a million packets, contributing each with 2 to 4% of all seen UDP datagrams.

Figure 19 depicts traffic distribution on a world map. Darker regions indicate packet counts of up to 10 million events being generated on a highlighted location.

*FIGURE 19. UDP radiation source countries.*

## 3) ICMP RADIATION SOURCES

ICMP traffic accounted 86 million network events. The ranking containing the twenty most active ICMP radiation sources is summarised in Table 10.

China generated more than one third of this radiation type, 37% of the packets, followed by Singapore, with 18% and Indonesia, 13%. The United States of Amer- ica were fourth, with 9%, followed by Hong Kong and Japan, with 3% each. Figure 20 illustrates the result- ing heat map revealing some concentration in eastern countries.

*TABLE 10. Most prevalent ICMP radiation sources.*

| Rank | Country | Count | % |
| --- | --- | --- | --- |
|   | China | 32.165.142 | |   | 37.34 |
| T | Singapore | 16,176,805 | |   |   |
| 2 |   |   | 18.78 |
| 3 | United States | | Indonesia | 11,609,410 8.006679 | | 13.48 |
| 4 |   | Hong Kong | 3.065714 | | 9.29 |
| 5 |   |   | 3.56 |
| 6 | Japan Malaysia | | 2,711,230 1294291 | | 31s |
| 7 | Philippines | | 1225954 | | 1.50 |
| 8 |   |   | 1.42 |
| 9 | Thailand | 1,186,495 | 1.38 |
| 10 | United Kingdom India | | 1.159.757 100.040 | | 1.35 |
| 11 |   |   | 128 |
| 12 | Germany | 1,038,961 | 1.21 |
| 13 | South Korea Australia | | 1.005.728 819.998 | | 1.17 |
| 14 |   |   | 0.95 |
| 15 | United Arab Emirates | 542,462 | 0.63 |
| 16 | wdi Arabia | 288.877 191464 | | 0.34 |
| 17 | Sweden | 173.846 | | 0.22 |
| 18 | Vietnam |   | 0.20 |
| 19 | Taiwan Ireland | 159.836 130207 | | 0.19 |
| 20 |   |   | 0.15 |
|   |   | Sub-total | 84,052,896 | 97.58 “Total | 86.139.655 | 100.00 |

*FIGURE 20. ICMP radiation source countries.*

## E. RADIATION TARGETS

We initially report radiation target distribution using similar aggregations than seen in related works. The TCP-centric analysis allows to focus not only on the most frequently probed TCP destination ports, but also towards a characterisa- tion of the most commonly exploited vulnerabilities linked to each port, and in terms of investigating the most commonly used protocol flag combinations as recorded by the sensor fleet. UDP radiation is also ranked by the most probed destination port, whereas the ICMP protocol is grouped the most frequently seen message types.

## 1) MOST PROBED TCP PORTS

Probing activity using the Transmission Control Protocol aimed the list of destination ports as ranked in Table 11.

The most targeted TCP port was 23, the Telnet application port. Sensors recorded more than nine million events of this type, corresponding to 2.2% of the capture sample. HTTP, on port 80 was second, with 8 million events, or 1.8%. This prevalence follows the same behaviour as our


*TABLE 11. Most probed TCP destination ports.*

*TABLE 12. CVEs linked to malware propagation on Port 23.*

previous, active, honeypot-enabled experiment, documented in [13]. Telnet and HTTP are intensely probed as part of botnet propagation patterns. Mirai, in particular, frequently exploits these two ports looking to find insecure, Busybox- based, embedded Linux software stacks. Mitre’s Common Vulnerabilities and Exposures entries presented in Table 12 motivate most attacks.

Mirai, Mozi, and Sora variants exploit a vulnerability where unauthenticated web-shell access can be obtained within a range of IoT IP Cameras. The Kinsing variant exploits the vulnerability documented in CVE-2020-20601, related to remote code execution against a PHP-based Content Management System, ThinkCMS, widely adopted in China. Mirai also exploits the more recent vulnerability documented on CVE-2022-40475, which enables unauthen- ticated command injection in a range ofTotolink branded IoT devices.

The trends observed on this experiment match and reinforces the findings of [29], in which they have perceived a quantitative radiation pattern shift, from malware-propagation aiming at ordinary server-based operat- ing systems, such as Windows Server and Linux, towards the exploitation ofmore abundant, billion-device scale, low-cost, low-power, fast-time-to-market Internet-of-Things devices, which, by their very nature, cannot afford to implement robust security mechanisms. Researchers in [55] characterise Mirai as the central actor in an ongoing battle over the

IoT, while [56] provides an a updated discussion of Mirai’s propagation patterns.

TCP ports 10000, 10001, and 10002 accounted ≈ 5 million events each. IANA assigned port 10000 to ‘‘Network Data Management Protocol’’, however at least 22 distinct application-layer services are implemented on this port [57], including open source tools, such as the PHP-based interface Webmin, backup-related agent Veritas Remote Execution Client, and a range of backdoor access software implemented by some malware.

Port 10001 is linked to eight different uses [58], including the live-streaming service of a range of IP cameras, Veeam Agent, some game servers, and a couple of backdoor-based malware. Port 10002 follows the same pattern.

Port 443 implements the well-known HTTPS service. Unsolicited traffic arriving at it is often benign, includes IP sources traceable to Censys and Shodan, plus AWS’s health checks as part of their cloud monitoring services. Remainder traffic, N < 1%, include widely adopted services, such as Microsoft’s Remote Desktop Protocol (3389), and the Common Internet File System - Server Message Block (CIFS/SMB) at 445.

## 2) TCP FLAG COMBINATION ANALYSIS

TCP flags, as documented on RFC 793 [59], allow the differentiation of many states of a controlled trans- mission, including its beginning, with the SYN flag, acknowledgement, with SYN and ACK flags enabled, trans- mission, with ACK, re-transmission requests, with RST, and connection termination, combining FIN and ACK flags.

Internet Background Radiation often contains malformed and malicious TCP flag combinations, usually aiming at firewall evasion, service exhaustion, or unexpected flag combination, hoping the target stack will halt due to poor, strict or unhardened flag handling.

Table 13 shows flag combinations of received TCP datagrams. The flag array is depicted using the dotted format, inherited from PCAP and decoded by TShark, masked as RRRNCEUAPRSF. From right to left, RFC 793 defines the original 6 TCP flags. RFC 3168 [60] introduced the ECN-Echo and Congestion Window Reduced flags. RFC 3540 [61] introduced the Nonce Sum flag. The remaining three bits of the TCP flags field are still marked as Reserved.

The vast majority of traffic, 82%, refer to SYN requests, which is the standard behaviour for any new incoming datagrams. Transmission reset requests, accounting to 17%, can be related to either reset-centric port scanning, or to backscatter, where radiation sensors collect reflected traffic generated by victim’s server IP, in response to attack packets with forged source IP addresses. Few packets, N < 05%, exploited a range of unexpected and odd flag combinations, including ACK+SYN, used for ongoing data exchange (0.36%) and CWE+ECE+SYN used to initiate


*TABLE 13. Most used TCP flag combinations.*

a congestion window negotiation (0.28%). Transit of the ACK flag alone, Christmas tree scan, UAPRSF, and null scan (empty flags), were also captured in very small quantities.

## 3) MOST PROBED UDP PORTS

UDP is described as a connection-less transport-layer protocol on RFC [62]. The UDP portion of Internet Background Radiation helps to understand attack types unrelated to typical system intrusion, either linked to service exhaustion, that is, denial-of-service attacks, or amplification, the situation where a vulnerable, intermediate service is used as a proxy to generate more traffic towards the final target than initially sent by the attacker to the proxy itself [63].

The twenty most probed UDP ports are ranked in Table 14. This ranking accounts for just less than a third of the entire UDP packet count, 30%, suggesting a higher diversity of probing and attacking patterns.

UDP-based traffic was diverse. 5.91% of the packets aimed at port 5100. This is used by a range of services, including Avaya’s VoIP/PBX ‘‘Communication Server 1000’’, regis- tered within IANA as socalia. SANS Internet Storm Centre reveals the port has had a surge in exploitation activity starting late 2019 [64]. Port 5060 (2.91%) is officially registered as the standard Session Initiation Protocol - SIP, the VoIP port. VoIP implementations, such as in Asterisk, Microsoft Lync, Cisco IOS and Siemens Openstage/Gigaset are vulnerable to a range of exploits widely available on the Internet. The DNS port, 53, was the target in 2.81% of cases. DNS implementations, such as widely-adopted BIND, released by the Internet Software Consortium, ISC, contains multiple critical vulnerabilities. Since 2020, 44 CVE entries

*TABLE 14. Top 20 UDP destination ports.*

have been published reporting situations where BIND can be remotely exploited [65] with publicly available code. Network Time Protocol - NTP exploitation came fourth, with 2.16% of the collected radiation. Implementations of this protocol were subject to a spike of 29 disclosed vulnerabilities around 2017, 19 out of which relate to input validation, and 10 to buffer and heap overflow situations [65]. NTP is widely used by attackers as a vector to achieve amplification [66]. Other interesting cases are port 9993 (2.12%) linked to the Zero Tier service and network encapsulation stack, 161, the Simple Network Management Protocol port, 1900, used by SSDP/UPnP (Simple Service Discovery Protocol - Universal Plug-and-Play protocol) to enable automatic local service discovery, 5353, related to Multicast DNS, and 1434, the Microsoft SQL Server, where the UDP port provides service management to that database software.

## 4) MOST FREQUENT ICMP MESSAGES

ICMP message exchange from probing sources towards the sensor fleet can be explained as a) malicious motivation when a host scanner must first determine whenever a target IP address is live, b) part of target operating system finger- printing attempt, c) part of a multi-protocol denial-of-service attack, or d) ping-based host monitoring misconfiguration; among other reasons.

A basic account of arriving Internet Control Message Protocol - ICMP is presented in Table 15.

Captured radiation contains 5 distinct ICMP message types. The vast majority refers to ICMP echo request, type 8, as initiated by the ping command. This was the case in 94% of the sample. ICMP echo response, type 0, usually implemented as a response to a ping request, was seen in 5% of the cases. Network and Cloud telescopes are configured


*TABLE 15. Top 5 ICMP message types.*

to never issue a ping request, therefore the arrival of a response is unsolicited, and could be a result of a packet forgery attempt conducted by an attacker using the sensor’s IP address as a response destination. ICMP types 13 ‘‘timestamp request’’, 17 ‘‘address mask request’’ and 1 ‘‘destination host unreachable’’ were occasionally captured.

## F. DISTRIBUTED ANALYSIS

The distributed architecture of the Cloud Telescope provides an opportunity to investigate how traffic dispersion affects different countries in the world. Therefore, this subsection quantifies how each country hosting a share of capture sensors was hit by overall traffic, followed by a breakdown of TCP, UDP and ICMP network events. In each case, not only a country-level aggregation, but a Cloud Region aggregation is provided to compensate the existence ofmore than one Cloud Region in a single country, most notably, the United States of America.

Country-level aggregations are capped at the twenty most affected targets to preserve consistency across all result reported, resulting in a Top 20 ranking for each aggregation. Cloud Region accounting, on the other hand, follows the number of effective experimented AWS points of presence: 26, therefore, tables provide an absolute dispersion accounting, N = 100%.

## 1) OVERALL TRAFFIC DISPERSION

Overall traffic dispersion is accounted for the twenty most affected countries in Table 16. This is regardless of any network layer or transport layer property. The listed countries answer together for 518 million network events, 97% of the total captured amount.

The United States of America is covered with four distinct cloud regions and, as such, was assigned four times the number ofbaseline sensors deployable in each region, 4 cloud regions × 5 sensors per region = 20 sensors. The USA was targeted by 84 million network events, corresponding to 15% of all traffic.

The country-level analysis points out Bahrain as the second most affected country, standing as target for 44 million events, or 8% of the entire dataset. Indonesia figures in third position, being the target of 36 million packets, or 6% of the volume. Japan also received a share of 6% of all traffic, followed by India, with 32 million, Singapore, 29 million, and South Korea, with 22 million. Hong Kong was hit by 21 million packets, while Sweden and France were the last

*TABLE 16. Top 20 radiation target countries.*

countries receiving at least 20 million packets each. All remainder countries in the list were hit with at least 14 million packets each.

The heat map in Figure 21 depicts the same twenty countries, highlighting the five most affected nations.

*FIGURE 21. Top radiation destinations.*

To neutralise the influence of countries containing more than one cloud region, consider the radiation distribution individually arriving to each of the twenty-six AWS Cloud Regions, as accounted in Table 17.

This perspective reveals that me-south-1, Bahrain, figures as the most targeted country, with 8% of the traffic, followed by ap-southeast-3, Indonesia, with 6%. us-west-1, in the USA, figures only as the third most affected individual Cloud Region, with 5.91% of the received packets.

Radiation normalization indicates that the theoretical average radiation distribution per Cloud Region should be R = 126 = 38%. AWS regions hit above the baseline average also include ap-southeast-1 (5%), ap-northeast-2 (4%), ap-east-1 (4%), and eu-north-1 (3.82%). On the other


*TABLE 17. Traffic dispersion per cloud region.*

hand, the least targeted region was sa-east-1, with only 2.41% of the captured events.

Despite the discrepancies, radiation distribution can be considered fairly even, with a median of med(R) = 336 and standard deviation of dev(R) = 135.

## 2) TCP RADIATION: TARGET COUNTRIES

The TCP-based radiation accounted for 425 million network events, as summarised in Table 18. The ranking of the twenty most affect nations corresponded to 97% of cases, revealing interesting concentration patterns.

The country-level aggregation confirms that the USA as a preferred destination to 72 million TCP events, or 17% of this traffic type, followed by Japan, hit by 31 million events, or 7%, India, with 28 million events, or 6%, and Singapore, with 23 million events, or 5%. Hong Kong was the last nation to be hit by at least 20 million packets.

The heat map in Figure 22 provides a gradient-based colouring scheme denoting the extent to which each country is affected by TCP-based radiation.

## 3) TCP RADIATION: TARGET CLOUD REGIONS

TCP event aggregation as arriving to each individual Cloud Region is accounted for in Table 19. This perspective reveals a fair radiation distribution across each of the twenty-six AWS locations.

This aggregation reveals that not only the United States of America figures first because it contains four cloud regions, but also because it hosts us-west-1, the most individually targeted one, with 25 million TCP events, or almost 6% of the captured sample. ap-southeast-1 closely follows, with

*TABLE 18. TCP radiation: target countries.*

*FIGURE 22. TCP radiation: target countries.*

23 million packets, or 5.5% of the cases. Regions affected above the baseline average also include ap-east-1, 20 million events, or 4.8%, ap-northeast-2, with 18 million events, or 4.4%, eu-north-1, eu-west-3, eu-central-2, eu-west-2, and

eu-central-1, with 17 million packet events each, or ≈ 4%, followed by ap-northeast-1, us-west-2, eu-west-1, ca-central- 1, and us-east-1, each seeing 3.72%-3.98% of all TCP-based traffic.

## 4) UDP RADIATION: TARGET COUNTRIES

The relatively small UDP packet count captured in this experiment is listed in Table 20. The list containing the twenty most affected countries represent 98% of all UDP events. Concentration is significantly biased towards the first five nations.

US-based IP addresses received more than one third of all UDP-based radiation. 6.5 million network events, or 34% of the subset. Japan was hit by 1.7 million UDP datagrams, or 9% of this traffic type. India was the last country to account at least 1 million network events, comprising 7% of the cases.


*TABLE 19. TCP radiation: target cloud regions.*

*TABLE 20. UDP radiation: target countries.*

Other relevant targets include Sweden, with 5% of the load, South Africa, 4%, and Singapore, 3.9%, or 730 thousand datagrams.

The heat map in Figure 23 summarises UDP radiation destinations, highlighting the most targeted countries.

## 5) UDP RADIATION: TARGET CLOUD REGIONS

The cloud-region-centric analysis ofUDP events is supported by the accounting provided in Table 21.

*FIGURE 23. UDP radiation: target countries.*

*TABLE 21. UDP radiation: target cloud regions.*

This perspective reveals that one single US based cloud region, us-west-1, was the preferred target. Alone, it was targeted by 27% of the radiation. ap-northeast-3 comes second, with 1.2 million network events, or 6% of the cases. eu-north-1, ap-south-1, and ap-southeast-1 were also hit with a percentage higher than the baseline average, ranging from 3.90 to 5.23% of the UDP-based traffic load.

A query on the dataset, aiming to raise the most prevalent sources to justify this particular aggregation, revealed that UDP-based traffic towards us-west-1 had the USA itself as the most prevalent attacking source.

## 6) ICMP RADIATION: TARGET COUNTRIES

Table 22 ranks the twenty targets most affected by ICMP events. The list answers for 99% of all seen ICMP radiation, revealing a high concentration of two countries as the target of more than half of the packet load.


*TABLE 22. ICMP radiation: target countries.*

Bahrain received one third of all captured ICMP traffic, almost 30 million events, or 34% of this event type, followed by Indonesia, with 21million packets, 24%of the ICMP load. Singapore-based sensors captured 5% of this traffic type, 5 million packets, closely followed by the United States, with a similar amount.

The corresponding heat map, depicted in Figure 24, reveals the ICMP traffic dispersion across the most targeted countries, highlighting the three most prevalent destinations.

*FIGURE 24. ICMP radiation: target countries.*

## 7) ICMP RADIATION: TARGET CLOUD REGIONS

The cloud-region-based analysis of ICMP events reinforces the country-level aggregation, as shown in Table 23.

me-south-1 was hit by almost 30 million ICMP packets during the capture, contributing alone with a third of the total load seen for network-layer probing activity. Sensors placed

in this region were hit by a total amount of ≈ 44 million packets, indicating that ICMP Type 8, echo request, alone, corresponds to two thirds, or 67% of all seen traffic towards thismiddle-east country. This drifts considerably fromtypical

*TABLE 23. ICMP radiation: target cloud regions.*

TCP-centric dispersion as the average case (as shown in Table 5). The origin of the ping-like activity traces back to

China in 40% of the cases (≈ 11 million events), followed by Singapore, with 6.2 million packets or 21%, and the United States of America, with 2.5 million, or 8%.

Region ap-southeast-3, was also hit by a large number of ICMP packets, 21 million, representing one fourth of the cases. Considering the total number of 36 million events arriving into that region, ICMP alone corresponded to almost 60% of all incoming packets. Traffic traces back to the same

three countries, in order: ≈ 9 million echo requests came from China (42%), while 4 million came from Singapore (20%), followed by US-based IP sources: 1.8 million, or 8%.

Cloud region ap-southeast-3, Singapore, ranking third, showed a behaviour aligned with the average case. ICMP answered for only 17% of the packets, against 80% TCP. Ping-like activity mostly came from Indonesia (26%), followed by China, with 19%. ap-northeast-2, in Korea, in fourth, obtained similar results, where only 13% of the traffic belonged to ICMP, 70% out of which coming from Singapore.

## V. DISCUSSION

A direct comparison of captured events performed by the Cloud Telescope against standard Network Telescopes is possible in some key aspects, including the total number of network packets arriving to each IP address per day, port number aggregation, and the most frequently seen probing/attacking sources.


As a baseline consider the number of captured network events, per day, per allocated IP address as summarised in Figure 25:

*FIGURE 25. Hourly network events per IP address.*

In 2011, [2] captured 40 million events in 50 months on a /24 subnet, hence 1,1 thousand network packets per day, per IP address. Ten years later, [32] saw 80 billion packets arriving to 8,192 addresses during 42 months, or 7,7 thousand network packets per day, per IP address. [33] reports the collection of 2 million packets for a single IP address during their four-month-long experiment, or 16 thousand network packets per day. The Cloud Telescope captured 27 thousand packets per day, per allocated IP address. One fair conclusion is that radiation emission seems to grow as Internet’s adoption expands across the world.

The Cloud Telescope had TCP as the most exploited transport-layer protocol, with 80% prevalence. This result aligns with [2]. who reported 81% of TCP dominance, [32], with 94%, and [33], with 89%.

TCP-based port aggregation reveals that the Cloud Tele- scope had the Telnet port as the most actively probed, followed by other well-known Internet services ranking high, including HTTP, SSH, HTTPS, and others. The pattern is very similar to the one seen in related works: [32] reports SSH (22) and Telnet (23) as the two most affected ports, followed by HTTP (80) and HTTPS (443). [34] reports 22, 23, and 80 as the top three. [33] reports 23, 22 and 445. Mirai infection attempts is commonly reported as the main cause. On the other hand, the Cloud Telescope was the only reporting high prevalence of traffic destined to the triplet formed by ports 10000-10001-10002 as the third, fourth and fifth most exploited TCP services, may reflect a focused interest on malware-based backdoor access generally affecting cloud-based service stacks, and may require detailed investigation.

UDP prevalence was of 12% in [2]. Top destination ports contained sql-server related 1434, along with Windows RPC-based services on ports 137 and 135. [32] reported 5% UDP traffic, highlighting SIP (5060) as the most prevalent. [33] does not provide an UDP port breakdown, but references the DNS protocol (53). The Cloud Telescope had 3.58% of the captured packets belonging to UDP, including the SIP protocol, followed by DNS. Windows RPC-based services also ranked high when using the distributed method.

ICMP was captured in lesser amounts in all compara- ble cases. The Cloud Telescope essentially captured echo requests (95%), while [2] had a fair dispersion of types 8 (62%), 3 (24%) and 11 (12%). [32] and [33] reported > 1% of ICMP traffic.

The geographically distributed nature of the Cloud Tele- scope has allowed for new forms of data aggregation, includ- ing target-country-centric and target-cloud-centric protocol breakdowns. Geopolitical influence motivating radiation generation and radiation targeting can be speculated and will deserve a detailed investigation, in particular, related to the findings where the United States of America figured as a top target for TCP attacks, followed by a range of cloud regions notably located in Asia and The Pacific, UDP radiation was significantly more prevalent towards a single cloud region: us-west-1, and ICMP radiation had China as the most prevalent source, while highly concentrated towards Bahrain and Indonesia. These should deserve a future investigation, in terms of determining the causal relationship, conjectural geopolitical motivation, extrapolation of the initial findings and new Cloud Telescope deployments to compare and contrast.

## A. BENEFITS OF THE CLOUD TELESCOPE

One understanding is that the distributed approach imple- mented by a cloud-backed telescope, as demonstrated on this study, offers unique advantages as a method for cyber threat intelligence acquisition:

- Improved coverage. The Cloud Telescope captured radiation from multiple points across the Internet, enabling for increased likelihood of capturing emerging threats, or malicious activity targeting particular coun- tries or regions of the world;

- Scalability. The telescope’s aperture can be easily scaled up or down based on needs, and can be focused on countries of interest, constraints being the existence of a cloud region, and costs associated with the operation;

- Flexibility. Findings of one experiment can help shape the behaviour of an upcoming deployment, particularly in terms of easily implementing active responders on selected ports to capture specific malware propagation behaviour;

- Early detection. The architecture can be deployed as a permanent capture mechanism and used as an input to feed intrusion detectors that could flag the rise of new threats early.

- Correlation of threats. Analysing IBR data targeting multiple destinations allows for the correlation of threat activities across different networks and geographic regions, potentially revealing coordinated attack cam- paigns;

- Improved threat actor profiling. By learning how radi- ation affects different regions of the world, researchers can speculate their motivation, tactics, techniques and


procedures, which can foster better, geopolitical-aware countermeasures and defence mechanisms;

- Long-term analyses. Longitudinal studies can help understand cyber threat evolution, trend shifts, and attack pattern tracking as malware evolve over time.

## VI. CONCLUSION

This paper introduced the Cloud Telescope as an ephemeral, distributed, cloud-native architecture for collecting Internet Background Radiation. The updated characterisation of radiation contents denotes the inception of internet-wide host and port scanners as a relevant benign component, which certainly deserves closer attention in terms of traffic overhead and, more importantly, regarding the implications of companies publishing internet-wide vulnerability data, as- a-service, on easily browsable, API-enabled, web interfaces. Regarding the malicious nature of the vast majority of the captured events, our experiment confirms the shift from malware-centric attacks targeting classic server stacks, such as Intel and Linux or Windows Server hosts, towards the low-power, low-cost, fast time-to-market Internet-of- Things devices, which, as a general rule, do not implement robust software update mechanisms to compensate for the weaknesses inherent to their design. Thus, we can deduce that attackers have been finding it easier to build zombie fleets comprised of numerous limited-power devices rather than a small number ofmore powerful servers, potentially indicating that the default-enabled software update mechanisms of modern server operating systems have been working in acceptable parameters. Exceptions exist, such as when using these servers as amplifiers to direct denial-of-service attacks against final targets. Amplification is becoming more abundant in radiation samples as vulnerability researchers responsibly disclose their existence in public information repositories.

Related works were extensively documented in order to provide a fair, reproducible recap of the radiation capture and analysis field. Seminal works set the stage and tone for what can be learnt from Network Telescope deployments, while snowballed works delve into the details of certain malware propagation, IoT-centric exploitation and the need for developing smaller aperture methods due to IPv4 scarcity. Studies configuring the current state-of-the-art IBR analysis explore the prediction of future events using artificial intelligence, geopolitics applicable to single regions of the world, and detailed studies focusing on the particularities of botnet propagation.

This scenario, in combination with what can be accom- plished with the support of Cloud Computing, resulted in what we defined as the Cloud Telescope. We have used a basic set of software engineering artefacts to explain what is expected from this capturing mechanism, trust- ing the functional and non-functional terminology can be understood, adapted, and adopted by any research group willing to conduct similar observations. The openly-available

provided Terraform implementation also contributes towards this particular research goal.

The long-term analysis documented in this paper confirms that radiation affecting a cloud-based, geographically dis- tributed fleet of capturing sensors tends to get most probed with TCP traffic, followed by UDP or ICMP traffic only to a smaller extent. Traffic distribution and protocol breakdown confirm the patterns found during our previous proof-of- concept experiments as well as those published by peers in recent years. There is a firm consensus that the Telnet service port configures the most targeted service port. Attack patterns point towards IoT-related, 32-bit embedded Linux implementations more than any other architecture or software stack.

Determining geopolitical patterns behind radiation gen- eration is a challenging task. We were able to capture and reveal some interesting patterns during the provided protocol breakdown analysis. The analysis of top radiation sources and targets attempted to shed some light on this influence, but no definitive conclusion can be drawn for the data discussed here. An attempt to focus only on the wealthiest nations in the world could indicate that the United States ofAmerica stands both as amajor radiation generator and radiation target. China is behind a large fraction of all captured ICMP radiation, while the United Kingdom ranks high in most analyses. On a different front, The Netherlands seems to host a range of anonymization services of choice for many attackers. All these deserve detailed and careful investigation before more consistent conclusions are drawn.

## A. FUTURE WORK

We envisage a series of future studies unfolding from the cloud telescope as a proposed mechanism for distributed Internet Background Radiation acquisition. The plan will expand across four main fields of interest.

## 1) CAPTURE REPRODUCTION AND EXPANSION

The Cloud Telescope can be expanded in manyways. In terms of magnitude, it can be launched with an increased IP address count attached to an expanded AWS EC2 fleet. It can be deployed onto cloud regions just recently announced, including il-central-1, in Tel-Aviv, Israel, or upcoming ones, such as in Auckland, New Zealand. Expansion could also aim at greater capillarity by spreading the sensor fleet across a federated network of cloud providers, potentially including Microsoft Azure and Google Cloud a start.

Another form of expansion refers to the level of interaction implemented by the capture sensor. We tested customised medium-interaction honeypots running on selected ports, however, this feature could be expanded to other ports, dynamically selected upon the announcement of zero-day vulnerabilities in the Common Vulnerability and Exposures database, enabling first-hand access to intelligence acquisi- tion to emerging threats. Cloud costs and dataset volume must be carefully considered in this case.
