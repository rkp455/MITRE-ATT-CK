# Tactic - Reconnaissance - ID: TA0043

**Created:** 02 October 2020  
**Last Modified:** 18 October 2020

The adversary is trying to gather information they can use to plan future operations.Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or staff/personnel. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute Initial Access, to scope and prioritize post-compromise objectives, or to drive and lead further Reconnaissance efforts.

## Technique 

### Active Scanning - ID:T1595

Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.
Adversaries may perform different forms of active scanning depending on what information they seek to gather. These scans can also be performed in various ways, including using native features of network protocols such as ICMP.Information from these scans may reveal opportunities for other forms of reconnaissance (ex: Search Open Websites/Domains or Search Open Technical Databases), establishing operational resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial access (ex: External Remote Services or Exploit Public-Facing Application).

### Sub-technique of:  T1595

#### Active Scanning: Scanning IP Blocks - ID:T1595.001

Adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses.
Adversaries may scan IP blocks in order to Gather Victim Network Information, such as which IP addresses are actively in use as well as more detailed information about hosts assigned these addresses. Scans may range from simple pings to more nuanced scans that may reveal host software/versions via server banners or other network artifacts.Information from these scans may reveal opportunities for other forms of reconnaissance (ex: Search Open Websites/Domains or Search Open Technical Databases), establishing operational resources, and/or initial access.

#### Active Scanning: Vulnerability Scanning - ID:T1595.002

Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host or application potentially aligns with the target of a specific exploit the adversary may seek to use.
These scans may also include more broad attempts to Gather Victim Host Information that can be used to identify more commonly known, exploitable vulnerabilities. Vulnerability scans typically harvest running software and version numbers via server banners, listening ports, or other network artifacts.Information from these scans may reveal opportunities for other forms of reconnaissance (ex: Search Open Websites/Domains or Search Open Technical Databases), establishing operational resources, and/or initial access.

#### Active Scanning: Wordlist Scanning - ID:T1595.003

Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to Brute Force, its goal is the identification of content and infrastructure rather than the discovery of valid credentials. Wordlists used in these scans may contain generic, commonly used names and file extensions or terms specific to a particular software. Adversaries may also create custom, target-specific wordlists using data gathered from other Reconnaissance techniques.

For example, adversaries may use web content discovery tools such as Dirb, DirBuster, and GoBuster and generic or custom wordlists to enumerate a website’s pages and directories.[1] This can help them to discover old, vulnerable pages or hidden administrative portals that could become the target of further operations.

As cloud storage solutions typically use globally unique names, adversaries may also use target-specific wordlists and tools such as s3recon and GCPBucketBrute to enumerate public and private buckets on cloud infrastructure.Once storage objects are discovered, adversaries may leverage Data from Cloud Storage to access valuable information that can be exfiltrated or used to escalate privileges and move laterally.

### Gather Victim Host Information - ID:T1592

Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data as well as specifics regarding its configuration.
Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning or Phishing for Information. Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.[1] Information about hosts may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and or initial access.

### Sub-technique of:  T1592

#### Gather Victim Host Information: Hardware - ID: T1592.001

Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections.

Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning or Phishing for Information. Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.Information about the hardware infrastructure may also be exposed to adversaries via online or other accessible data sets . Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and or initial access.

#### Gather Victim Host Information: Software - ID:T1592.002

Adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections.
Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning (ex: listening ports, server banners, user agent strings) or Phishing for Information. Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.Information about the installed software may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and or for initial access .

#### Gather Victim Host Information: Firmware - ID:T1592.003

Adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more information about hosts in the environment.
Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about host firmware may only be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial access.

#### Gather Victim Host Information: Client Configurations - ID:T1592.004

Adversaries may gather information about the victim's client configurations that can be used during targeting. Information about client configurations may include a variety of details and settings, including operating system or version, virtualization, architecture, language, and or time zone.
Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning or Phishing for Information. Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.Information about the client configurations may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance , establishing operational resources, and initial access.

### Gather Victim Identity Information - ID:T1589

Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data  as well as sensitive details such as credentials or multi-factor authentication (MFA) configurations.Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about users could also be enumerated via other active means such as probing and analyzing responses from authentication services that may reveal valid usernames in a system or permitted MFA /methods associated with those usernames.Information about victims may also be exposed to adversaries via online or other accessible data sets.
Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources (ex: Compromise Accounts), and/or initial access.

### Sub-technique of:  T1589

#### Gather Victim Identity Information: Credentials - ID:T1589.001

Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts.
Adversaries may gather credentials from potential victims in various ways, such as direct elicitation via Phishing for Information. Adversaries may also compromise sites then add malicious content designed to collect website authentication cookies from visitors.Credential information may also be exposed to adversaries via leaks to online or other accessible data sets.Adversaries may also purchase credentials from dark web or other black-markets. Finally, where multi-factor authentication (MFA) based on out-of-band communications is in use, adversaries may compromise a service provider to gain access to MFA codes and one-time passwords (OTP).Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and or initial access.

#### Gather Victim Identity Information: Email Addresses - ID:T1589.002

Adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees.Adversaries may easily gather email addresses, since they may be readily available and exposed via online or other accessible data sets.Email addresses could also be enumerated via more active means, such as probing and analyzing responses from authentication services that may reveal valid usernames in a system.For example, adversaries may be able to enumerate email addresses in Office 365 environments by querying a variety of publicly available API endpoints, such as autodiscover and GetCredentialType.Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and or initial access.

#### Gather Victim Identity Information: Employee Names - ID: T1589.003

Adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures.Adversaries may easily gather employee names, since they may be readily available and exposed via online or other accessible data sets (ex: Social Media or Search Victim-Owned Websites).Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and or initial access.

### Gather Victim Network Information - ID:T1590

Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data as well as specifics regarding its topology and operations.

Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning or Phishing for Information. Information about networks may also be exposed to adversaries via online or other accessible data sets.Gathering this information may reveal opportunities for other forms of reconnaissance,establishing operational resources , and/or initial access.

### Sub-technique of:  T1590

#### Gather Victim Network Information: Domain Properties - ID:T1590.001

Adversaries may gather information about the victim's network domains that can be used during targeting. Information about domains and their properties may include a variety of details including what domains the victim owns as well as administrative data ex name, registrar, etc. and more directly actionable information such as contacts email addresses and phone numbers, business addresses, and name servers.

Adversaries may gather this information in various ways such as direct collection actions via Active Scanning or Phishing for Information. Information about victim domains and their properties may also be exposed to adversaries via online or other accessible data sets ex WHOIS. Where third-party cloud providers are in use, this information may also be exposed through publicly available API endpoints, such as GetUserRealm and autodiscover in Office 365 environments. Gathering this information may reveal opportunities for other forms of reconnaissance ex Search Open Technical Databases, Search Open Websites/Domains, or Phishing for Information, establishing operational resources ex Acquire Infrastructure or Compromise Infrastructure, and/or initial access ex Phishing.

#### Gather Victim Network Information: DNS - ID:T1590.002

Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. DNS, MX, TXT, and SPF records may also reveal the use of third party cloud and SaaS providers, such as Office 365, G Suite, Salesforce, or Zendesk.

Adversaries may gather this information in various ways such as querying or otherwise collecting details via DNS/Passive DNS. DNS information may also be exposed to adversaries via online or other accessible data sets ex Search Open Technical Databases.Gathering this information may reveal opportunities for other forms of reconnaissance ex Search Open Technical Databases, Search Open Websites/Domains, or Active Scanning, establishing operational resources ex Acquire Infrastructure or Compromise Infrastructure, and/or initial access ex External Remote Services.

#### Gather Victim Network Information: Network Trust Dependencies - ID:T1590.003

Adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details including second or third-party organizations/domains ex managed service providers, contractors, etc. that have connected and potentially elevated network access.

Adversaries may gather this information in various ways such as direct elicitation via Phishing for Information. Information about network trusts may also be exposed to adversaries via online or other accessible data sets ex Search Open Technical Databases.Gathering this information may reveal opportunities for other forms of reconnaissance ex Active Scanning or Search Open Websites/Domains, establishing operational resources ex Acquire Infrastructure or Compromise Infrastructure, and/or initial access ex Trusted Relationship.

#### Gather Victim Network Information: Network Topology - ID:T1590.004

Adversaries may gather information about the victim's network topology that can be used during targeting. Information about network topologies may include a variety of details including the physical and/or logical arrangement of both external-facing and internal network environments. This information may also include specifics regarding network devices gateways, routers, etc. and other infrastructure.

Adversaries may gather this information in various ways such as direct collection actions via Active Scanning or Phishing for Information. Information about network topologies may also be exposed to adversaries via online or other accessible data sets ex Search Victim-Owned Websites.Gathering this information may reveal opportunities for other forms of reconnaissance ex Search Open Technical Databases or Search Open Websites/Domains, establishing operational resources ex Acquire Infrastructure or Compromise Infrastructure, and/or initial access ex External Remote Services.

#### Gather Victim Network Information: IP Addresses - ID:T1590.005

Adversaries may gather the victim's IP addresses that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Information about assigned IP addresses may include a variety of details such as which IP addresses are in use. IP addresses may also enable an adversary to derive other details about a victim such as organizational size, physical location(s), Internet service provider, and or where/how their publicly-facing infrastructure is hosted.

Adversaries may gather this information in various ways such as direct collection actions via Active Scanning or Phishing for Information. Information about assigned IP addresses may also be exposed to adversaries via online or other accessible data sets ex Search Open Technical Databases.Gathering this information may reveal opportunities for other forms of reconnaissance ex Active Scanning or Search Open Websites/Domains, establishing operational resources ex Acquire Infrastructure or Compromise Infrastructure, and/or initial access ex External Remote Services.

#### Gather Victim Network Information: Network Security Appliances - ID: T1590.006

Adversaries may gather information about the victim's network security appliances that can be used during targeting. Information about network security appliances may include a variety of details such as the existence and specifics of deployed firewalls, content filters, and proxies/bastion hosts. Adversaries may also target information about victim network-based intrusion detection systems NIDS or other appliances related to defensive cybersecurity operations.

Adversaries may gather this information in various ways such as direct collection actions via Active Scanning or Phishing for Information. Information about network security appliances may also be exposed to adversaries via online or other accessible data sets ex Search Victim-Owned Websites. Gathering this information may reveal opportunities for other forms of reconnaissance ex Search Open Technical Databases or Search Open Websites/Domains, establishing operational resources ex Develop Capabilities or Obtain Capabilities, and/or initial access ex External Remote Services.

### Gather Victim Org Information - ID:T1591

Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees. Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about an organization may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.

### Sub-technique of:  T1591

#### Gather Victim Org Information: Determine Physical Locations - ID:T1591.001

Adversaries may gather the victim's physical locations that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed. Physical locations may also indicate what legal jurisdiction and/or authorities the victim operates within.

Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Physical locations of a target organization may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.

#### Gather Victim Org Information: Business Relationships - ID: T1591.002

Adversaries may gather information about the victim's business relationships that can be used during targeting. Information about an organization's business relationships may include a variety of details, including second or third-party organizations/domains that have connected and potentially elevated network access. This information may also reveal supply chains and shipment paths for the victim’s hardware and software resources.

Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about business relationships may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.

#### Gather Victim Org Information: Identify Business Tempo - ID: T1591.003

Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization's business tempo may include a variety of details, including operational hours and days of the week. This information may also reveal times and dates of purchases and shipments of the victim’s hardware and software resources.

Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about business tempo may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.

#### Gather Victim Org Information: Identify Roles - ID: T1591.004

Adversaries may gather information about identities and roles within the victim organization that can be used during targeting. Information about business roles may reveal a variety of targetable details, including identifiable information for key personnel as well as what data and resources they have access to.

Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about business roles may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.

### Phishing for Information - ID:T1598

Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Phishing for information is different from phishing in that the objective is gathering data from the victim rather than executing malicious code.

All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass credential harvesting campaigns.

Adversaries may also try to obtain information directly through the exchange of emails, instant messages, or other electronic conversation means. Victims may also receive phishing messages that direct them to call a phone number where the adversary attempts to collect confidential information.

Phishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information and/or sending multiple, seemingly urgent messages. Another way to accomplish this is by forging or spoofing the identity of the sender, which can be used to fool both the human recipient and automated security tools.

Phishing for information may also involve evasive techniques, such as removing or manipulating emails or metadata/headers from compromised accounts being abused to send messages.

### Sub-technique of:  T1598 

#### Phishing for Information: Spearphishing Service - ID: T1598.001

Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information and/or sending multiple, seemingly urgent messages.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services. These services are more likely to have a less strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries may create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and information about their environment. Adversaries may also use information from previous reconnaissance efforts to craft persuasive and believable lures.

####  Phishing for Information: Spearphishing Attachment - ID:T1598.002

Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information and/or sending multiple, seemingly urgent messages.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon the recipient populating information then returning the file. The text of the spearphishing email usually tries to give a plausible reason why the file should be filled in, such as a request for information from a business associate. Adversaries may also use information from previous reconnaissance efforts to craft persuasive and believable lures.

#### Phishing for Information: Spearphishing Link - ID: T1598.003

Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information and/or sending multiple, seemingly urgent messages.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, the malicious emails contain links generally accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. The given website may be a clone of a legitimate site or may closely resemble a legitimate site in appearance and have a URL containing elements from the real site. URLs may also be obfuscated by taking advantage of quirks in the URL schema, such as the acceptance of integer- or hexadecimal-based hostname formats and the automatic discarding of text before an "@" symbol.

Adversaries may also embed "tracking pixels," "web bugs," or "web beacons" within phishing messages to verify the receipt of an email, while also potentially profiling and tracking victim information such as IP address. These mechanisms often appear as small images or otherwise obfuscated objects and are typically delivered as HTML code containing a link to a remote server.

Adversaries may also be able to spoof a complete website using what is known as a "browser-in-the-browser" (BitB) attack. By generating a fake browser popup window with an HTML-based address bar that appears to contain a legitimate URL, they may be able to prompt users to enter their credentials while bypassing typical URL verification methods.

Adversaries can use phishing kits such as EvilProxy and Evilginx2 to perform adversary-in-the-middle phishing by proxying the connection between the victim and the legitimate website. On a successful login, the victim is redirected to the legitimate website, while the adversary captures their session cookie in addition to their username and password. This may enable the adversary to then bypass MFA via Web Session Cookie.

Adversaries may also send a malicious link in the form of Quick Response. These links may direct a victim to a credential phishing page. By using a QR code, the URL may not be exposed in the email and may thus go undetected by most automated email security scans. These QR codes may be scanned by or delivered directly to a user’s mobile device, which may be less secure in several relevant ways. For example, mobile users may not be able to notice minor differences between genuine and credential harvesting websites due to mobile’s smaller form factor.

From the fake website, information is gathered in web forms and sent to the adversary. Adversaries may also use information from previous reconnaissance efforts to craft persuasive and believable lures.

#### Phishing for Information: Spearphishing Voice - ID: T1598.004

Adversaries may use voice communications to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information and/or creating a sense of urgency or alarm for the recipient.

All forms of phishing are electronically delivered social engineering. In this scenario, adversaries use phone calls to elicit sensitive information from victims. Known as voice phishing (or "vishing"), these communications can be manually executed by adversaries, hired call centers, or even automated via robocalls. Voice phishers may spoof their phone number while also posing as a trusted entity, such as a business partner or technical support staff.

Victims may also receive phishing messages that direct them to call a phone number ("callback phishing") where the adversary attempts to collect confidential information.

Adversaries may also use information from previous reconnaissance efforts to tailor pretexts to be even more persuasive and believable for the victim.

### Search Closed Sources - ID: T1597

Adversaries may search and gather information about victims from closed sources that can be used during targeting. Information about victims may be available for purchase from reputable private sources and databases, such as paid subscriptions to feeds of technical or threat intelligence data. Adversaries may also purchase information from less-reputable sources such as the dark web or cybercrime black markets.

Adversaries search through various closed databases depending on the specific information they seek to gather. Information obtained from these sources may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or gaining initial access. This could include activities like phishing for information, searching open websites/domains, developing capabilities, obtaining capabilities, accessing external remote services, or using valid accounts for unauthorized purposes.

### Sub-technique of:  T1597

#### Search Closed Sources: Threat Intel Vendors - ID: T1597.001

Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that provide more comprehensive data than what is publicly available. While sensitive details such as customer names and specific identifiers are typically redacted, this information may include trends related to breaches, such as target industries, attribution claims, and successful tactics, techniques, and procedures (TTPs) along with countermeasures.

Adversaries leverage private threat intelligence vendor data to gather actionable information. Threat actors often look for information and indicators related to their own campaigns, as well as those conducted by other adversaries that align with their target industries, capabilities, objectives, or other operational concerns. Information reported by vendors can also reveal opportunities for other forms of reconnaissance, establishing operational resources, and gaining initial access. This might involve activities such as searching open websites/domains, developing capabilities, obtaining capabilities, exploiting public-facing applications, or accessing external remote services.

#### Search Closed Sources: Purchase Technical Data - ID: T1597.002

Adversaries may purchase technical information about victims that can be used during targeting. This information can typically be sourced from reputable private databases and services, which offer paid subscriptions to comprehensive scan databases or other data aggregation services. Alternatively, adversaries may resort to less-reputable sources such as the dark web or cybercrime black markets.

In their pursuit, adversaries may acquire detailed technical data about their identified targets or use purchased information to uncover opportunities for successful breaches. This data may encompass various specifics such as employee contact information, credentials, or details regarding the victim’s infrastructure.

Such purchased information enables adversaries to conduct various forms of reconnaissance, such as phishing for information or searching open websites/domains. It also facilitates activities aimed at establishing operational resources and gaining initial access, which could involve developing capabilities, obtaining further capabilities, exploiting external remote services, or leveraging valid accounts for unauthorized purposes.

### Search Open Technical Databases - ID: T1596

Adversaries may search freely available technical databases for information about victims that can be used during targeting. Such information can be found in online databases and repositories, including registrations of domains and certificates, as well as public collections of network data and artifacts gathered from traffic and scans.

Depending on their objectives, adversaries search various open databases to gather pertinent information. This data can reveal opportunities for conducting further reconnaissance, such as phishing for information or searching open websites and domains. Additionally, it can aid in establishing operational resources by acquiring or compromising infrastructure. Furthermore, it may facilitate initial access through external remote services or exploiting trusted relationships.

These activities allow adversaries to gather actionable intelligence that assists in planning and executing targeted attacks against their victims.

### Sub-technique of: T1596

#### Search Open Technical Databases: DNS/Passive DNS - ID: T1596.001

Adversaries may search DNS data for information about victims that can be used during targeting. DNS information encompasses details such as registered name servers and records outlining addressing for a target’s subdomains, mail servers, and other hosts.

To gather actionable information, threat actors typically query nameservers directly or access centralized repositories of logged DNS query responses, known as passive DNS. Additionally, adversaries may exploit DNS misconfigurations or leaks that inadvertently disclose internal network information. These sources provide insights that can aid in further reconnaissance, such as searching victim-owned websites or open websites/domains. They also facilitate the establishment of operational resources by acquiring or compromising infrastructure, and potentially enable initial access through external remote services or exploiting trusted relationships.

#### Search Open Technical Databases: WHOIS - ID: T1596.002

Adversaries may also search public WHOIS data for information about victims. WHOIS data, managed by regional Internet registries (RIRs), includes details such as assigned IP blocks, contact information, and DNS nameservers for registered domains. This data is publicly accessible, allowing threat actors to query WHOIS servers directly or use online tools to extract information relevant to their targeting efforts. Utilizing WHOIS data can support activities like active scanning, phishing for information, acquiring infrastructure, compromising infrastructure, and gaining initial access through external remote services or trusted relationships.

#### Search Open Technical Databases: Digital Certificates - ID: T1596.003

Adversaries may leverage public digital certificate data for their targeting strategies. Digital certificates, issued by certificate authorities (CAs), validate the authenticity and integrity of encrypted web traffic (HTTPS SSL/TLS communications). These certificates contain organizational details such as names and locations, which adversaries can extract using online resources and lookup tools. Digital certificate data obtained from signed artifacts used in web traffic provides valuable insights for activities like active scanning, phishing for information, developing capabilities, obtaining capabilities, and gaining initial access through external remote services or trusted relationships

#### Search Open Technical Databases: CDNs - ID: T1596.004

Adversaries may search content delivery network data about victims that can be used during targeting. CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor’s geographical region.

Adversaries may search CDN data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about content servers within a CDN. Adversaries may also seek and target CDN misconfigurations that leak sensitive information not intended to be hosted and/or do not have the same protection mechanisms as the content hosted on the organization’s website.Information from these sources may reveal opportunities for other forms of reconnaissance , establishing operational resources , and/or initial access.

#### Search Open Technical Databases: Scan Databases - ID: T1596.005

Adversaries may search within public scan databases for information about victims that can be used during targeting. Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP addresses, hostnames, open ports, certificates, and even server banners.

Adversaries may search scan databases to gather actionable information. Threat actors can use online resources and lookup tools to harvest information from these services. Adversaries may seek information about their already identified targets, or use these datasets to discover opportunities for successful breaches. Information from these sources may reveal opportunities for other forms of reconnaissance , establishing operational resources, and/or initial access.

### Search Open Websites/Domains - ID: T1593

Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts.
Adversaries may search in different online sites depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.

### Sub-technique of:  T1593

#### Search Open Websites/Domains: Social Media - ID: T1593.001

Adversaries may search social media for information about victims that can be used during targeting. Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff.

Adversaries may search in different social media sites depending on what information they seek to gather. Threat actors may passively harvest data from these sites, as well as use information gathered to create fake profiles/groups to elicit victim’s into revealing specific information (i.e. Spearphishing Service).Information from these sources may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.

#### Search Open Websites/Domains: Search Engines - ID: T1593.002

Adversaries may use search engines to collect information about victims that can be used during targeting. Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keywords or specific types of content.

Adversaries may craft various search engine queries depending on what information they seek to gather. Threat actors may use search engines to harvest general information about victims, as well as use specialized queries to look for spillages or leaks of sensitive information such as network details or credentials. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: Phishing for Information or Search Open Technical Databases), establishing operational resources, and/or initial access.

#### Search Open Websites/Domains Code Repositories - ID: T1593.003

Adversaries may search public code repositories for information about victims that can be used during targeting. Victims may store code in repositories on various third-party websites such as GitHub, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git.

Adversaries may search various public code repositories for various information about a victim. Public code repositories can often be a source of various general information about victims, such as commonly used programming languages and libraries as well as the names of employees. Adversaries may also identify more sensitive data, including accidentally leaked credentials or API keys.Information from these sources may reveal opportunities for other forms of reconnaissance, establishing operational resources ,and/or initial access.

Note: This is distinct from Code Repositories, which focuses on Collection from private and internally hosted code repositories.

### Search Victim Owned Websites ID T1594

Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info (ex: Email Addresses). These sites may also have details highlighting business operations and relationships.

Adversaries may search victim-owned websites to gather actionable information. Information from these sources may reveal opportunities for other forms of reconnaissance, establishing operational resources (ex: Establish Accounts or Compromise Accounts), and/or initial access.
