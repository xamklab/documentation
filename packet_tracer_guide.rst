.. role:: bash(code)
   :language: bash

.. role:: raw-html(raw)
   :format: html

A cheat sheet for commands related to Cisco switches and routers.

:raw-html:`<details><summary>Terminology</summary>`

- Placeholders are indicated between less-than and greater-than symbols (e.g. :bash:`<subnet mask>`).
- Optional arguments are indicated between square brackets (e.g. :bash:`[<upper range>]`).
- Option sets where one option is required are indicated between curly brackets (e.g. :bash:`{permit | deny}`).
  Options are seperated by the pipe sybmols (:bash:`|`).
  Optional arguments can also made an option set by including the pipe symbol.
- If long command sections are repeated across different commands, they'll be substituted with paranthesis (e.g. :bash:`(source address)`), with the actual argument(s) being defined earlier.
- Some commands require confirmation. "Confirm" means press enter when asked for confirmation.

:raw-html:`</details>`
:raw-html:`<details><summary>Connecting to a switch/router's CLI with an end device</summary>`

- Connect a console cable from a computer's RS 232 port to the console port of the switch/router.
- Enter the computer's desktop, go to terminal, and click OK.

:raw-html:`</details>`
:raw-html:`<details><summary>Navigating access levels</summary>`

- User EXEC (UE) ⇌ Privileged EXEC (PE) ⇌ Global Configuration (GC) ⇌ ...
- Access levels can be told apart by their input prompts:

  - :bash:`UE: hostname>`
  - :bash:`PE: hostname#`
  - :bash:`GC: hostname(config)#`

- Type :bash:`enable` to go up from UE to PE (think of PE as having administrator privileges).
- Type :bash:`conf t` to go up from PE to GC (GC can configure much more than PE, hence the name).
- Typing :bash:`exit` goes down the chain (GC to PE, PE to UE, etc.). Typing :bash:`end` goes down directly to PE.

:raw-html:`</details>`
:raw-html:`<details><summary>The basics</summary>`

- To show the currently active configuration file, from PE type :bash:`show running-config`.
  Spam spacebar until it reaches the end.
  :bash:`show startup-config` shows the configuration that the device will power on with.
- To save configuration changes, from PE type :bash:`copy running-config startup-config`. Confirm.
- Typing :bash:`?` shows all available commands for the access level that you're on.

  - Typing :bash:`<anything>?` will show all available commands that start with :bash:`<anything>`.
  - Typing :bash:`<command> ?` will show available/required arguments for :bash:`<command>` (notice the space).

- The up and down keys can be used to navigate through previously input commands.
- The tab key can be used for autocompletion.

:raw-html:`</details>`
:raw-html:`<details><summary>Resetting a switch/router</summary>`

- From PE, type :bash:`erase startup-config` to reset the startup configuration. Confirm.

  - For switches, also type :bash:`delete vlan.dat` to clear VLAN configurations. Confirm x2.

- From PE, type :bash:`reload` to restart the device (upon restarting it will be reset).

  - Do not save, as the current running-config would then still be in effect after the reload.

- If, on startup, you see the message "Would you like to enter the initial configuration dialog? [yes/no]", type :bash:`no`.

  - If you then see the message "Would you like to terminate autoinstall? [yes]", type :bash:`yes`.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up and securing a switch/router</summary>`

- From GC, type :bash:`hostname <name>` to give the device a new name.
- From GC, type :bash:`line con 0` to create a password for UE:

  - Type :bash:`password <password>` (e.g. "cisco").
  - Type :bash:`login` to specify that the password configured on the line(s) must be used for logging in.
  - Type :bash:`exec-timeout <minutes> [<seconds>]` to set an automatic inactivity disconnection timer.
  - Type :bash:`logging synchronous` to prevent the logs from cutting you off and making you retype commands.
  - Repeat for subsequent lines in the configuration file (e.g. :bash:`line vty 0 15` and :bash:`line aux 0`).

- To create a password for PE, from GC type :bash:`enable [algorithm-type scrypt] secret <password>` (e.g. "class").

  - :bash:`[algorithm-type scrypt]` makes the password much more secure, but is only available on newer devices.

- From GC, type :bash:`service password-encryption` to encrypt the UE password(s).

  - The PE password is encrypted by default.

- To create a message to be shown during UE login, from GC type :bash:`banner motd "<message>"` (e.g. "Unauthorized access prohibited!"). (Anything can be used as delimiters, not just quotation marks.)
- From GC, type :bash:`no ip domain-lookup` so the device doesn't misinterpret a typo as a domain.

  - You can cancel a domain lookup with :bash:`Ctrl+Shift+6`.

:raw-html:`</details>`
:raw-html:`<details><summary>Securing a switch/router: in-band management</summary>`

- From GC, type :bash:`ip domain-name <domain>` (e.g. "xamk.fi").
- From GC, type :bash:`crypto key generate rsa` to create an RSA key.

  - Type :bash:`1024` to set the modulus bit length to 1024.

- From GC, type :bash:`username <name> [algorithm-type scrypt] secret <password>` (e.g. "ssh_user" and "cisco").

  - :bash:`[algorithm-type scrypt]` makes the password much more secure, but is only available on newer devices.

- From GC, type :bash:`line vty 0 15` to edit all vty lines simultaneously:

  - Type :bash:`transport input ssh` to restrict the management connection type to SSH.
  - Type :bash:`login local` to restrict login to users (if a password is configured on the lines, it is ignored).

- From GC, type :bash:`ip ssh version 2` (this must be done AFTER creating the RSA key).
- To test the connection, do the following:

  - Open a command prompt (not the terminal) from any PC connected to the device.
  - Type :bash:`ssh -l <name> <ip>` (e.g. "ssh_user" and "192.168.1.2").
  - Enter the password (e.g. "cisco").

- You should now have in-band management, removing the need to use the console cable.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting an IP address</summary>`

- Router (each physical interface in use needs an IP address).

  - From GC, type :bash:`int <interface>` (e.g. "F0/5", "G0/1", "S0/0/0", etc.)

    - Type :bash:`ip address <ip> <subnet mask>`.
    - Type :bash:`no shutdown` to enable the interface.

- Switch (each VLAN in use can have an IP address).

  - From GC, type :bash:`int <vlan>` (e.g. "vlan1").

    - Type :bash:`ip address <ip> <subnet mask>`.
    - Type :bash:`no shutdown` to enable the interface.

  - From GC, type :bash:`ip default-gateway <ip>` to set the switch's default gateway.

- From PE, type :bash:`show ip int brief` to give details on each VLAN and interface.
- A range of interfaces can also be specified, if multiple interfaces need the same configuration.

  - For example, for a range of "F0/1" to "F0/4" and "F0/7" to "F0/10", type :bash:`int range F0/1-4, F0/7-10`.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up a VLAN</summary>`

- From GC, type :bash:`vlan <number>` (e.g. "99") to create the VLAN.

  - Type :bash:`name <name>` (e.g. "Management") to assign a name to the VLAN.

- From GC, type :bash:`int <vlan>` (e.g. "vlan99") to create the VLAN's interface (if the VLAN needs an IP, see above).
- From GC, type :bash:`int <interface>` (e.g. "F0/5") to add an interface to a VLAN (a range can also be specified).

  - If a single VLAN is behind an interface (e.g. a workstation), do the following:

    - Type :bash:`switchport mode access`.
    - Type :bash:`switchport access vlan <number>`.
    - Type :bash:`spanning-tree portfast` to have the interface bypass straight to the forwording state.

      - Type :bash:`spanning-tree bpduguard enable` for the interface to shut down if switch traffic is detected.

    - Type :bash:`switchport port-security` to block CAM table overflow attacks.

      - Type :bash:`switchport port-security maximum <number>` to specify the maximum number of MAC addresses allowed behind the interface (by default only one is allowed).
      - Type :bash:`switchport port-security mac-address sticky` to have the interface memorize the MAC(s) it sees.

  - If multiple VLANs are behind an interface (e.g. another switch), do the following:

    - Type :bash:`switchport mode trunk`.
    - Type :bash:`switchport nonegotiate` to disable DTP (auto trunking), requiring trunks to be manually configured.
    - Type :bash:`switchport trunk native vlan <number>` to set the trunk's default VLAN (usually "1").
    - Type :bash:`switchport trunk allowed vlan <numbers>` to restrict VLANs allowed over the trunk (e.g. "1,10,20,99").

- From PE, type :bash:`show vlan brief` to show what interfaces belong to what VLANs.
- For configuring router-on-a-stick on a router, from GC type :bash:`int <interface>` (e.g. "G0/0").

  - Type :bash:`no shutdown` to enable the interface.
  - Type :bash:`int <subinterface>` (e.g. "G0/0.10" for VLAN 10 on port G0/0) to configure a subinterface for a VLAN.

    - Type :bash:`encapsulation dot1q <vlan number>` (e.g. "10").
    - Type :bash:`ip address <ip> <subnet mask>`.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up EtherChannel on a switch</summary>`

- From GC, type :bash:`int range <range>` (e.g. "f0/1-4") to create an EtherChannel group.

  - Type :bash:`channel-group <number> mode <mode>` to set the channel (number must match on either switch).

    - For PAgP, the modes are :bash:`desirable` for requesting connections and :bash:`auto` for waiting for connections.
    - For LACP, the modes are :bash:`active` for requesting connections and :bash:`passive` for waiting for connections.

  - VLAN trunking can then be set up on the interfaces.

- From GC, type :bash:`int port-channel <number>` to modify the channel (can be used instead of the interface range).

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up DHCP on a router</summary>`

- From GC, type :bash:`service dhcp` to enable the DHCP service.
- From GC, type :bash:`ip dhcp excluded-address <ip>` to exclude an address from your created pool(s).

  - A range can be specified by appending a second IP address.

- From GC, type :bash:`ip dhcp pool <pool name>` (e.g. "R1_LAN").

  - Type :bash:`network <ip> <subnet mask>` to create a pool from all host addresses in the network.
  - Type :bash:`default-router <ip>` to include a default gateway in offers to hosts.
  - Type :bash:`dns-server <ip>` to include a DNS server in offers to hosts.

- To have a router relay DHCP frames, from GC type :bash:`int <interface>` for the client-facing interface(s).

  - Type :bash:`ip helper-address <dhcp server ip>` to have the router forward DHCP frames.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up HSRP on a router</summary>`

- From GC, type :bash:`int <interface>` to set up HSRP on a router interface.

  - Type :bash:`standby version 2` to set the HSRP version to 2.
  - Type :bash:`standby <group number> ip <ip>` to set the virtual IP.
  - Type :bash:`standby <group number> priority <number>` to set the priority.
  - Type :bash:`standby <group number> preempt` to tell the router to preempt when possible.
  - Type :bash:`standby <group number> track <interface>` to track an interface.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up PPP on a router</summary>`

- For point-to-point connections (e.g. serial), do the following:

  - From GC, type :bash:`int <interface>` to set up PPP on a router interface.

    - Type :bash:`encapsulation ppp` to set PPP as the encapsulation method.
    - Type :bash:`ppp authentication chap` to set CHAP as the authentication method.

  - From GC, type :bash:`username <neighbor router's hostname> password <password>` to set the CHAP password.

- For Ethernet connections, do the following to configure a PPPoE client:

  - From GC, type :bash:`interface dialer <number>` (e.g. "1").

    - Type :bash:`encapsulation ppp`.
    - Type :bash:`ip address negotiated` for the router to get its IP address(es) from a PPPoE server.
    - Type :bash:`mtu <bytes>` (usually "1492").
    - Type :bash:`dialer pool <pool number>` (e.g. "1").
    - Type :bash:`ppp authentication chap callin`.
    - Type :bash:`ppp chap hostname <router hostname>`.
    - Type :bash:`ppp chap password <password>` (password must match password set by the PPPoE server).

  - From GC, type :bash:`int <interface>` for the interface to use PPPoE.

    - Type :bash:`no ip address` (the IP is provided by the PPPoE server).
    - Type :bash:`pppoe enable group global`.
    - Type :bash:`ip tcp adjust-mss <number>` (usually "1452", related to the configured MTU).
    - Type :bash:`pppoe-client dial-pool-number <pool number>` (e.g. "1").
    - Type :bash:`no shutdown`.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up Syslog on a switch/router</summary>`

- From GC, type :bash:`logging host <ip>` to set a Syslog server (e.g. a computer with Syslog software).
- From GC, type :bash:`logging trap <level 0-7>` (e.g. "6") to set the minimum severity for Syslog logging.
- From GC, type :bash:`logging source-interface <interface>` (e.g. "s0/0/0", "loopback0", etc.) to set the IP address that the Syslog server will see as the source for Syslog messages from that device. This is usually a loopback interface.
- From GC, type :bash:`logging on` to enable logging to the Syslog server(s).

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up (dynamic) routing on a router</summary>`

:raw-html:`<details><summary>Dynamic routing with RIP</summary>`

- From GC, type :bash:`router rip` to enter the router RIP config.

  - Type :bash:`version 2` to set the RIP version to 2.

    - Type :bash:`no auto-summary` to enable the advertising of classless networks.

  - Type :bash:`network <ip>` to advertise a directly connected network (repeat for all directly connected networks).
  - Type :bash:`passive-interface <interface>` to disable routing updates through an interface (e.g. if there's only hosts).

:raw-html:`</details>`
:raw-html:`<details><summary>Dynamic routing with EIGRP</summary>`

- From GC, type :bash:`router eigrp <as id>` (e.g. "1") to enter the router EIGRP config (AS ID must match across routers).

  - Type :bash:`no auto-summary` to enable the advertising of classless networks.
  - Type :bash:`network <ip> <wildcard mask>` to advertise a directly connected network.
  - Type :bash:`passive-interface <interface>` to disable routing updates through an interface.

- From GC, type :bash:`key chain <name>` (e.g. "eigrp-keys") to create a key chain for authentication.

  - Type :bash:`key <number>` (e.g. "1").

    - Type :bash:`key-string <password>` (e.g. "cisco").

- From GC, enter the interface config for the interface(s) to enable the MD5 authentication.

  - Type :bash:`ip authentication mode eigrp <as id> md5`.
  - Type :bash:`ip authentication key-chain eigrp <key number> <key chain name>`.

:raw-html:`</details>`
:raw-html:`<details><summary>Dynamic routing with OSPF</summary>`

- From GC, type :bash:`router ospf <process id>` (e.g. "1") to enter the router OSPF config.

  - Type :bash:`router-id <router id>` (e.g. "1.1.1.1") to set the router ID (highest becomes DR).
  - Type :bash:`network <ip> <wildcard mask> area <area number>` to advertise a directly connected network.
  - Type :bash:`passive-interface <interface>` to disable routing updates through an interface.
  - Type :bash:`area <area number> range <ip> <subnet mask>` to set a summary route for an area.

- From GC, enter the interface config for the interface(s) to set an MD5 authentication password.

  - Type :bash:`ip ospf authentication message-digest`.
  - Type :bash:`ip ospf message-digest-key <number> md5 <password>` (e.g. "1", "cisco").

:raw-html:`</details>`

- From GC, type :bash:`ip route <ip> <subnet mask> <next-hop ip or exit interface>` to set a static route.
- From an interface config, type :bash:`ip summary-address <ip> <subnet mask>` to set a static summary address.
- From GC, type :bash:`ip route 0.0.0.0 0.0.0.0 <next-hop ip or exit interface>` to set a default route.

  - Under the RIP/OSPF routing config, type :bash:`default-information originate` to advertise the default route.
  - Under the EIGRP routing config, type :bash:`redistribute static` to advertise the default route.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up an ACL on a router</summary>`

- :bash:`(source address)`: :bash:`{<source ip> <wildcard mask> | any | host <source ip>}`.
- :bash:`(destination address)`: :bash:`{<destination ip> <wildcard mask> | any | host <destination ip>}`.
- From GC, type :bash:`ip access-list standard <name | number 1-99>` to configure a standard named/numbered ACL.

  - Type :bash:`{permit | deny} (source address)` to permit/deny IP/network traffic.
  - Type :bash:`remark <comment>` to document the purpose of following ACEs.
  - Alternatively to first doing :bash:`ip access-list standard ...`, each ACE command can be prepended with :bash:`access-list <number 1-99>` (numbered ACLs only).

- From GC, type :bash:`ip access-list extended <name | number 100-199>` to configure an extended named/numbered ACL.

  - Type :bash:`{permit | deny} <protocol> (source address) (destination address) [eq <destination port>]` to permit/deny IP/network traffic. Setting the protocol to "ip" will cause the ACE to apply to all traffic.
  - Type :bash:`remark <comment>` to document the purpose of following ACEs.
  - Alternatively to first doing :bash:`ip access-list extended ...`, each ACE command can be prepended with :bash:`access-list <number 100-199>` (numbered ACLs only).

- From GC, type :bash:`int <interface>` to apply an ACL on an interface:

  - Type :bash:`ip access-group <acl name/number> out` to enforce the ACL for traffic outbound from the router.
  - Type :bash:`ip access-group <acl name/number> in` to enforce the ACL for traffic inbound to the router.

- From GC, type :bash:`line vty 0 15` to apply an ACL on all VTY lines (e.g. for SSH):

  - Type :bash:`ip access-class <acl name/number> in` to enforce the ACL for traffic inbound to the vty lines.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up ZPF on a router</summary>`

- From GC, type :bash:`zone security <zone name>` to create a zone.
- From GC, type :bash:`class-map type inspect {match-any | match-all} <class name>` to create a class to match traffic.

  - Type :bash:`match access-group {[name] <acl name> | <acl number>}` to match traffic based on an ACL.

    - Some devices require the :bash:`[name]` when adding a named ACL.

  - Type :bash:`match protocol <protocol>` (e.g. "https", "ssh", etc.) to match traffic based on a protocol.
  - Type :bash:`match class-map <class name>` to match traffic based on another class (classes can be nested).

- From GC, type :bash:`policy-map type inspect <policy name>` to create a policy for how to apply a class.

  - Type :bash:`class type inspect <class name>` to use a class for the policy.

    - Type :bash:`{inspect | drop | pass} [log]` to specify what action to take for traffic matched to the class.

- From GC, type :bash:`zone-pair security <pair name> source <zone name> destination <zone name>` to create a zone pair for applying a policy (different policies may be needed for each direction).

  - Type :bash:`service-policy type inspect <policy name>` to filter traffic based on a policy.

- To apply a zone to an interface (and the network behind it), from GC type :bash:`int <interface>`.

  - Type :bash:`zone-member security <zone name>` to apply the zone.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up a Site-to-Site IPsec VPN on a router</summary>`

- From GC, type :bash:`crypto isakmp policy <priority number>` (e.g. "10", lower is preferred) to configure phase 1 policy. The policy must be identical on both routers.

  - Type :bash:`hash <hash algorithm>` (e.g. "sha").
  - Type :bash:`authentication pre-share` to specify that authentication will use a key set on both routers.
  - Type :bash:`group <dh group number>` (e.g. "14", higher is more secure).
  - Type :bash:`lifetime <seconds>` (e.g. "3600").
  - Type :bash:`encryption <encryption algorithm>` (e.g. "aes 256").

- From GC, type :bash:`crypto isakmp key <key> address <ip of remote router>` (e.g. "cisco123", "10.2.2.1") to set the pre-shared key used for phase 1 authentication between the routers. The key must be identical on both routers.
- From GC, type :bash:`crypto ipsec transform-set <set name> <encryption algorithm> <hash algorithm>` (e.g. "R1-R2", "esp-aes 256", "esp-sha-hmac") to set the algorithms for phase 2. The same command must be used on both routers.
- An extended ACL must be configured, which permits traffic from the local network to the remote one.

  - The ACLs should be mirrored on either router to prevent networking issues.

- From GC, type :bash:`crypto map <map name> <policy priority number> ipsec-isakmp` (e.g. "R1-R2-MAP", "10") to configure the phase 2 map. The map must be identical on both routers (aside from the peer and ACL).

  - Type :bash:`set peer <ip of remote router>` (e.g. "10.2.2.1").
  - Type :bash:`match address <acl name/number>` to bind an ACL to the map.
  - Type :bash:`set transform-set <set name>` (e.g. "R1-R2") to bind a transform set to the map.
  - Type :bash:`set pfs <dh group>` (e.g. "group14").
  - Type :bash:`set security-association lifetime seconds <seconds>` (e.g. "900").

- From GC, type :bash:`int <interface>` (e.g. "S0/0/0") to apply the map to an interface.

  - Type :bash:`crypto map <map name>` (e.g. "R1-R2-MAP").

- Once traffic passes from one side specified in the ACLs to the other, the security assoctiation will be established.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up PAT on a router</summary>`

- Create a numbered ACL to describe the inner network (e.g. "1", "192.168.1.0", "0.0.0.255").
- From GC, type :bash:`ip nat pool <pat name> <outer ip> <outer ip> netmask <outer subnet mask>`.
- From GC, type :bash:`ip nat inside source list <acl number> pool <pat name> overload`.
- To set an inside interface for the PAT, from GC type :bash:`int <interface>`.

  - Type :bash:`ip nat inside`.

- To set an outside interface for the PAT, from GC type :bash:`int <interface>`.

  - Type :bash:`ip nat outside`.

:raw-html:`</details>`
:raw-html:`<details><summary>Setting up NTP on a switch/router</summary>`

- From GC, type :bash:`ntp authentication-key <key number> md5 <password>` (e.g. "1", "NTPpassword").
- From GC, type :bash:`ntp trusted-key <key number>` (e.g. "1").
- From GC, type :bash:`ntp authenticate` to enable the authentication.
- To configure the device as an NTP master:

  - From GC, type :bash:`ntp master <stratum number>` (e.g. "3").

- To configure the device as an NTP client:

  - From GC, type :bash:`ntp server <ntp master ip>` to set what device to use as a master.
  - From GC, type :bash:`ntp update-calendar` for the client to also use ntp to update its calendar.

:raw-html:`</details>`
