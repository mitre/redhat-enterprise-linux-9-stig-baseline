control 'SV-257948' do
  title 'RHEL 9 systems using Domain Name Servers (DNS) resolution must have at least two name servers configured.'
  desc 'To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Verify the name servers used by the system with the following command:

$ grep nameserver /etc/resolv.conf

nameserver 192.168.1.2
nameserver 192.168.1.3

If less than two lines are returned that are not commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to use two or more name servers for DNS resolution based on the DNS mode of the system.

If the NetworkManager DNS mode is set to "none", then add the following lines to "/etc/resolv.conf":

nameserver [name server 1]
nameserver [name server 2]

Replace [name server 1] and [name server 2] with the IPs of two different DNS resolvers.

If the NetworkManager DNS mode is set to "default" then add two DNS servers to a NetworkManager connection. Using the following commands:

$ sudo nmcli connection modify [connection name] ipv4.dns [name server 1]
$ sudo nmcli connection modify [connection name] ipv4.dns [name server 2]

Replace [name server 1] and [name server 2] with the IPs of two different DNS resolvers. Replace [connection name] with a valid NetworkManager connection name on the system. Replace ipv4 with ipv6 if IPv6 DNS servers are used.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61689r925829_chk'
  tag severity: 'medium'
  tag gid: 'V-257948'
  tag rid: 'SV-257948r925831_rule'
  tag stig_id: 'RHEL-09-252035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61613r925830_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
