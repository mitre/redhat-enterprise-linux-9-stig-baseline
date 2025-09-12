control 'SV-257948' do
  title 'RHEL 9 systems using Domain Name Servers (DNS) resolution must have at least two name servers configured.'
  desc 'To provide availability for name resolution services, multiple
redundant name servers are mandated. A failure in name resolution could lead to
the failure of security functions requiring name resolution, which may include
time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Note: If the system is running in a cloud platform and the cloud provider gives a single, highly available IP address for DNS configuration; this control is Not Applicable.

Verify the name servers used by the system with the following command:

$ grep nameserver /etc/resolv.conf

nameserver 192.168.1.2
nameserver 192.168.1.3

If fewer than two lines are returned that are not commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to use two or more name servers for DNS resolution based on the DNS mode of the system.

If the NetworkManager DNS mode is set to "none", add the following lines to "/etc/resolv.conf":

nameserver [name server 1]
nameserver [name server 2]

Replace [name server 1] and [name server 2] with the IPs of two different DNS resolvers.

If the NetworkManager DNS mode is set to "default", add two DNS servers to a NetworkManager connection using the following command:

$ nmcli connection modify [connection name] ipv4.dns [name server 1],[name server 2]

Replace [name server 1] and [name server 2] with the IPs of two different DNS resolvers. Replace [connection name] with a valid NetworkManager connection name on the system. Replace ipv4 with ipv6 if IPv6 DNS servers are used.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257948'
  tag rid: 'SV-257948r1045004_rule'
  tag stig_id: 'RHEL-09-252035'
  tag fix_id: 'F-61613r1045003_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  only_if('Cloud platform provides a single, highly available DNS resolver IP; this control is Not Applicable', impact: 0.0) {
    !input('ha_cloud_dns')
  }

  dns_in_host_line = parse_config_file('/etc/nsswitch.conf',
                                       comment_char: '#',
                                       assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/).params['hosts'].include?('dns')

  unless dns_in_host_line
    describe 'If `local` resolution is being used, a `hosts` entry in /etc/nsswitch.conf having `dns`' do
      subject { dns_in_host_line }
      it { should be false }
    end
  end

  unless dns_in_host_line
    describe 'If `local` resoultion is being used, the /etc/resolv.conf file should' do
      subject { parse_config_file('/etc/resolv.conf', comment_char: '#').params }
      it { should be_empty }
    end
  end

  nameservers = parse_config_file('/etc/resolv.conf', comment_char: '#').params.keys.grep(/nameserver/)

  if dns_in_host_line
    describe "The system's nameservers: #{nameservers}" do
      subject { nameservers }
      it { should_not be nil }
    end
  end

  if dns_in_host_line
    describe 'The number of nameservers' do
      subject { nameservers.count }
      it { should cmp >= 2 }
    end
  end
end
