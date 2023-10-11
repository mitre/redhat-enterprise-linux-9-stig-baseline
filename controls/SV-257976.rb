control 'SV-257976' do
  title 'RHEL 9 must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', %q(Verify RHEL 9 will not accept IPv6 ICMP redirect messages.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the default "accept_redirects" variables with the following command:

$ sysctl net.ipv6.conf.default.accept_redirects

net.ipv6.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F net.ipv6.conf.default.accept_redirects | tail -1

net.ipv6.conf.default.accept_redirects = 0

If "net.ipv6.conf.default.accept_redirects" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to prevent IPv6 ICMP redirect messages from being accepted.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.default.accept_redirects = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61717r925913_chk'
  tag severity: 'medium'
  tag gid: 'V-257976'
  tag rid: 'SV-257976r925915_rule'
  tag stig_id: 'RHEL-09-254035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61641r925914_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
