control 'SV-257971' do
  title 'RHEL 9 must not accept router advertisements on all IPv6 interfaces.'
  desc 'An illicit router advertisement message could result in a man-in-the-middle attack.'
  desc 'check', %q(Verify RHEL 9 does not accept router advertisements on all IPv6 interfaces, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Determine if router advertisements are not accepted by using the following command:

$ sudo sysctl net.ipv6.conf.all.accept_ra

net.ipv6.conf.all.accept_ra = 0

If the "accept_ra" value is not "0" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv6.conf.all.accept_ra | tail -1

net.ipv6.conf.all.accept_ra = 0

If "net.ipv6.conf.all.accept_ra" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not accept router advertisements on all IPv6 interfaces unless the system is a router.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_ra = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61712r925898_chk'
  tag severity: 'medium'
  tag gid: 'V-257971'
  tag rid: 'SV-257971r925900_rule'
  tag stig_id: 'RHEL-09-254010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61636r925899_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
