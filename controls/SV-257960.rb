control 'SV-257960' do
  title 'RHEL 9 must log IPv4 packets with impossible addresses.'
  desc 'The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.'
  desc 'check', %q(Verify RHEL 9 logs IPv4 martian packets.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv4.conf.all.log_martians

net.ipv4.conf.all.log_martians = 1

If the returned line does not have a value of "1", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.all.log_martians | tail -1

net.ipv4.conf.all.log_martians = 1

If "net.ipv4.conf.all.log_martians" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to log martian packets on IPv4 interfaces.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.log_martians=1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61701r925865_chk'
  tag severity: 'medium'
  tag gid: 'V-257960'
  tag rid: 'SV-257960r925867_rule'
  tag stig_id: 'RHEL-09-253025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61625r925866_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
