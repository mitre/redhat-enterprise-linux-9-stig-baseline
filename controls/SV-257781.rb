control 'SV-257781' do
  title 'The graphical display manager must not be the default target on RHEL 9 unless approved.'
  desc 'Unnecessary service packages must not be installed to decrease the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and must not be used, unless approved and documented.'
  desc 'check', 'Verify that RHEL 9 is configured to boot to the command line:

$ systemctl get-default

multi-user.target

If the system default target is not set to "multi-user.target" and the information system security officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding.'
  desc 'fix', 'Document the requirement for a graphical user interface with the ISSO or set the default target to multi-user with the following command:

$ sudo systemctl set-default multi-user.target'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61522r925328_chk'
  tag severity: 'medium'
  tag gid: 'V-257781'
  tag rid: 'SV-257781r925330_rule'
  tag stig_id: 'RHEL-09-211030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61446r925329_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
