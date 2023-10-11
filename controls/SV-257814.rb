control 'SV-257814' do
  title 'RHEL 9 must disable core dumps for all users.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', 'Verify RHEL 9 disables core dumps for all users by issuing the following command:

$ grep -r -s core /etc/security/limits.conf /etc/security/limits.d/*.conf

/etc/security/limits.conf:* hard core 0

This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.

If the "core" item is missing, commented out, or the value is anything other than "0" and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement for all domains that have the "core" item assigned, this is a finding.'
  desc 'fix', 'Configure the operating system to disable core dumps for all users.

Add the following line to the top of the /etc/security/limits.conf or in a single ".conf" file defined in /etc/security/limits.d/:

* hard core 0'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61555r925427_chk'
  tag severity: 'medium'
  tag gid: 'V-257814'
  tag rid: 'SV-257814r925429_rule'
  tag stig_id: 'RHEL-09-213095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61479r925428_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
