control 'SV-258076' do
  title 'RHEL 9 must display the date and time of the last successful account logon upon logon.'
  desc 'Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.'
  desc 'check', 'Verify users are provided with feedback on when account accesses last
occurred with the following command:

    $ sudo grep pam_lastlog /etc/pam.d/postlogin

    session required pam_lastlog.so showfailed

    If "pam_lastlog" is missing from "/etc/pam.d/postlogin" file, or the
silent option is present, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/postlogin".

Add the following line to the top of "/etc/pam.d/postlogin":

session required pam_lastlog.so showfailed'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258076'
  tag rid: 'SV-258076r926215_rule'
  tag stig_id: 'RHEL-09-412075'
  tag fix_id: 'F-61741r926214_fix'
  tag cci: ['CCI-000366', 'CCI-000052']
  tag nist: ['CM-6 b', 'AC-9']
  tag 'host'
  tag 'container'

  describe pam('/etc/pam.d/postlogin') do
    its('lines') { should match_pam_rule('session .* pam_lastlog.so').all_with_args('showfailed') }
    its('lines') { should_not match_pam_rule('session .* pam_lastlog.so').all_without_args('silent') }
  end
end
