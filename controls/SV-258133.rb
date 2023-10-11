control 'SV-258133' do
  title 'RHEL 9 must prohibit the use of cached authenticators after one day.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'Verify that the System Security Services Daemon (SSSD) prohibits the use of cached authentications after one day.

Note: If smart card authentication is not being used on the system, this requirement is Not Applicable.

Check that SSSD allows cached authentications with the following command:

$ sudo grep cache_credentials /etc/sssd/sssd.conf

cache_credentials = true

If "cache_credentials" is set to "false" or missing from the configuration file, this is not a finding and no further checks are required.

If "cache_credentials" is set to "true", check that SSSD prohibits the use of cached authentications after one day with the following command:

$ sudo grep offline_credentials_expiration  /etc/sssd/sssd.conf

offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Configure the SSSD to prohibit the use of cached authentications after one day.

Add or change the following line in "/etc/sssd/sssd.conf" just below the line [pam]:

offline_credentials_expiration = 1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61874r926384_chk'
  tag severity: 'medium'
  tag gid: 'V-258133'
  tag rid: 'SV-258133r926386_rule'
  tag stig_id: 'RHEL-09-631020'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-61798r926385_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
