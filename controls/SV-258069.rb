control 'SV-258069' do
  title 'RHEL 9 must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service (DoS) attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be defined based on mission needs and the operational environment for each system.'
  desc 'check', 'Verify RHEL 9 limits the number of concurrent sessions to "10" for all accounts and/or account types with the following command:

$ grep -r -s maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf

/etc/security/limits.conf:* hard maxlogins 10

This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.

If the "maxlogins" item is missing, commented out, or the value is set greater than "10" and is not documented with the information system security officer (ISSO) as an operational requirement for all domains that have the "maxlogins" item assigned, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to limit the number of concurrent sessions to "10" for all accounts and/or account types.

Add the following line to the top of the /etc/security/limits.conf or in a ".conf" file defined in /etc/security/limits.d/:

* hard maxlogins 10'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61810r926192_chk'
  tag severity: 'low'
  tag gid: 'V-258069'
  tag rid: 'SV-258069r926194_rule'
  tag stig_id: 'RHEL-09-412040'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-61734r926193_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
