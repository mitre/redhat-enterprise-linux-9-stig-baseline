control 'SV-258174' do
  title 'RHEL 9 must have mail aliases to notify the information system security officer (ISSO) and system administrator (SA) (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify that RHEL 9 is configured to notify the appropriate interactive users in the event of an audit processing failure.

Find the alias maps that are being used with the following command:

$ postconf alias_maps 

alias_maps = hash:/etc/aliases

Query the Postfix alias maps for an alias for the root user with the following command:

$ postmap -q root hash:/etc/aliases
isso

If an alias is not set, this is a finding.'
  desc 'fix', 'Edit the aliases map file (by default /etc/aliases) used by Postfix and configure a root alias (using the user ISSO as an example):

root:    ISSO

and then update the aliases database with the command:

$ sudo newaliases'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61915r926507_chk'
  tag severity: 'medium'
  tag gid: 'V-258174'
  tag rid: 'SV-258174r926509_rule'
  tag stig_id: 'RHEL-09-653125'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-61839r926508_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
