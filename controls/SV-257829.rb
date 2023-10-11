control 'SV-257829' do
  title 'RHEL 9 must not have the ypserv package installed.'
  desc 'The NIS service provides an unencrypted authentication service, which does not provide for the confidentiality and integrity of user passwords or the remote session.

Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  desc 'check', 'Verify that the ypserv package is not installed with the following command:

$ sudo dnf list --installed ypserv

Error: No matching Packages to list

If the "ypserv" package is installed, this is a finding.'
  desc 'fix', 'Remove the ypserv package with the following command:

$ sudo dnf remove ypserv'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61570r925472_chk'
  tag severity: 'medium'
  tag gid: 'V-257829'
  tag rid: 'SV-257829r925474_rule'
  tag stig_id: 'RHEL-09-215030'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61494r925473_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
