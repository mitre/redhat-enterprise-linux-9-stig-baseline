control 'SV-257825' do
  title 'RHEL 9 subscription-manager package must be installed.'
  desc 'The Red Hat Subscription Manager application manages software subscriptions and software repositories for installed software products on the local system. It communicates with backend servers, such as the Red Hat Customer Portal or an on-premise instance of Subscription Asset Manager, to register the local system and grant access to software resources determined by the subscription entitlement.'
  desc 'check', 'Verify that RHEL 9 subscription-manager package is installed with the following command:

$ sudo dnf list --installed subscription-manager

Example output:

subscription-manager.x86_64          1.29.26-3.el9_0

If the "subscription-manager" package is not installed, this is a finding.'
  desc 'fix', 'The  subscription-manager package can be installed with the following command:
 
$ sudo dnf install subscription-manager'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61566r925460_chk'
  tag severity: 'medium'
  tag gid: 'V-257825'
  tag rid: 'SV-257825r925462_rule'
  tag stig_id: 'RHEL-09-215010'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-61490r925461_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
