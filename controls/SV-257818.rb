control 'SV-257818' do
  title 'The kdump service on RHEL 9 must be disabled.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition. Unless the system is used for kernel development or testing, there is little need to run the kdump service.'
  desc 'check', 'Verify that the kdump service is disabled in system boot configuration with the following command:

$ systemctl is-enabled  kdump  

disabled 

Verify that the kdump service is not active (i.e., not running) through current runtime configuration with the following command:

$ systemctl is-active kdump 

inactive 

Verify that the kdump service is masked with the following command:

$ sudo systemctl show  kdump  | grep "LoadState\\|UnitFileState" 

LoadState=masked 

UnitFileState=masked 

If the "kdump" service is loaded or active, and is not masked, this is a finding.'
  desc 'fix', 'Disable and mask the kdump service on RHEL 9.

To disable the kdump service run the following command:

$ sudo systemctl disable --now kdump

To mask the kdump service run the following command:

$ sudo systemctl mask --now kdump'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61559r925439_chk'
  tag severity: 'medium'
  tag gid: 'V-257818'
  tag rid: 'SV-257818r925441_rule'
  tag stig_id: 'RHEL-09-213115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61483r925440_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
