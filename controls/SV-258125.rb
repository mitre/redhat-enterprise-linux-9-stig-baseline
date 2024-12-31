control 'SV-258125' do
  title 'The pcscd service on RHEL 9 must be active.'
  desc 'The information system ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

The daemon program for pcsc-lite and the MuscleCard framework is pcscd. It is a resource manager that coordinates communications with smart card readers and smart cards and cryptographic tokens that are connected to the system.'
  desc 'check', 'Verify that the "pcscd" service is active with the following command:

$ systemctl is-active pcscd

active

If the pcscdservice is not active, this is a finding.'
  desc 'fix', 'To enable the pcscd service run the following command:

$ sudo systemctl enable --now pcscd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61866r926360_chk'
  tag severity: 'medium'
  tag gid: 'V-258125'
  tag rid: 'SV-258125r997109_rule'
  tag stig_id: 'RHEL-09-611180'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-61790r926361_fix'
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-004046']
  tag nist: ['IA-2 (11)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('smart_card_enabled')
    describe service('pcscd') do
      it { should be_enabled }
      it { should be_running }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement, this control is Not Applicable.'
    end
  end
end
