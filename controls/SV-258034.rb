control 'SV-258034' do
  title 'RHEL 9 must be configured to disable USB mass storage.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby
facilitating malicious activity.'
  desc 'check', 'Verify that RHEL 9 disables the ability to load the USB Storage kernel module with the following command:

$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d/*

install usb-storage /bin/false
blacklist usb-storage

If the command does not return any output, or either line is commented out, and use of USB Storage is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'To configure the system to prevent the usb-storage kernel module from being loaded, add the following lines to the file "/etc/modprobe.d/usb-storage.conf" (or create "usb-storage.conf" if it does not exist):

install usb-storage /bin/false
blacklist usb-storage'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-258034'
  tag rid: 'SV-258034r1051267_rule'
  tag stig_id: 'RHEL-09-291010'
  tag fix_id: 'F-61699r1045122_fix'
  tag cci: ['CCI-000778', 'CCI-000366', 'CCI-001958', 'CCI-003959']
  tag nist: ['IA-3', 'CM-6 b', 'CM-7 (9) (b)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  if input('usb_storage_required') == true
    describe kernel_module('usb_storage') do
      it { should_not be_disabled }
      it { should_not be_blacklisted }
    end
  else
    describe kernel_module('usb_storage') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
