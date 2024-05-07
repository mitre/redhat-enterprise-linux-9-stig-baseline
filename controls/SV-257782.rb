control 'SV-257782' do
  title 'RHEL 9 must enable the hardware random number generator entropy gatherer service.'
  desc 'The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness.  The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.

The rngd service feeds random data from hardware device to kernel random device. Quality (nonpredictable) random number generation is important for several security functions (i.e., ciphers).'
  desc 'check', 'Note: For RHEL 9 systems running with kernel FIPS mode enabled as specified by RHEL-09-671010, this requirement is Not Applicable.

Verify that RHEL 9 has enabled the hardware random number generator entropy gatherer service with the following command:

$ systemctl is-active rngd

active

If the "rngd" service is not active, this is a finding.'
  desc 'fix', 'Install the rng-tools package with the following command:

$ sudo dnf install rng-tools

Then enable the rngd service run the following command:

$ sudo systemctl enable --now rngd'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257782'
  tag rid: 'SV-257782r942961_rule'
  tag stig_id: 'RHEL-09-211035'
  tag fix_id: 'F-61447r925332_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('use_fips') == true
    impact 0.0
    describe 'N/A' do
      skip "For RHEL 9 running with kernel FIPS mode enabled, this requirement is Not Applicable."
    end
  else
    describe service('rngd') do
      it { should be_enabled }
      it { should be_running }
    end
  end
end
