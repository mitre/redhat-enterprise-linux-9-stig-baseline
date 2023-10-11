control 'SV-257782' do
  title 'RHEL 9 must enable the hardware random number generator entropy gatherer service.'
  desc 'The most important characteristic of a random number generator is its randomness, namely its ability to deliver random numbers that are impossible to predict. Entropy in computer security is associated with the unpredictability of a source of randomness. The random source with high entropy tends to achieve a uniform distribution of random values. Random number generators are one of the most important building blocks of cryptosystems.  

The rngd service feeds random data from hardware device to kernel random device. Quality (nonpredictable) random number generation is important for several security functions (i.e., ciphers).'
  desc 'check', 'Verify that RHEL 9 has enabled the hardware random number generator entropy gatherer service with the following command:

$ systemctl is-active rngd

active

If the "rngd" service is not active, this is a finding.'
  desc 'fix', 'Install the rng-tools package with the following command:

$ sudo dnf install rng-tools

Then enable the rngd service run the following command:

$ sudo systemctl enable --now rngd'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61523r925331_chk'
  tag severity: 'low'
  tag gid: 'V-257782'
  tag rid: 'SV-257782r925333_rule'
  tag stig_id: 'RHEL-09-211035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61447r925332_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
