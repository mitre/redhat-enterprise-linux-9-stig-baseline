control 'SV-257937' do
  title 'The RHEL 8 fapolicy module must be configured to employ a deny-all,
permit-by-exception policy to allow the execution of authorized software
programs.'
  desc 'The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    Utilizing a whitelist provides a configuration management method for
allowing the execution of only authorized software. Using only authorized
software decreases risk by limiting the number of potential vulnerabilities.
Verification of whitelisted software occurs prior to execution or at system
startup.

    User home directories/folders may contain information of a sensitive
nature. Non-privileged users should coordinate any sharing of information with
an SA through shared resources.

    RHEL 8 ships with many optional packages. One such package is a file access
policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that
determines access rights to files based on attributes of the process and file.
It can be used to either blacklist or whitelist processes or file access.

    Proceed with caution with enforcing the use of this daemon. Improper
configuration may render the system non-functional. The "fapolicyd" API is
not namespace aware and can cause issues when launching or running containers.'
  desc 'check', 'Verify the RHEL 8 "fapolicyd" employs a deny-all, permit-by-exception policy.

Check that "fapolicyd" is in enforcement mode with the following command:

$ sudo grep permissive /etc/fapolicyd/fapolicyd.conf

permissive = 0

Check that fapolicyd employs a deny-all policy on system mounts with the following commands:

For RHEL 8.4 systems and older:
$ sudo tail /etc/fapolicyd/fapolicyd.rules

For RHEL 8.5 systems and newer:
$ sudo tail /etc/fapolicyd/compiled.rules

allow exe=/usr/bin/python3.7 : ftype=text/x-python
deny_audit perm=any pattern=ld_so : all
deny perm=any all : all

If fapolicyd is not running in enforcement mode with a deny-all, permit-by-exception policy, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to employ a deny-all, permit-by-exception application whitelisting policy with "fapolicyd".

With the "fapolicyd" installed and enabled, configure the daemon to function in permissive mode until the whitelist is built correctly to avoid system lockout. Do this by editing the "/etc/fapolicyd/fapolicyd.conf" file with the following line:

permissive = 1

For RHEL 8.4 systems and older:
Build the whitelist in the "/etc/fapolicyd/fapolicyd.rules" file ensuring the last rule is "deny perm=any all : all".

For RHEL 8.5 systems and newer:
Build the whitelist in a file within the "/etc/fapolicyd/rules.d" directory ensuring the last rule is "deny perm=any all : all".

Once it is determined the whitelist is built correctly, set the fapolicyd to enforcing mode by editing the "permissive" line in the /etc/fapolicyd/fapolicyd.conf file.

permissive = 0'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155', 'SRG-OS-000480-GPOS-00232']
  tag gid: 'V-244546'
  tag rid: 'SV-257937r858730_rule'
  tag stig_id: 'RHEL-08-040137'
  tag fix_id: 'F-47778r858729_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']

  # Check if the system is a Docker container or not using Fapolicyd
  if virtualization.system.eql?('docker') || !input('use_fapolicyd')
    impact 0.0
    describe 'Control not applicable' do
      skip 'The organization is not using the Fapolicyd service to manage firewall services, this control is Not Applicable' unless input('use_fapolicyd')
      skip 'Control not applicable within a container' if virtualization.system.eql?('docker')
    end
  else
    # Parse the fapolicyd configuration file
    fapolicyd_config = parse_config_file('/etc/fapolicyd/fapolicyd.conf')

    describe 'Fapolicyd configuration' do
      it 'permissive should not be commented out' do
        expect(fapolicyd_config.content).to match(/^permissive\s*=\s*0$/), 'permissive is commented out in the fapolicyd.conf file'
      end
      it 'should have permissive set to 0' do
        expect(fapolicyd_config.params['permissive']).to cmp '0'
      end
    end

    # Determine the rules file based on the OS release
    rules_file = os.release.to_f < 8.4 ? '/etc/fapolicyd/fapolicyd.rules' : '/etc/fapolicyd/compiled.rules'

    # Check if the rules file exists
    describe file(rules_file) do
      it { should exist }
    end

    # If the rules file exists, check the last rule
    if file(rules_file).exist?
      rules = file(rules_file).content.strip.split("\n")
      last_rule = rules.last

      describe 'Last rule in the rules file' do
        it { expect(last_rule).to cmp 'deny perm=any all : all' }
      end
    end
  end
end
