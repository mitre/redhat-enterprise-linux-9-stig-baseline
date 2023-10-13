# Policyfile.rb - Describe how you want Chef Infra Client to build your system.
#
# For more information on the Policyfile feature, visit
# https://docs.chef.io/policyfile/

# A name that describes what the system you're building with Chef does.
name 'redhat-enterprise-linux-9-stig-baseline'

# Where to find external cookbooks:
default_source :supermarket

# run_list: chef-client will run these recipes in the order specified.
run_list 'example_cookbook::default'
#run_list 'dokken_test::default'
#run_list 'rhel8STIG::default'

# Specify a custom source for a single cookbook:
#cookbook 'rhel8STIG', path: 'test/fixtures/rhel8STIG-chef/cookbooks/rhel8STIG'