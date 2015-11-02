source 'https://rubygems.org'

if ENV.key?('PUPPET_VERSION')
  puppetversion = "~> #{ENV['PUPPET_VERSION']}"
else
  puppetversion = ['>= 3.6.0']
end

gem 'metadata-json-lint'
gem 'puppet', puppetversion
# Support ruby 1.8.7
# https://github.com/rspec/rspec-core/issues/1864
if RUBY_VERSION < "1.9"
  gem 'rspec', '< 3.2.0'
end
gem 'puppet-lint'
gem 'puppetlabs_spec_helper'
gem 'rake'
gem 'facter', ' >=2.0.0'

# vim:ft=ruby
