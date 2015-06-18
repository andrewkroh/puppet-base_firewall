require 'spec_helper'

describe 'base_firewall' do

  context 'with default parameters' do
    it { should contain_class('base_firewall') }
  end

end
