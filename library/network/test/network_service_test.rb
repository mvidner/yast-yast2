#! /usr/bin/env rspec

inc_dirs = Dir.glob("../../../library/*/src")
inc_dirs.map { |inc_dir| File.expand_path(inc_dir, __FILE__) }
ENV["Y2DIR"] = inc_dirs.join(":")

require "yast"

Yast.import "NetworkService"

describe Yast::NetworkService do
  context "smoke test" do
    describe "#is_network_manager" do
      it "does not crash" do
        expect(Yast::NetworkService.is_network_manager).to include(true, false)
      end
    end
  end
end
