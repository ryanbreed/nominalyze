#!/bin/env ruby
unless File.respond_to? :realpath
  class File #:nodoc:
    def self.realpath path
      return realpath(File.readlink(path)) if symlink?(path)
      path
    end
  end
end
$: << File.expand_path(File.dirname(File.realpath(__FILE__)) + '/../lib')
require 'nominalyze'
$ARGV.each do |filename|
  puts "processing #{filename}"
  DnsParser.new(:pcap_filename=>"filename").parse
end

