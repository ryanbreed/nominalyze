unless File.respond_to? :realpath
  class File #:nodoc:
    def self.realpath path
      return realpath(File.readlink(path)) if symlink?(path)
      path
    end
  end
end
$: << File.expand_path(File.dirname(File.realpath(__FILE__)) + '/nominalyze')

require 'java'
require 'rubygems'
require 'mongo'
require 'bit-struct'
require 'ffi-pcap'
require 'pp'
require 'dnsjava-2.1.3.jar'
require 'dns_message'
require 'udp_frame'
require 'dns_parser'
require 'json'

module Nominalyze
  VERSION="0.5.0"
end
