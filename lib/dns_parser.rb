require 'rubygems'
require 'dnsruby'
require 'pcaplet'
require 'mongo'
require 'pp'

class DnsParser
  attr_accessor :pcap_filename, :pcap_interface
  attr_reader   :pcap
  def initialize(*args)
    Hash[*args].each {|k,v| self.send("%s="%k,v)}
    filter=Pcap::Filter.new("udp port 53")
    if pcap_filename != nil
      @pcap=Pcaplet.new("-r #{pcap_filename}")
    elsif pcap_interface != nil
      @pcap=Pcaplet.new("-i #{pcap_interface}")
    else
      raise ArgumentError
    end
    yield self if block_given?
  end
  def parse
    pcap.each_packet do |pkt|
      message=DnsRuby.decode(pkt.udp_data)
      puts message.to_s
    end
  end
end
