require 'dnsruby'
require 'ffi/pcap'
require 'mongo'
require 'bit-struct'
require 'pp'

module Hashinator
  def to_h
    h={}
    self.instance_variables.collect {|i| i.to_s.gsub(/^@/,"")}.each do |var|
      h[var]=self.send(var).to_s.dup.force_encoding("UTF-8")
    end
    h
  end
end

class UdpFrame <BitStruct
  attr_accessor :timestamp
  hex_octets :enet_dst,  48,     "Source MAC"
  hex_octets :enet_src,  48,     "Destination MAC"
  unsigned   :enet_type,16,     "Ethertype or length"
  unsigned    :ip_v,     4,     "Version"
  unsigned    :ip_hl,    4,     "Header length"
  unsigned    :ip_tos,   8,     "TOS"
  unsigned    :ip_len,  16,     "Length"
  unsigned    :ip_id,   16,     "ID"
  unsigned    :ip_off,  16,     "Frag offset"
  unsigned    :ip_ttl,   8,     "TTL"
  unsigned    :ip_p,     8,     "Protocol"
  unsigned    :ip_sum,  16,     "Checksum"
  octets      :ip_src,  32,     "Source addr"
  octets      :ip_dst,  32,     "Dest addr"
  unsigned    :udp_sport,       16,     "Source Port"
  unsigned    :udp_dport,       16,     "Destination Port"
  unsigned    :udp_length,  16,     "Datagram Length"
  unsigned    :udp_checksum,16,     "Datagram Checksum"
  rest        :udp_data,            "UDP Data"
  initial_value.ip_v    = 4
  initial_value.ip_hl   = 5
  alias_method :original_to_h, :to_h
  alias_method :original_initialize, :initialize
  def initialize(pkt)
    p=original_initialize(pkt.body)
    p.timestamp=pkt.timestamp.utc.to_i
    p
  end
  def to_h
    h=original_to_h
    h[:udp_data]=BSON::Binary.new(h[:udp_data])
    h["timestamp"]=self.timestamp
    h
  end
end
class Dnsruby::Message
  include Hashinator
  alias signing tsig
  alias old_to_hash to_h
  def tsigkey
    ""
  end
  def to_h
    h={}#old_to_hash
    %w{ question answer header additional authority }.each {|s| h.delete(s)}
    h["questions"]=[]
    h["answers"]=[]
    h["txid"]=header.id
    each_question {|q| h["questions"]<<q.to_h}
    each_answer   {|a| h["answers"]<<a.to_h}
    h["qcount"]=h["questions"].length
    h["acount"]=h["answers"].length
    h
  end
end
class Dnsruby::Header
  include Hashinator
  alias rcode get_header_rcode
end
class Dnsruby::Question
  def to_h
   h={}
    self.instance_variables.collect {|i| i.to_s.gsub(/^@/,"")}.each do |var|
      h[var]=self.send(var).to_s.dup.force_encoding("UTF-8")
    end
    h["namelen"]=self.qname.to_s.size
    h
  end
end
class Dnsruby::RR
  def to_h
   h={}
   varnames=self.instance_variables.collect {|i| i.to_s.gsub(/^@/,"")}
   varnames.delete('options')
   varnames.each do |var|
      h[var]=self.send(var).to_s.dup.force_encoding("UTF-8")
    end
    h.delete("signature")
    h["rdatalen"]=self.rdata.to_s.size
    h
  end
end

class DnsParser
  attr_accessor :pcap_filename, :mongo_server, :mongo_port
  attr_reader   :pcap, :connection, :db
  def initialize(*args)
    Hash[*args].each {|k,v| self.send("%s="%k,v)}
    @mongo_server ||= "localhost"
    @mongo_port   ||= 27017
    @connection = Mongo::Connection.new(mongo_server,mongo_port)
    @db=connection['nominalyze']
    @pcap=FFI::PCap::Offline.new(pcap_filename)
    pcap.setfilter("udp port 53")
    yield self if block_given?
  end
  def parse
    count=0
    pcap.loop do |this,pkt|
      udp=UdpFrame.new(pkt)
      # TODO this needs to go into UdpFrame#new
      message=nil
      begin
        message=Dnsruby::Message.decode(udp.udp_data)
      rescue
      end
      uh=udp.to_h
      message.nil? ? mh={} : mh=message.to_h
      doc=uh.merge(mh)
      db["dns"].insert(doc)
    end
  end
end
