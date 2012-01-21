# CREATED BY: RYAN BREED <opensource@breed.org>
# CREATED:    1/21/12

# import the entire dnzjava namespace into the JavaImports module
module JavaImports
  include_package 'org.xbill.DNS'
end

# automatically lookup missing constants/etc in the JavaImports module to find
# dnsjava classes, constants, etc.
class Object
  class << self
    alias :const_missing_old :const_missing
    def const_missing c
      JavaImports.const_get c
    end
  end
end

class DnsParser
  attr_accessor :pcap_filename, :mongo_server, :mongo_port
  attr_reader   :pcap, :connection, :db, :packets
  def initialize(*args)
    Hash[*args].each {|k,v| self.send("%s="%k,v)}
    @mongo_server ||= "localhost"
    @mongo_port   ||= 27017
    @connection = Mongo::Connection.new(mongo_server,mongo_port)
    @db=connection['nominalyze']
    @pcap=FFI::PCap::Offline.new(pcap_filename)
    pcap.setfilter("udp port 53")
    @packets=[]
    @frames=[]
    @messages=[]
    yield self if block_given?
  end

  def parse
    t=Time.new.to_i
    hashes=0
    pcap.loop do |this,pkt|
      message=DnsMessage.new(UdpFrame.new(pkt.body)).to_h
      begin
        db["dns"].insert(message)
      rescue
        puts "BOMBED on message #{hashes}"
        pp message
      end

      hashes+=1
    end
    puts "parsed #{hashes} messages in #{Time.new.to_i - t} seconds"
    nil
  end
end
