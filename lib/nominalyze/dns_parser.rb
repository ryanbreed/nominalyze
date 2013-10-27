# CREATED BY: RYAN BREED <opensource@breed.org>
# CREATED:    1/21/12

# import the entire dnsjava namespace into the JavaImports module
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
    @connection = Mongo::Connection.new(mongo_server,mongo_port, :pool_size=>4)
    @db=connection['nom']
    @pcap=FFI::PCap::Offline.new(pcap_filename)
    pcap.setfilter("udp port 53")
    @packets=[]
    @frames=[]
    @messages=[]
    yield self if block_given?
  end

  def parse
    t=Time.new.to_i
    q=Queue.new

    hash_num=0
    message_generator = Thread.new do
      pcap.loop do |this,pkt|
        frame=UdpFrame.new(pkt.body)
        frame.time=pkt.time
        message_hash=DnsMessage.new(:frame=>frame).to_h
        #pp message_hash
        q << message_hash
      end
      q << "done"
    end

    persister = Thread.new do
      while (item=q.pop)!= "done"
        hash_num+=1
        db["dns"].insert(item)
        #pp item
      end
    end
    persister.join
    t_total=Time.new.to_i - t
    puts "parsed #{hash_num} messages in #{t_total} seconds #{t_total==0 ? '' : (hash_num.to_f/t_total.to_f)}"
    nil
  end
end
