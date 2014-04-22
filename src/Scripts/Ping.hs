module Ping where

import Network.Pcap
import Connector
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.IP as I
import qualified Packet.ICMP as IC
import qualified Packet.Payload as P

request = 	E.ethernet +++ 
			I.ip +++ 
			IC.icmp +++
			P.payload



main = do 
	i <- openIface "enp2s0"
	loopBS i 1 pp 
	--bs <- readPacket i

pp pr bs = do
	print bs
	print "\n"