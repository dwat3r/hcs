module Ping where

import Network.Pcap hiding (sendPacket)
import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Control.Lens
import Connector
import Control.Monad
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.IP as I
import qualified Packet.ICMP as IC
import qualified Packet.Payload as P

request = 	
			(E.ethernet & E.dest   .~ (read "00:0a:e4:32:97:4c"::MACAddr) 
						& E.source .~ (read "90:e6:ba:4e:7b:0b"::MACAddr)) +++ 
			(I.ip & I.source .~ (read "192.168.0.100"::IPAddr)
				  & I.dest   .~ (read "192.168.0.101"::IPAddr)) +++ 
			(IC.icmpEchoReq) +++
			(P.payload & P.content .~ (B.pack [0..3]))



main = do 
	i <- openIface "enp2s0"
	setFilter i "icmp" True 0
	replicateM_ 10 (sendPacket i request)
	loopBS i 10 pp
	printStats i

pp _ bs = do
	case (isICMP $ parsePacket $ B.fromStrict bs) of
			True -> print $ parsePacket $ B.fromStrict bs
			False -> print '.'