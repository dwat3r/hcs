module Ping where

import Network.Pcap hiding (sendPacket)
import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Control.Lens
import Connector
import Control.Monad
import Control.Concurrent(threadDelay)
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.IP as I
import qualified Packet.ICMP as IC
import qualified Packet.Payload as P
import Network.BSD

request hostname = do
			address <- fmap hostAddress (getHostByName hostname)
			return $ (E.ethernet & E.dest   .~ (read "08:9e:01:05:fd:07"::MACAddr) 
							& E.source .~ (read "00:0a:e4:32:97:4c"::MACAddr)) +++ 
				(I.ip & I.source .~ (read "157.181.167.124"::IPAddr)
					  & I.dest   .~ (IPA $ flipBO32 address)
					  & I.ttl	 .~ 64) +++ 
				(IC.icmpEchoReq) +++
				(P.payload & P.content .~ (B.pack [0..47]))


{-
main = do 
	i <- openIface "lan"
	setFilter i "icmp" True 0
	req <- request "oktnb106.inf.elte.hu"
	replicateM 10 $ sendPacket i req
	--loopBS i 10 pp
	printStats i
-}

main = do
	i <- openIface "lan"
	--setFilter i "tcp" True 0
	loopBS i 1000 ppp

pp _ bs = do
	case (isICMP $ parsePacket $ B.fromStrict bs) of
			True -> print $ parsePacket $ B.fromStrict bs
			False -> print '.'
	threadDelay 1000000


ppp _ = print . parsePacket . B.fromStrict
