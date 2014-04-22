module Connector where

--imports
import Network.Pcap
import System.IO
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.ARP as A
import qualified Packet.IP as I
import qualified Packet.TCP as T
import qualified Packet.UDP as U
import qualified Packet.ICMP as IC
import qualified Packet.Payload as P

--list your devs:
listDevNames :: IO ()
listDevNames = do
  x <- findAllDevs
  print $ map ifName x 

--open the iface:
openIface::String->IO PcapHandle
openIface i = openLive i 2048 True 512

--let it go:
sendPacket::(Header a)=>PcapHandle->a->IO ()
sendPacket hl p = undefined

--the parsing begins:
readPacket::PcapHandle->IO B.ByteString
readPacket hl = do
	(_,bs) <- nextBS hl
	return $ B.fromStrict bs

timestamp::PktHdr->String
timestamp pr = (show $ hdrTime pr) ++ ",size: " ++ (show $ hdrWireLength pr) 

--readPackets::(Header a)=>PcapHandle->Int->IO [a]
--readPackets hl n = do
--	loopBS hl n $ readPacket hl

--print the stats:
printStats::PcapHandle->IO ()
printStats hl = do
	stat <- statistics hl
	print $ "packets received: " ++ (show $ statReceived stat)
  	print $ "packets dropped by libpcap: " ++ (show $ statDropped stat)
  	print $ "packets dropped by network iface: " ++ (show $ statIfaceDropped stat)


parsePacket::(Header a)=>B.ByteString->a
parsePacket bs = undefined
