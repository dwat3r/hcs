module Connector where

--imports
import Network.Pcap
import System.IO
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Applicative
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

getFragment ::Get P
getFragment = 
  (PE <$> (getBytes :: Get E.Ethernet)) <|>
    (PA <$> (getBytes :: Get A.ARP)) <|> (PIP <$> (getBytes :: Get I.IP)) <|>
    (PT <$> (getBytes :: Get T.TCP)) <|> (PU <$> (getBytes :: Get U.UDP)) <|>
    (PIC <$> (getBytes :: Get IC.ICMP)) {-<|>
    (PP <$> (getBytes :: Get P.Payload))-}

only1 a = empty <|> a

getPacket :: Get (Maybe ?) 
getPacket = do
	fs <- many getFragment
    if (and (zipWith isAttachable (fs) (tail fs)))
      then return 
      else return Nothing

--toM::Get a->Maybe (Get a)
--toM g | 

--foldl (+++ . unP) [P]
data P =  PE E.Ethernet |  
			PA A.ARP |
			PIP I.IP |
			PIC IC.ICMP |
			PT T.TCP |
			PU U.UDP |
			PP P.Payload

		deriving (Show)

isAttachable (PE _) (PA _)   = True
isAttachable (PE _) (PIP _)  = True
isAttachable (PIP _) (PIC _) = True
isAttachable (PIP _) (PT _)  = True
isAttachable (PIP _) (PU _)  = True
isAttachable (PIC _) (PP _)  = True
isAttachable (PT _) (PP _)   = True
isAttachable (PU _) (PP _)   = True
isAttachable _       _       = False
