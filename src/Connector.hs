module Connector where

--imports
import Network.Pcap hiding (sendPacket)
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
sendPacket hl p = sendPacketBS hl (B.toStrict $ toBytes p)

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




--only1 a = empty <|> a
{-
getPacket :: Get [P]
getPacket = do
	l2 <- getBytes :: Get E.Ethernet
	end <- isEmpty
	if end then return [PE l2]
	else do
		case l2 of
			(E.Ethernet {E._ethType=0x806}) -> do 
				l3 <- getBytes :: Get A.ARP
				return [PE l2,PA l3]
			(E.Ethernet {E._ethType=0x800}) -> do 
				l3 <- getBytes :: Get I.IP
				end <- isEmpty
				if end then return [PE l2,PIP l3]
				else do
					case l3 of
						(I.IP {I._protocol=6}) 	-> do 
							l4 <- getBytes :: Get T.TCP
							end <- isEmpty
							if end then return [PE l2,PIP l3,PT l4]
								else do
								l5 <- getBytes :: Get P.Payload
								return [PE l2,PIP l3,PT l4,PP l5]
						(I.IP {I._protocol=17}) -> do 
							l4 <- getBytes :: Get U.UDP
							end <- isEmpty
							if end then return [PE l2,PIP l3,PU l4]
								else do
								l5 <- getBytes :: Get P.Payload
								return [PE l2,PIP l3,PU l4,PP l5]
						(I.IP {I._protocol=1})  -> do 
							l4 <- getBytes :: Get IC.ICMP
							end <- isEmpty
							if end then return [PE l2,PIP l3,PIC l4]
								else do
								l5 <- getBytes :: Get P.Payload
								return [PE l2,PIP l3,PIC l4,PP l5]
						_ -> do 
							l4 <- getBytes :: Get P.Payload
							return [PE l2,PIP l3,PP l4]
			_ -> do 
				l3 <- getBytes :: Get P.Payload
				return [PE l2,PP l3]

toICMP :: [P] -> Maybe (E.Ethernet:+:I.IP:+:IC.ICMP:+:P.Payload)
toICMP [PE e,PIP i,PIC ic,PP p] = Just $ e:+:i:+:ic:+:p
toICMP _ = Nothing

toUDP :: [P] -> Maybe (E.Ethernet:+:I.IP:+:U.UDP:+:P.Payload)
toUDP [PE e,PIP i,PU u,PP p] = Just $ e+++i+++u+++p
toUDP _ = Nothing

toTCP :: [P] -> Maybe (E.Ethernet:+:I.IP:+:T.TCP:+:P.Payload)
toTCP [PE e,PIP i,PT t,PP p] = Just $ e+++i+++t+++p

isAttachable::P->P->Bool
isAttachable (PE _) (PA _)   = True
isAttachable (PE _) (PIP _)  = True
isAttachable (PIP _) (PIC _) = True
isAttachable (PIP _) (PT _)  = True
isAttachable (PIP _) (PU _)  = True
isAttachable (PIC _) (PP _)  = True
isAttachable (PT _) (PP _)   = True
isAttachable (PU _) (PP _)   = True
isAttachable _       _       = False

data P =  PE E.Ethernet |  
			PA A.ARP |
			PIP I.IP |
			PIC IC.ICMP |
			PT T.TCP |
			PU U.UDP |
			PP P.Payload
		deriving (Show)
-}
getPacket :: Get (Maybe L2)
getPacket = do
	end <- isEmpty
	if end then return Nothing
	else do
		l2 <- getBytes :: Get E.Ethernet
		end <- isEmpty
		if end then return Nothing
		else do
			case l2 of
				(E.Ethernet {E._ethType=0x806}) -> do 
					l3 <- getBytes :: Get A.ARP
					return $ Just $ HE l2 $ HA l3
				(E.Ethernet {E._ethType=0x800}) -> do 
					l3 <- getBytes :: Get I.IP
					end <- isEmpty
					if end then return Nothing
					else do
						case l3 of
							(I.IP {I._protocol=6}) 	-> do 
								l4 <- getBytes :: Get T.TCP
								end <- isEmpty
								if end then return Nothing
									else do
									l5 <- getBytes :: Get P.Payload
									return $ Just $ HE l2 $ HI l3 $ HT l4 $ HP l5
							(I.IP {I._protocol=17}) -> do 
								l4 <- getBytes :: Get U.UDP
								end <- isEmpty
								if end then return Nothing
									else do
									l5 <- getBytes :: Get P.Payload
									return $ Just $ HE l2 $ HI l3 $ HU l4 $ HP l5
							(I.IP {I._protocol=1})  -> do 
								l4 <- getBytes :: Get IC.ICMP
								end <- isEmpty
								if end then return Nothing
									else do
									l5 <- getBytes :: Get P.Payload
									return $ Just $ HE l2 $ HI l3 $ HIC l4 $ HP l5
							_ -> return Nothing
				_ -> return Nothing


--foldl (+++ . unP) [P]
parsePacket::B.ByteString->Maybe L2
parsePacket bs = runGet getPacket bs

data L2 = HE E.Ethernet L3 | HP2 P.Payload
	deriving (Show)
data L3 = HI I.IP L4 | HA A.ARP | HP3 P.Payload
	deriving (Show)
data L4 = HT T.TCP L5 | HU U.UDP L5 | HIC IC.ICMP L5 | HP4 P.Payload
	deriving (Show)
data L5 = HP P.Payload
	deriving (Show)

isICMP :: Maybe L2 -> Bool
isICMP (Just (HE _ (HI _ (HIC _ (HP _))))) = True
isICMP _ = False