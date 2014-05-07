{-# LANGUAGE TypeOperators #-}
module Connector where

--imports
import Network.Pcap hiding (sendPacket)
import System.IO
import Data.Word
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString as BS
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Applicative
import Control.Monad
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

parseDumpFile::FilePath->IO [(PktHdr,Maybe L2)]
parseDumpFile file = do
	hl <- openOffline file
	readit hl
	where
		readit hl = do
			(hdr,bs) <- nextBS hl
			if (hdrWireLength hdr == 0) then return []
			else (:) <$> pure (hdr,parsePacket $ B.fromStrict bs) <*> readit hl

--let it go:
sendPacket::(Header a)=>PcapHandle->a->IO ()
sendPacket hl p = sendPacketBS hl (B.toStrict $ toBytes p)

--the parsing begins:
printPacket::PcapHandle->IO Int
printPacket hl = do
	loopBS hl 1 (\_ -> print . parsePacket . B.fromStrict)

timestamp::PktHdr->String
timestamp pr = (show $ hdrTime pr) ++ ",size: " ++ (show $ hdrWireLength pr) 

readPackets::PcapHandle->Int->CallbackBS->IO Int
readPackets = loopBS 


--print the stats:
printStats::PcapHandle->IO ()
printStats hl = do
	stat <- statistics hl
	print $ "packets received: " ++ (show $ statReceived stat)
  	print $ "packets dropped by libpcap: " ++ (show $ statDropped stat)
  	print $ "packets dropped by network iface: " ++ (show $ statIfaceDropped stat)

--packet parser
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

getPackets::Get [Maybe L2]
getPackets = do
    empty <- isEmpty
    if empty then return []
    else do packet <- getPacket
            packets <- getPackets
            return (packet:packets)

parsePacket::B.ByteString->Maybe L2
parsePacket = runGet getPacket

parsePackets::B.ByteString->[Maybe L2]
parsePackets = runGet getPackets

data L2 = HE E.Ethernet L3 | HP2 P.Payload
data L3 = HI I.IP L4 | HA A.ARP | HP3 P.Payload
data L4 = HT T.TCP L5 | HU U.UDP L5 | HIC IC.ICMP L5 | HP4 P.Payload
data L5 = HP P.Payload

instance Show L2 where
	show (HE e l3) = show e ++ show l3
	show (HP2 p) = show p

instance Show L3 where
	show (HI i l4) = show i ++ show l4
	show (HA a) = show a
	show (HP3 p) = show p

instance Show L4 where
	show (HT t l5) = show t ++ show l5
	show (HU u l5) = show u ++ show l5
	show (HIC ic l5) = show ic ++ show l5
	show (HP4 p) = show p

instance Show L5 where
	show (HP p) = show p
--predicates for input packets:
isARP :: Maybe L2 -> Bool
isARP (Just (HE _ (HA _))) = True
isARP _ = False

isICMP :: Maybe L2 -> Bool
isICMP (Just (HE _ (HI _ (HIC _ (HP _))))) = True
isICMP _ = False

isTCP :: Maybe L2 -> Bool
isTCP (Just (HE _ (HI _ (HT _ (HP _))))) = True
isTCP _ = False

isUDP :: Maybe L2 -> Bool
isUDP (Just (HE _ (HI _ (HU _ (HP _))))) = True
isUDP _ = False
--for examining and modifying input packets:
toARP :: Maybe L2 -> Maybe (E.Ethernet:+:A.ARP)
toARP (Just (HE e (HA a))) = Just $ e:+:a
toARP _ = Nothing

toICMP :: Maybe L2 -> Maybe (E.Ethernet:+:I.IP:+:IC.ICMP:+:P.Payload)
toICMP (Just (HE e (HI i (HIC ic (HP p))))) = Just $ e:+:i:+:ic:+:p
toICMP _ = Nothing

toTCP :: Maybe L2 ->  Maybe (E.Ethernet:+:I.IP:+:T.TCP:+:P.Payload)
toTCP (Just (HE e (HI i (HT t (HP p))))) = Just $ e:+:i:+:t:+:p
toTCP _ = Nothing

toUDP :: Maybe L2 -> Maybe (E.Ethernet:+:I.IP:+:U.UDP:+:P.Payload)
toUDP (Just (HE e (HI i (HU u (HP p))))) = Just $ e:+:i:+:u:+:p
toUDP _ = Nothing

