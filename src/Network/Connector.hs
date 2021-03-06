{-# LANGUAGE TypeOperators #-}
module Network.Connector where

--imports
import Network.Pcap hiding (sendPacket)
import System.IO
import Data.Word
import Data.Maybe
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString as BS
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Applicative
import Control.Monad
import Control.Lens
import Data.Maybe
import Network.Packet
import qualified Network.Ethernet as E
import qualified Network.ARP as A
import qualified Network.IP as I
import qualified Network.TCP as T
import qualified Network.UDP as U
import qualified Network.ICMP as IC
import qualified Network.Payload as P
import Network.Info
import Data.IORef

getIPMAC::String->IO (Maybe (IPAddr,MACAddr))
getIPMAC s = do
    ifaces  <- getNetworkInterfaces
    return $ toThrees $ listToMaybe $ filter (\n->s==name n) ifaces
        where
            toThrees::Maybe NetworkInterface->Maybe (IPAddr,MACAddr)
            toThrees mn = case isJust mn of
                        True -> Just $ (toIP $ ipv4 $ fromJust mn,toMac $ Network.Info.mac $ fromJust mn)
                        False -> Nothing
            toMac::MAC->MACAddr
            toMac (MAC a b c d e f) = MACA $ B.pack [a,b,c,d,e,f]
            toIP::IPv4->IPAddr
            toIP (IPv4 i) = IPA $ flipBO32 i

--list your devs:
listDevNames :: IO ()
listDevNames = do
  x <- findAllDevs
  print $ map ifName x 

--open the iface:
openIface::String->IO PcapHandle
openIface i = openLive i 2048 True 512

filterPacket::PcapHandle->String->IO ()
filterPacket hl s = setFilter hl s True 0

parseDumpFile::FilePath->IO [(PktHdr,Maybe L2)]
parseDumpFile file = do
	hl <- openOffline file
	readit hl
	where
		readit hl = do
			(hdr,bs) <- nextBS hl
			if (hdrWireLength hdr == 0) 
				then return []
				else (:) <$> pure (hdr,parsePacket $ B.fromStrict bs) <*> readit hl

sendPacket::(Header a)=>PcapHandle->a->IO ()
sendPacket hl p = sendPacketBS hl (B.toStrict $ toBytes p)

printPacket::PcapHandle->IO Int
printPacket hl = do
	loopBS hl 1 (\_ -> print . parsePacket . B.fromStrict)

readPacket::PcapHandle->IORef (Maybe L2)->IO Int
readPacket hl r = do
	loopBS hl 1 (\_ -> (writeIORef r) . parsePacket . B.fromStrict)

readPackets::PcapHandle->Int->CallbackBS->IO Int
readPackets = loopBS 

timestamp::PktHdr->String
timestamp pr = (show $ hdrTime pr) ++ ",size: " ++ (show $ hdrWireLength pr) 

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
	if end 
		then return Nothing
		else do
			l2 <- getBytes :: Get E.Ethernet
			end <- isEmpty
			if end 
				then return Nothing
				else do
					case l2 of
						(E.Ethernet {E._ethType=0x806}) -> do 
							l3 <- getBytes :: Get A.ARP
							return $ Just $ HE l2 $ HA l3
						(E.Ethernet {E._ethType=0x800}) -> do 
							l3 <- getBytes :: Get I.IP
							end <- isEmpty
							if end 
								then return Nothing
								else do
									case l3 of
										(I.IP {I._protocol=6}) 	-> do 
											l4 <- getBytes :: Get T.TCP
											l5 <- getBytes :: Get P.Payload
											return $ Just $ HE l2 $ HI l3 $ HT l4 $ HP l5
										(I.IP {I._protocol=17}) -> do 
											l4 <- getBytes :: Get U.UDP
											l5 <- getBytes :: Get P.Payload
											return $ Just $ HE l2 $ HI l3 $ HU l4 $ HP l5
										(I.IP {I._protocol=1})  -> do 
											l4 <- getBytes :: Get IC.ICMP
											l5 <- getBytes :: Get P.Payload
											return $ Just $ HE l2 $ HI l3 $ HIC l4 $ HP l5
										_ -> return Nothing
						_ -> return Nothing

getPackets::Get [Maybe L2]
getPackets = do
    empty <- isEmpty
    if empty 
    	then return []
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
isARP = isJust . toARP

isICMP :: Maybe L2 -> Bool
isICMP = isJust . toICMP

isTCP :: Maybe L2 -> Bool
isTCP = isJust . toTCP

isUDP :: Maybe L2 -> Bool
isUDP = isJust . toUDP 

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

