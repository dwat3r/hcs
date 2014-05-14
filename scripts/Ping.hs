{-# LANGUAGE TypeOperators #-}
module Main where

import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Control.Lens
import Network.Connector
import Control.Monad
import Network.Packet
import qualified Network.Ethernet as E
import qualified Network.ARP as A
import qualified Network.IP as I
import qualified Network.ICMP as IC
import qualified Network.Payload as P
import System.Environment
import System.Exit
import Data.IORef

usage   = putStrLn "Usage: ping interface ip <gateway ip>"
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

request::IPAddr->String->MACAddr->MACAddr->(E.Ethernet:+:I.IP:+:IC.ICMP:+:P.Payload)
request si di sm dm = 	(E.ethernet 	& E.dest   .~ dm 
										& E.source .~ sm) +++ 
						(I.ip 	& I.source .~ si
					  			& I.dest   .~ (read di::IPAddr)
					  			& I.ttl	 .~ 64) +++ 
						(IC.icmpEchoRequest) +++
						(P.payload & P.content .~ (B.pack [0..47]))
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
			filterPacket i ("dst " ++ show sip ++ " && arp")
			sendPacket i (arpreq sip sha gateway)
			ptr<-newIORef Nothing
			readPacket i ptr
			arpresp <- readIORef ptr
			let getmac = (^.A.sha) . (^._2) . get2 . fromJust . toARP
			sendPacket i $ request sip dip sha (getmac arpresp)
			filterPacket i "icmp"
			printPacket i >> exit