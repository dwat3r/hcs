-- Description: A program using PCS to analyze a pcap file and graph
-- the sequence numbers
module Tcp_seq where

import Network.Pcap hiding (sendPacket)
import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Data.Word
import Control.Lens
import Network.Connector
import Control.Monad
import Control.Concurrent(threadDelay)
import Network.Packet
import qualified Network.Ethernet as E
import qualified Network.IP as I
import qualified Network.TCP as T
import qualified Network.Payload as P
import System.Environment
import System.Exit

usage   = putStrLn "Usage: Tcp_seq <file> <source ip> <dest ip> <source port> <dest port>"
noFile  = putStrLn "Error: no file found with given name"
exit    = exitWith ExitSuccess
die     = exitWith (ExitFailure 1)

main = do
	args <- getArgs
	if length args /= 5 then usage >> die
	else do
		let [file,sip,dip,spt,dpt] = args
		packets <- parseDumpFile file
		let nps = zip [1..] packets
		let	filt (n,(ph,ml2)) = (isTCP ml2)
							  && (i^.I.source == (read sip::IPAddr))
							  && (i^.I.dest   == (read dip::IPAddr))
							  && (t^.T.flags & T.ack)
							  && (t^.T.source == (read spt::Word16))
							  && (t^.T.dest   == (read dpt::Word16))
					        where (e,i,t,p) = grab ml2
		let pkts@(_:ps) = filter filt nps
		putStrLn $ unlines [ "Duplicate packets at:" ++ show x | y@((x,_),_) <- zip pkts ps, dup y]
			where
				grab = get4 . fromJust . toTCP

				dup ((n1,(_,ml21)),(n2,(_,ml22))) = t1^.T.acknum >= t2^.T.acknum 
					where 
						[(e1,i1,t1,p1),(e2,i2,t2,p2)] = map grab [ml21,ml22]
