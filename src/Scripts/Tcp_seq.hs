-- Description: A program using PCS to analyze a pcap file and graph
-- the sequence numbers
module Tcp_seq where

import Network.Pcap hiding (sendPacket)
import qualified Data.ByteString.Lazy as B
import Data.Maybe
import Data.Word
import Control.Lens
import Connector
import Control.Monad
import Control.Concurrent(threadDelay)
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.IP as I
import qualified Packet.TCP as T
import qualified Packet.Payload as P
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
		packets <- parseDumpFile (args!!0)
		print $ filter (filt args) packets
			where
				filt::[String]->(PktHdr,Maybe L2)->Bool
				filt args (ph,ml2) = (isTCP ml2) 
							&& ((get42 pkt)^.I.source == (read (args!!1)::IPAddr))
							&& ((get42 pkt)^.I.dest   == (read (args!!2)::IPAddr))
							&& ((get43 pkt)^.T.flags & T.ack)
							&& ((get43 pkt)^.T.source == (read (args!!3)::Word16))
							&& ((get43 pkt)^.T.dest   == (read (args!!4)::Word16))
					where pkt = (fromJust $ toTCP ml2) 