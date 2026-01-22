{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StrictData #-}

{-|
Module      : NullSec.NetSeer
Description : Hardened Network Traffic Analyzer
Copyright   : (c) bad-antics, 2024
License     : NullSec Proprietary
Stability   : experimental

NullSec NetSeer - Hardened Passive Network Traffic Analysis Tool

Security Features:
  - Pure functional design (no side effects in core logic)
  - Strong type safety with newtype wrappers
  - Input validation through smart constructors
  - Bounded data structures to prevent memory exhaustion
  - Immutable data structures throughout
  - Explicit error handling (no exceptions in pure code)
-}

module Main where

import Control.Monad (when, unless, forM_)
import Control.Exception (catch, SomeException)
import Data.Bits ((.&.), shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.List (sortBy)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, mapMaybe)
import Data.Ord (comparing, Down(..))
import Data.Time.Clock (UTCTime, getCurrentTime, diffUTCTime)
import Data.Word (Word8, Word16, Word32)
import GHC.Generics (Generic)
import Numeric (showHex)
import System.Console.GetOpt
import System.Directory (doesFileExist)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)
import Text.Printf (printf)

-- ============================================================================
-- Constants
-- ============================================================================

version :: String
version = "2.0.0"

banner :: String
banner = unlines
    [ ""
    , "███╗   ██╗███████╗████████╗███████╗███████╗███████╗██████╗ "
    , "████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗"
    , "██╔██╗ ██║█████╗     ██║   ███████╗█████╗  █████╗  ██████╔╝"
    , "██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██╔══╝  ██╔══██╗"
    , "██║ ╚████║███████╗   ██║   ███████║███████╗███████╗██║  ██║"
    , "╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝"
    , "             bad-antics • Network Traffic Analyzer"
    , "═════════════════════════════════════════════════════════════"
    ]

maxPacketSize :: Int
maxPacketSize = 65535

maxFlows :: Int
maxFlows = 100000

maxPathLength :: Int
maxPathLength = 4096

-- ============================================================================
-- Validation Newtypes (Smart Constructors)
-- ============================================================================

-- | Validated IP address (prevents injection)
newtype ValidIP = ValidIP { getIP :: Word32 }
    deriving (Eq, Ord, Show, Generic)

-- | Validated port number (1-65535)
newtype ValidPort = ValidPort { getPort :: Word16 }
    deriving (Eq, Ord, Show, Generic)

-- | Validated file path
newtype ValidPath = ValidPath { getPath :: FilePath }
    deriving (Show, Generic)

-- | Validated packet data (bounded size)
newtype ValidPacket = ValidPacket { getPacketData :: ByteString }
    deriving (Show, Generic)

-- | Smart constructor for IP address
mkValidIP :: Word32 -> Either String ValidIP
mkValidIP ip
    | ip == 0 = Left "Invalid IP: 0.0.0.0"
    | otherwise = Right $ ValidIP ip

-- | Smart constructor for port
mkValidPort :: Word16 -> Either String ValidPort
mkValidPort port
    | port == 0 = Left "Invalid port: 0"
    | otherwise = Right $ ValidPort port

-- | Smart constructor for file path
mkValidPath :: FilePath -> Either String ValidPath
mkValidPath path
    | length path > maxPathLength = Left "Path too long"
    | ".." `isInfixOfStr` path = Left "Path traversal detected"
    | '\0' `elem` path = Left "Null byte in path"
    | otherwise = Right $ ValidPath path
  where
    isInfixOfStr needle haystack = needle `C8.isInfixOf` C8.pack haystack

-- | Smart constructor for packet data
mkValidPacket :: ByteString -> Either String ValidPacket
mkValidPacket bs
    | BS.null bs = Left "Empty packet"
    | BS.length bs > maxPacketSize = Left "Packet too large"
    | otherwise = Right $ ValidPacket bs

-- ============================================================================
-- Protocol Types
-- ============================================================================

data Protocol
    = TCP
    | UDP
    | ICMP
    | Unknown Word8
    deriving (Eq, Ord, Show, Generic)

protocolFromByte :: Word8 -> Protocol
protocolFromByte = \case
    1  -> ICMP
    6  -> TCP
    17 -> UDP
    n  -> Unknown n

protocolName :: Protocol -> String
protocolName TCP = "TCP"
protocolName UDP = "UDP"
protocolName ICMP = "ICMP"
protocolName (Unknown n) = "PROTO-" ++ show n

-- ============================================================================
-- Network Flow
-- ============================================================================

-- | Unique identifier for a network flow
data FlowKey = FlowKey
    { fkSrcIP   :: !ValidIP
    , fkDstIP   :: !ValidIP
    , fkSrcPort :: !ValidPort
    , fkDstPort :: !ValidPort
    , fkProto   :: !Protocol
    } deriving (Eq, Ord, Show, Generic)

-- | Statistics for a network flow
data FlowStats = FlowStats
    { fsPacketCount :: !Int
    , fsByteCount   :: !Int
    , fsFirstSeen   :: !UTCTime
    , fsLastSeen    :: !UTCTime
    , fsTcpFlags    :: ![Word8]
    } deriving (Show, Generic)

-- | Create initial flow stats
mkFlowStats :: UTCTime -> Int -> FlowStats
mkFlowStats time size = FlowStats
    { fsPacketCount = 1
    , fsByteCount = size
    , fsFirstSeen = time
    , fsLastSeen = time
    , fsTcpFlags = []
    }

-- | Update flow stats with new packet
updateFlowStats :: FlowStats -> UTCTime -> Int -> Maybe Word8 -> FlowStats
updateFlowStats !fs !time !size mflags = fs
    { fsPacketCount = fsPacketCount fs + 1
    , fsByteCount = fsByteCount fs + size
    , fsLastSeen = time
    , fsTcpFlags = maybe (fsTcpFlags fs) (: fsTcpFlags fs) mflags
    }

-- ============================================================================
-- Packet Parsing (Pure, Type-Safe)
-- ============================================================================

-- | Parsed packet information
data ParsedPacket = ParsedPacket
    { ppSrcIP   :: !ValidIP
    , ppDstIP   :: !ValidIP
    , ppSrcPort :: !ValidPort
    , ppDstPort :: !ValidPort
    , ppProto   :: !Protocol
    , ppSize    :: !Int
    , ppTcpFlags :: !(Maybe Word8)
    } deriving (Show, Generic)

-- | Parse IPv4 packet (pure function, no IO)
parseIPv4Packet :: ByteString -> Either String ParsedPacket
parseIPv4Packet bs = do
    -- Validate minimum size
    when (BS.length bs < 20) $ Left "Packet too small for IPv4"
    
    -- Extract and validate version
    let version = (BS.index bs 0 `shiftR` 4) .&. 0x0F
    when (version /= 4) $ Left $ "Not IPv4: version " ++ show version
    
    -- Extract header length
    let ihl = (BS.index bs 0 .&. 0x0F) * 4
    when (fromIntegral ihl > BS.length bs) $ Left "Invalid header length"
    
    -- Extract protocol
    let proto = protocolFromByte $ BS.index bs 9
    
    -- Extract IPs (bounds already checked)
    let srcIP = readWord32 bs 12
    let dstIP = readWord32 bs 16
    
    -- Validate IPs
    validSrcIP <- mkValidIP srcIP
    validDstIP <- mkValidIP dstIP
    
    -- Parse transport layer
    let transportData = BS.drop (fromIntegral ihl) bs
    (srcPort, dstPort, tcpFlags) <- parseTransportLayer proto transportData
    
    validSrcPort <- mkValidPort srcPort
    validDstPort <- mkValidPort dstPort
    
    Right ParsedPacket
        { ppSrcIP = validSrcIP
        , ppDstIP = validDstIP
        , ppSrcPort = validSrcPort
        , ppDstPort = validDstPort
        , ppProto = proto
        , ppSize = BS.length bs
        , ppTcpFlags = tcpFlags
        }

-- | Parse transport layer (TCP/UDP)
parseTransportLayer :: Protocol -> ByteString -> Either String (Word16, Word16, Maybe Word8)
parseTransportLayer proto bs = case proto of
    TCP | BS.length bs >= 14 -> Right
        ( readWord16 bs 0  -- src port
        , readWord16 bs 2  -- dst port
        , Just $ BS.index bs 13  -- TCP flags
        )
    UDP | BS.length bs >= 4 -> Right
        ( readWord16 bs 0  -- src port
        , readWord16 bs 2  -- dst port
        , Nothing
        )
    ICMP -> Right (0, 0, Nothing)
    _ | BS.length bs >= 4 -> Right
        ( readWord16 bs 0
        , readWord16 bs 2
        , Nothing
        )
    _ -> Left "Transport header too small"

-- | Read big-endian Word16
readWord16 :: ByteString -> Int -> Word16
readWord16 bs off =
    fromIntegral (BS.index bs off) * 256 +
    fromIntegral (BS.index bs (off + 1))

-- | Read big-endian Word32
readWord32 :: ByteString -> Int -> Word32
readWord32 bs off =
    fromIntegral (BS.index bs off) * 16777216 +
    fromIntegral (BS.index bs (off + 1)) * 65536 +
    fromIntegral (BS.index bs (off + 2)) * 256 +
    fromIntegral (BS.index bs (off + 3))

-- ============================================================================
-- Flow Table (Bounded)
-- ============================================================================

-- | Bounded flow table to prevent memory exhaustion
data FlowTable = FlowTable
    { ftFlows    :: !(Map FlowKey FlowStats)
    , ftMaxFlows :: !Int
    } deriving (Show, Generic)

-- | Create empty flow table
emptyFlowTable :: Int -> FlowTable
emptyFlowTable maxSize = FlowTable Map.empty maxSize

-- | Insert or update flow (pure)
updateFlow :: FlowTable -> FlowKey -> UTCTime -> Int -> Maybe Word8 -> FlowTable
updateFlow ft@FlowTable{..} key time size flags
    | Map.size ftFlows >= ftMaxFlows && not (Map.member key ftFlows) = ft
    | otherwise = ft { ftFlows = Map.alter updateF key ftFlows }
  where
    updateF Nothing = Just $ mkFlowStats time size
    updateF (Just stats) = Just $ updateFlowStats stats time size flags

-- | Get flow statistics
getFlowStats :: FlowTable -> [(FlowKey, FlowStats)]
getFlowStats = Map.toList . ftFlows

-- ============================================================================
-- Analysis Functions (Pure)
-- ============================================================================

-- | Security analysis results
data SecurityAnalysis = SecurityAnalysis
    { saPortScanners    :: ![ValidIP]      -- IPs with many dest ports
    , saHighVolumeFlows :: ![(FlowKey, Int)] -- High byte count flows
    , saLongDuration    :: ![(FlowKey, Double)] -- Long-lived connections
    , saUnusualPorts    :: ![(ValidPort, Int)]  -- Non-standard ports
    } deriving (Show, Generic)

-- | Analyze flows for security indicators (pure)
analyzeFlows :: [(FlowKey, FlowStats)] -> SecurityAnalysis
analyzeFlows flows = SecurityAnalysis
    { saPortScanners = findPortScanners flows
    , saHighVolumeFlows = findHighVolume flows
    , saLongDuration = findLongDuration flows
    , saUnusualPorts = findUnusualPorts flows
    }

-- | Find potential port scanners
findPortScanners :: [(FlowKey, FlowStats)] -> [ValidIP]
findPortScanners flows =
    let srcDstPorts = Map.fromListWith (++) 
            [(fkSrcIP k, [fkDstPort k]) | (k, _) <- flows]
        scanners = [(ip, length ports) | (ip, ports) <- Map.toList srcDstPorts
                                       , length ports > 100]
    in map fst $ sortBy (comparing (Down . snd)) scanners

-- | Find high-volume flows
findHighVolume :: [(FlowKey, FlowStats)] -> [(FlowKey, Int)]
findHighVolume flows =
    take 10 $ sortBy (comparing (Down . snd))
        [(k, fsByteCount s) | (k, s) <- flows]

-- | Find long-duration flows
findLongDuration :: [(FlowKey, FlowStats)] -> [(FlowKey, Double)]
findLongDuration flows =
    take 10 $ sortBy (comparing (Down . snd))
        [(k, realToFrac $ diffUTCTime (fsLastSeen s) (fsFirstSeen s)) 
         | (k, s) <- flows]

-- | Find unusual port usage
findUnusualPorts :: [(FlowKey, FlowStats)] -> [(ValidPort, Int)]
findUnusualPorts flows =
    let commonPorts = [22, 80, 443, 53, 25, 110, 143, 993, 995] :: [Word16]
        portCounts = Map.fromListWith (+)
            [(fkDstPort k, 1) | (k, _) <- flows
                              , getPort (fkDstPort k) `notElem` commonPorts]
    in take 10 $ sortBy (comparing (Down . snd)) $ Map.toList portCounts

-- ============================================================================
-- IP Formatting (Pure)
-- ============================================================================

formatIP :: ValidIP -> String
formatIP (ValidIP ip) = printf "%d.%d.%d.%d"
    ((ip `shiftR` 24) .&. 0xFF)
    ((ip `shiftR` 16) .&. 0xFF)
    ((ip `shiftR` 8) .&. 0xFF)
    (ip .&. 0xFF)

formatPort :: ValidPort -> String
formatPort (ValidPort p) = show p

formatTcpFlags :: Word8 -> String
formatTcpFlags flags = concatMap check
    [ (0x01, "F")  -- FIN
    , (0x02, "S")  -- SYN
    , (0x04, "R")  -- RST
    , (0x08, "P")  -- PSH
    , (0x10, "A")  -- ACK
    , (0x20, "U")  -- URG
    ]
  where
    check (bit, name) = if flags .&. bit /= 0 then name else "."

-- ============================================================================
-- Output Functions
-- ============================================================================

printFlowSummary :: [(FlowKey, FlowStats)] -> IO ()
printFlowSummary flows = do
    putStrLn "\n[*] Flow Summary"
    putStrLn $ replicate 70 '─'
    printf "%-15s %-6s %-15s %-6s %-6s %10s %8s\n"
        "SRC IP" "PORT" "DST IP" "PORT" "PROTO" "BYTES" "PACKETS"
    putStrLn $ replicate 70 '─'
    
    let sorted = take 20 $ sortBy (comparing (Down . fsByteCount . snd)) flows
    forM_ sorted $ \(FlowKey{..}, FlowStats{..}) ->
        printf "%-15s %-6s %-15s %-6s %-6s %10d %8d\n"
            (formatIP fkSrcIP)
            (formatPort fkSrcPort)
            (formatIP fkDstIP)
            (formatPort fkDstPort)
            (protocolName fkProto)
            fsByteCount
            fsPacketCount

printSecurityAnalysis :: SecurityAnalysis -> IO ()
printSecurityAnalysis SecurityAnalysis{..} = do
    putStrLn "\n[*] Security Analysis"
    putStrLn $ replicate 50 '─'
    
    unless (null saPortScanners) $ do
        putStrLn "\n⚠️  Potential Port Scanners:"
        forM_ (take 5 saPortScanners) $ \ip ->
            printf "    • %s\n" (formatIP ip)
    
    unless (null saHighVolumeFlows) $ do
        putStrLn "\n📊 High Volume Flows:"
        forM_ (take 5 saHighVolumeFlows) $ \(FlowKey{..}, bytes) ->
            printf "    • %s:%s → %s:%s (%d bytes)\n"
                (formatIP fkSrcIP) (formatPort fkSrcPort)
                (formatIP fkDstIP) (formatPort fkDstPort)
                bytes
    
    unless (null saUnusualPorts) $ do
        putStrLn "\n🔍 Unusual Port Activity:"
        forM_ (take 5 saUnusualPorts) $ \(port, count) ->
            printf "    • Port %s: %d connections\n" (formatPort port) count

-- ============================================================================
-- CLI Options
-- ============================================================================

data Options = Options
    { optHelp    :: Bool
    , optVerbose :: Bool
    , optMaxFlows :: Int
    } deriving Show

defaultOptions :: Options
defaultOptions = Options
    { optHelp = False
    , optVerbose = False
    , optMaxFlows = maxFlows
    }

options :: [OptDescr (Options -> Options)]
options =
    [ Option ['h'] ["help"]
        (NoArg (\o -> o { optHelp = True }))
        "Show this help"
    , Option ['v'] ["verbose"]
        (NoArg (\o -> o { optVerbose = True }))
        "Verbose output"
    , Option ['m'] ["max-flows"]
        (ReqArg (\n o -> o { optMaxFlows = read n }) "NUM")
        "Maximum flows to track"
    ]

usage :: String
usage = unlines
    [ "USAGE:"
    , "    netseer [OPTIONS] <pcap_file>"
    , ""
    , "OPTIONS:"
    , "    -h, --help           Show this help"
    , "    -v, --verbose        Verbose output"
    , "    -m, --max-flows NUM  Maximum flows to track (default: 100000)"
    , ""
    , "EXAMPLES:"
    , "    netseer capture.pcap"
    , "    netseer -v -m 50000 traffic.pcap"
    , ""
    , "NOTE: This is a demonstration tool. For actual PCAP parsing,"
    , "      use with libpcap bindings."
    ]

-- ============================================================================
-- Main
-- ============================================================================

main :: IO ()
main = do
    putStr banner
    printf "v%s\n\n" version
    
    args <- getArgs
    let (opts', nonOpts, errs) = getOpt Permute options args
        opts = foldl (flip ($)) defaultOptions opts'
    
    unless (null errs) $ do
        mapM_ putStrLn errs
        exitFailure
    
    when (optHelp opts) $ do
        putStrLn usage
        exitSuccess
    
    case nonOpts of
        [] -> do
            putStrLn "[!] No input file specified"
            putStrLn usage
            exitFailure
        (file:_) -> do
            case mkValidPath file of
                Left err -> do
                    printf "[!] Validation error: %s\n" err
                    exitFailure
                Right validPath -> do
                    exists <- doesFileExist (getPath validPath)
                    unless exists $ do
                        printf "[!] File not found: %s\n" (getPath validPath)
                        exitFailure
                    
                    printf "[*] Analyzing: %s\n" (getPath validPath)
                    printf "[*] Max flows: %d\n" (optMaxFlows opts)
                    
                    -- In a real implementation, we would parse PCAP here
                    -- For demonstration, show that the architecture is correct
                    putStrLn "\n[*] Flow table initialized"
                    putStrLn "[*] Ready for packet processing"
                    
                    let flowTable = emptyFlowTable (optMaxFlows opts)
                    printf "[*] Flow table capacity: %d\n" (ftMaxFlows flowTable)
                    
                    -- Demonstrate the pure analysis
                    let analysis = analyzeFlows (getFlowStats flowTable)
                    printSecurityAnalysis analysis
                    
                    putStrLn "\n[*] Analysis complete"
