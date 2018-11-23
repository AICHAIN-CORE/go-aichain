// Copyright 2014 The go-aichain Authors
// This file is part of the go-aichain library.
//
// The go-aichain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-aichain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-aichain library. If not, see <http://www.gnu.org/licenses/>.

// Package eth implements the AICHAIN protocol.
package eth

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/AICHAIN-CORE/go-aichain/accounts"
	"github.com/AICHAIN-CORE/go-aichain/common"
	"github.com/AICHAIN-CORE/go-aichain/common/hexutil"
	"github.com/AICHAIN-CORE/go-aichain/consensus"
	"github.com/AICHAIN-CORE/go-aichain/consensus/aiconsensus"
	"github.com/AICHAIN-CORE/go-aichain/consensus/clique"
	"github.com/AICHAIN-CORE/go-aichain/consensus/ethash"
	"github.com/AICHAIN-CORE/go-aichain/core"
	"github.com/AICHAIN-CORE/go-aichain/core/bloombits"
        "github.com/AICHAIN-CORE/go-aichain/core/rawdb"
	"github.com/AICHAIN-CORE/go-aichain/core/types"
	"github.com/AICHAIN-CORE/go-aichain/core/vm"
	"github.com/AICHAIN-CORE/go-aichain/eth/downloader"
	"github.com/AICHAIN-CORE/go-aichain/eth/filters"
	"github.com/AICHAIN-CORE/go-aichain/eth/gasprice"
	"github.com/AICHAIN-CORE/go-aichain/ethdb"
	"github.com/AICHAIN-CORE/go-aichain/event"
	"github.com/AICHAIN-CORE/go-aichain/internal/ethapi"
	"github.com/AICHAIN-CORE/go-aichain/log"
	"github.com/AICHAIN-CORE/go-aichain/miner"
	"github.com/AICHAIN-CORE/go-aichain/node"
	"github.com/AICHAIN-CORE/go-aichain/p2p"
	"github.com/AICHAIN-CORE/go-aichain/params"
	"github.com/AICHAIN-CORE/go-aichain/rlp"
	"github.com/AICHAIN-CORE/go-aichain/rpc"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
	SetBloomBitsIndexer(bbIndexer *core.ChainIndexer)
}

// AICHAIN implements the AICHAIN full node service.
type AICHAIN struct {
	config      *Config
	chainConfig *params.ChainConfig

	// Channel for shutting down the service
	shutdownChan chan bool // Channel for shutting down the AICHAIN

	// Handlers
	txPool          *core.TxPool
	blockchain      *core.BlockChain
	protocolManager *ProtocolManager
	lesServer       LesServer

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager
	MyNodeServer   *p2p.Server

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	APIBackend *EthAPIBackend

	miner      *miner.Miner
	gasPrice   *big.Int
	etherbase  common.Address
	passphrase string

	networkID     uint64
	netRPCService *ethapi.PublicNetAPI

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)
}

func (s *AICHAIN) AddLesServer(ls LesServer) {
	s.lesServer = ls
	ls.SetBloomBitsIndexer(s.bloomIndexer)
}

// New creates a new AICHAIN object (including the
// initialisation of the common AICHAIN object)
func New(ctx *node.ServiceContext, config *Config) (*AICHAIN, error) {
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.AICHAIN in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	chainDb, err := CreateDB(ctx, config, "chaindata")
	if err != nil {
		return nil, err
	}
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration", "config", chainConfig)

	eth := &AICHAIN{
		config:         config,
		chainDb:        chainDb,
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, chainConfig, &config.Ethash, config.MinerNotify, chainDb),
		shutdownChan:   make(chan bool),
		networkID:      config.NetworkId,
		gasPrice:       config.MinerGasPrice,
		etherbase:      config.Etherbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks, bloomConfirms),
	}

	log.Info("Initialising AICHAIN protocol", "versions", ProtocolVersions, "network", config.NetworkId)

	if !config.SkipBcVersionCheck {
		bcVersion := rawdb.ReadDatabaseVersion(chainDb)
		if bcVersion != core.BlockChainVersion && bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d).\n", bcVersion, core.BlockChainVersion)
		}
		rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
	}
	var (
		vmConfig    = vm.Config{EnablePreimageRecording: config.EnablePreimageRecording}
		cacheConfig = &core.CacheConfig{Disabled: config.NoPruning, TrieNodeLimit: config.TrieCache, TrieTimeLimit: config.TrieTimeout}
	)
	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, eth.chainConfig, eth.engine, vmConfig)
	if err != nil {
		return nil, err
	}
	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		eth.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	eth.bloomIndexer.Start(eth.blockchain)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = ctx.ResolvePath(config.TxPool.Journal)
	}
	eth.txPool = core.NewTxPool(config.TxPool, eth.chainConfig, eth.blockchain)

	if eth.protocolManager, err = NewProtocolManager(eth.chainConfig, config.SyncMode, config.NetworkId, eth.eventMux, eth.txPool, eth.engine, eth.blockchain, chainDb); err != nil {
		return nil, err
	}
	eth.miner = miner.New(eth, eth.chainConfig, eth.EventMux(), eth.engine)
	eth.miner.SetExtra(makeExtraData(config.MinerExtraData))

	eth.APIBackend = &EthAPIBackend{eth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.MinerGasPrice
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, gpoParams)

	return eth, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"gait",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateDB creates the chain database.
func CreateDB(ctx *node.ServiceContext, config *Config, name string) (ethdb.Database, error) {
	db, err := ctx.OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := db.(*ethdb.LDBDatabase); ok {
		db.Meter("eth/db/chaindata/")
	}
	return db, nil
}

// CreateConsensusEngine creates the required type of consensus engine instance for an AICHAIN service
func CreateConsensusEngine(ctx *node.ServiceContext, chainConfig *params.ChainConfig, config *ethash.Config, notify []string, db ethdb.Database) consensus.Engine {
	// If proof-of-authority is requested, set it up
	if chainConfig.Clique != nil {
		return clique.New(chainConfig.Clique, db)
	}
	//Set the default engine to aiconsensus
	return aiconsensus.New(chainConfig.AiConsensus, db)
	// if chainConfig.AiConsensus != nil {
	// 	return aiconsensus.New(chainConfig.AiConsensus, db)
	// }
	// Otherwise assume proof-of-work
	// switch {
	// case config.PowMode == ethash.ModeFake:
	// 	log.Warn("Ethash used in fake mode")
	// 	return ethash.NewFaker()
	// case config.PowMode == ethash.ModeTest:
	// 	log.Warn("Ethash used in test mode")
	// 	return ethash.NewTester()
	// default:
	// 	engine := ethash.New(ethash.Config{})
	// 	engine.SetThreads(-1) // Disable CPU mining
	// 	return engine
	// }
}

// APIs return the collection of RPC services the aichain package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *AICHAIN) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicEthereumAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicMinerAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.APIBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s.chainConfig, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *AICHAIN) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *AICHAIN) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			etherbase := accounts[0].Address

			s.lock.Lock()
			s.etherbase = etherbase
			s.lock.Unlock()

			log.Info("Etherbase automatically configured", "address", etherbase)
			return etherbase, nil
		}
	}
	return common.Address{}, fmt.Errorf("etherbase must be explicitly specified")
}

// SetEtherbase sets the mining reward address.
func (s *AICHAIN) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.lock.Unlock()

	s.miner.SetEtherbase(etherbase)
}

// set in js console via admin interface or wrapper from cli flags
func (self *AICHAIN) SetEtherbasePassphrase(passphrase string) {
	self.passphrase = passphrase
	self.miner.SetEtherbasePassphrase(passphrase)
}

func (s *AICHAIN) StartMining(local bool) error {
	eb, err := s.Etherbase()
	if err != nil {
		log.Error("Cannot start mining without etherbase", "err", err)
		return fmt.Errorf("etherbase missing: %v", err)
	}

	stateDb, err := s.BlockChain().StateAt(s.blockchain.CurrentBlock().Root())
	if err == nil {
		balance := stateDb.GetBalance(eb)
		if !s.BlockChain().Config().CheckMinerAccountAit(balance) {
			return fmt.Errorf("Not enough AIT for the miner account, %s AIT needed, balance of current miner account: %s AIT.\n", s.BlockChain().Config().AitNeedForMinerAccount().Text(10), balance.Div(balance, big.NewInt(1e+18)).Text(10))
		}
	} else {
		log.Error("get coinbase balance error\n", "err", err)
		os.Exit(1)
	}

	if clique, ok := s.engine.(*clique.Clique); ok {
		wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("Etherbase account unavailable locally", "err", err)
			return fmt.Errorf("signer missing: %v", err)
		}
		clique.Authorize(eb, wallet.SignHash)
	}
	if aiconsensus, ok := s.engine.(*aiconsensus.AiConsensus); ok {
		wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("Etherbase account unavailable locally", "err", err)
			return fmt.Errorf("signer missing: %v", err)
		}
		aiconsensus.AuthorizeWithPassphrase(eb, wallet.SignHashWithPassphraseCached, s.passphrase)
	}
	if local {
		// If local (CPU) mining is started, we can disable the transaction rejection
		// mechanism introduced to speed sync times. CPU mining on mainnet is ludicrous
		// so none will ever hit this path, whereas marking sync done on CPU mining
		// will ensure that private networks work in single miner mode too.
		atomic.StoreUint32(&s.protocolManager.acceptTxs, 1)
	}
	go s.miner.Start(eb)
	return nil
}

func (s *AICHAIN) StopMining()         { s.miner.Stop() }
func (s *AICHAIN) IsMining() bool      { return s.miner.Mining() }
func (s *AICHAIN) Miner() *miner.Miner { return s.miner }

func (s *AICHAIN) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *AICHAIN) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *AICHAIN) TxPool() *core.TxPool               { return s.txPool }
func (s *AICHAIN) EventMux() *event.TypeMux           { return s.eventMux }
func (s *AICHAIN) Engine() consensus.Engine           { return s.engine }
func (s *AICHAIN) ChainDb() ethdb.Database            { return s.chainDb }
func (s *AICHAIN) IsListening() bool                  { return true } // Always listening
func (s *AICHAIN) EthVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *AICHAIN) NetVersion() uint64                 { return s.networkID }
func (s *AICHAIN) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *AICHAIN) NodeServer() *p2p.Server            { return s.MyNodeServer }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *AICHAIN) Protocols() []p2p.Protocol {
	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
}

// Start implements node.Service, starting all internal goroutines needed by the
// AICHAIN protocol implementation.
func (s *AICHAIN) Start(srvr *p2p.Server) error {
	// Start the bloom bits servicing goroutines
	s.startBloomHandlers()

	// Start the RPC service
	s.netRPCService = ethapi.NewPublicNetAPI(srvr, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= srvr.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, srvr.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// AICHAIN protocol.
func (s *AICHAIN) Stop() error {
	s.bloomIndexer.Close()
	s.blockchain.Stop()
	s.protocolManager.Stop()
	if s.lesServer != nil {
		s.lesServer.Stop()
	}
	s.txPool.Stop()
	s.miner.Stop()
	s.eventMux.Stop()

	s.chainDb.Close()
	close(s.shutdownChan)
	return nil
}
