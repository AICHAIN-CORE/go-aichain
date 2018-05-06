// Copyright 2014 The go-aichain Authors
// This file is part of go-aichain.
//
// go-aichain is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-aichain is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-aichain. If not, see <http://www.gnu.org/licenses/>.

// gait is the official command-line client for AICHAIN.
package main

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/AICHAIN-CORE/go-aichain/accounts"
	"github.com/AICHAIN-CORE/go-aichain/accounts/keystore"
	"github.com/AICHAIN-CORE/go-aichain/cmd/utils"
	"github.com/AICHAIN-CORE/go-aichain/common"
	"github.com/AICHAIN-CORE/go-aichain/console"
	"github.com/AICHAIN-CORE/go-aichain/crypto"
	"github.com/AICHAIN-CORE/go-aichain/eth"
	"github.com/AICHAIN-CORE/go-aichain/ethclient"
	"github.com/AICHAIN-CORE/go-aichain/internal/debug"
	"github.com/AICHAIN-CORE/go-aichain/log"
	"github.com/AICHAIN-CORE/go-aichain/metrics"
	"github.com/AICHAIN-CORE/go-aichain/node"
	"gopkg.in/urfave/cli.v1"
)

const (
	clientIdentifier = "gait" // Client identifier to advertise over the network
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	// AICHAIN address of the Gait release oracle.
	relOracle = common.HexToAddress("0xfa7b9770ca4cb04296cac84f37736d4041251cdf")
	// The app that holds all commands and flags.
	app = utils.NewApp(gitCommit, "the go-aichain command line interface")
	// flags that configure the node
	nodeFlags = []cli.Flag{
		utils.IdentityFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		utils.BootnodesV4Flag,
		utils.BootnodesV5Flag,
		utils.DataDirFlag,
		utils.KeyStoreDirFlag,
		utils.NoUSBFlag,
		utils.DashboardEnabledFlag,
		utils.DashboardAddrFlag,
		utils.DashboardPortFlag,
		utils.DashboardRefreshFlag,
		utils.DashboardAssetsFlag,
		utils.TxPoolNoLocalsFlag,
		utils.TxPoolJournalFlag,
		utils.TxPoolRejournalFlag,
		utils.TxPoolPriceLimitFlag,
		utils.TxPoolPriceBumpFlag,
		utils.TxPoolAccountSlotsFlag,
		utils.TxPoolGlobalSlotsFlag,
		utils.TxPoolAccountQueueFlag,
		utils.TxPoolGlobalQueueFlag,
		utils.TxPoolLifetimeFlag,
		utils.FastSyncFlag,
		utils.LightModeFlag,
		utils.SyncModeFlag,
		utils.GCModeFlag,
		utils.LightServFlag,
		utils.LightPeersFlag,
		utils.LightKDFFlag,
		utils.CacheFlag,
		utils.CacheDatabaseFlag,
		utils.CacheGCFlag,
		utils.TrieCacheGenFlag,
		utils.ListenPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.EtherbaseFlag,
		utils.PassphraseFlag,
		utils.GasPriceFlag,
		utils.MinerThreadsFlag,
		utils.MiningEnabledFlag,
		utils.TargetGasLimitFlag,
		utils.NATFlag,
		utils.NoDiscoverFlag,
		utils.DiscoveryV5Flag,
		utils.NetrestrictFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.DeveloperFlag,
		utils.DeveloperPeriodFlag,
		utils.TestnetFlag,
		utils.RinkebyFlag,
		utils.VMEnableDebugFlag,
		utils.NetworkIdFlag,
		utils.RPCCORSDomainFlag,
		utils.RPCVirtualHostsFlag,
		utils.EthStatsURLFlag,
		utils.MetricsEnabledFlag,
		utils.FakePoWFlag,
		utils.NoCompactionFlag,
		utils.GpoBlocksFlag,
		utils.GpoPercentileFlag,
		utils.ExtraDataFlag,
		configFileFlag,
	}

	rpcFlags = []cli.Flag{
		utils.RPCEnabledFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		utils.RPCApiFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.IPCDisabledFlag,
		utils.IPCPathFlag,
	}

	whisperFlags = []cli.Flag{
		utils.WhisperEnabledFlag,
		utils.WhisperMaxMessageSizeFlag,
		utils.WhisperMinPOWFlag,
	}
)

func init() {
	// Initialize the CLI app and start Gait
	app.Action = gait
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2013-2017 The go-aichain Authors"
	app.Commands = []cli.Command{
		// See chaincmd.go:
		initCommand,
		importCommand,
		exportCommand,
		copydbCommand,
		removedbCommand,
		dumpCommand,
		// See monitorcmd.go:
		monitorCommand,
		// See accountcmd.go:
		accountCommand,
		walletCommand,
		// See consolecmd.go:
		consoleCommand,
		attachCommand,
		javascriptCommand,
		// See misccmd.go:
		versionCommand,
		bugCommand,
		licenseCommand,
		// See config.go
		dumpConfigCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = append(app.Flags, nodeFlags...)
	app.Flags = append(app.Flags, rpcFlags...)
	app.Flags = append(app.Flags, consoleFlags...)
	app.Flags = append(app.Flags, debug.Flags...)
	app.Flags = append(app.Flags, whisperFlags...)

	app.Before = func(ctx *cli.Context) error {
		runtime.GOMAXPROCS(runtime.NumCPU())
		if err := debug.Setup(ctx); err != nil {
			return err
		}
		// Start system runtime metrics collection
		go metrics.CollectProcessMetrics(3 * time.Second)

		utils.SetupNetwork(ctx)
		return nil
	}

	app.After = func(ctx *cli.Context) error {
		debug.Exit()
		console.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	fmt.Println(os.Args)
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// gait is the main entry point into the system if no special subcommand is ran.
// It creates a default node based on the command line arguments and runs it in
// blocking mode, waiting for it to be shut down.
func gait(ctx *cli.Context) error {
	node := makeFullNode(ctx)
	startNode(ctx, node)
	node.Wait()
	return nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC/IPC interfaces and the
// miner.
func startNode(ctx *cli.Context, stack *node.Node) {
	// Start up the node itself
	utils.StartNode(stack)

	// Unlock any account specifically requested
	ks := stack.AccountManager().Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)

	passwords := utils.MakePasswordList(ctx)
	unlocks := strings.Split(ctx.GlobalString(utils.UnlockedAccountFlag.Name), ",")
	for i, account := range unlocks {
		if trimmed := strings.TrimSpace(account); trimmed != "" {
			unlockAccount(ctx, ks, trimmed, i, passwords)
		}
	}
	// Register wallet event handlers to open and auto-derive wallets
	events := make(chan accounts.WalletEvent, 16)
	stack.AccountManager().Subscribe(events)

	go func() {
		// Create an chain state reader for self-derivation
		rpcClient, err := stack.Attach()
		if err != nil {
			utils.Fatalf("Failed to attach to self: %v", err)
		}
		stateReader := ethclient.NewClient(rpcClient)

		// Open any wallets already attached
		for _, wallet := range stack.AccountManager().Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			}
		}
		// Listen for wallet event till termination
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				}
			case accounts.WalletOpened:
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)

				if event.Wallet.URL().Scheme == "ledger" {
					event.Wallet.SelfDerive(accounts.DefaultLedgerBaseDerivationPath, stateReader)
				} else {
					event.Wallet.SelfDerive(accounts.DefaultBaseDerivationPath, stateReader)
				}

			case accounts.WalletDropped:
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()

	// Start auxiliary services if enabled
	if ctx.GlobalBool(utils.MiningEnabledFlag.Name) || ctx.GlobalBool(utils.DeveloperFlag.Name) {
		// Mining only makes sense if a full AICHAIN node is running
		if ctx.GlobalBool(utils.LightModeFlag.Name) || ctx.GlobalString(utils.SyncModeFlag.Name) == "light" {
			utils.Fatalf("Light clients do not support mining")
		}
		var aichain *eth.AICHAIN
		if err := stack.Service(&aichain); err != nil {
			utils.Fatalf("AICHAIN service not running: %v", err)
		}

		aichain.MyNodeServer = stack.Server()
		// Use a reduced number of threads if requested
		if threads := ctx.GlobalInt(utils.MinerThreadsFlag.Name); threads > 0 {
			type threaded interface {
				SetThreads(threads int)
			}
			if th, ok := aichain.Engine().(threaded); ok {
				th.SetThreads(threads)
			}
		}

		stateDb, err := aichain.BlockChain().StateAt(aichain.BlockChain().CurrentBlock().Root())
		if err == nil {
			coinbase, err := aichain.Etherbase()
			if err == nil {
				balance := stateDb.GetBalance(coinbase)
				if !aichain.BlockChain().Config().CheckMinerAccountAit(balance) {
					utils.Fatalf("Not enough AIT for the miner account, %s AIT needed, balance of current miner account: %s AIT.\n", aichain.BlockChain().Config().AitNeedForMinerAccount().Text(10), balance.Div(balance, big.NewInt(1e+18)).Text(10))
				}
			}
		} else {
			utils.Fatalf("get coinbase balance error: %v", err)
		}

		passphrase := ctx.GlobalString(utils.PassphraseFlag.Name)

		if passphrase == "" {
			utils.Fatalf("the passphrase of the miner account must set")
		}
		//checks miner account.
		eb, err := aichain.Etherbase()
		if err != nil || eb == (common.Address{}) {
			utils.Fatalf("the etherbase of the miner account must set: %v", err)
		}

		account := accounts.Account{Address: eb}
		wallet, err := aichain.AccountManager().Find(account)
		if err != nil {
			utils.Fatalf("Error to find miner account in keystore: %v", err)
			return
		}
		hash := crypto.Keccak256([]byte("data to sign"))
		sig, err := wallet.SignHashWithPassphrase(account, passphrase, hash)
		if err != nil {
			utils.Fatalf("Error to sign using miner account: %v", err)
		}

		// if it is!  need verify the signature : header.SigData + header.coinbase + header + ParentHash
		recoveredPubkey, err := crypto.SigToPub(hash, sig)
		if err != nil || recoveredPubkey == nil {
			utils.Fatalf("Get public key from signature error: %v", err)
		}
		recoveredAddress := crypto.PubkeyToAddress(*recoveredPubkey)
		if eb != recoveredAddress {
			utils.Fatalf("Verify public key error")
		}

		aichain.SetEtherbasePassphrase(passphrase)
		// Set the gas price to the limits from the CLI and start mining
		aichain.TxPool().SetGasPrice(utils.GlobalBig(ctx, utils.GasPriceFlag.Name))
		if err := aichain.StartMining(true); err != nil {
			utils.Fatalf("Failed to start mining: %v", err)
		}
	}
}
