// Copyright 2016 The go-aichain Authors
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

package params

import (
	"fmt"
	"math/big"

	"github.com/AICHAIN-CORE/go-aichain/common"
	"github.com/AICHAIN-CORE/go-aichain/common/hexutil"
)

var (
	MainnetGenesisHash = common.HexToHash("0x84ba29088566df091e2e7214ca338b4c6f7fda8a52c0454fd134b0e485da1d3a") // Mainnet genesis hash to enforce below configs on
	TestnetGenesisHash = common.HexToHash("0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d") // Testnet genesis hash to enforce below configs on
)

var (
	// MainnetChainConfig is the chain parameters to run a node on the main network.
	MainnetChainConfig = &ChainConfig{
		ChainID:             big.NewInt(18376426810067278), // this is the HEX binary: "AICHAIN", convirt to bigint as network ID
		TotalRewardBlockNum: big.NewInt(1250000000),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      false,
		EIP150Block:         nil,
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: nil,
		Ethash:              new(EthashConfig),
		AiConsensus: &AiConsensusConfig{
			MaxValidatorNumber:            10,
			MaxPooledMinerNumber:          10,
			Period:                        1,
			BlockValidNumber:              12,
			Epoch:                         1200,
			VoteEpoch:                     30000,
			EthashDifficulty:              big.NewInt(10000000),
			ExtraData:                     hexutil.MustDecode("0x00000000000000000000000000000000000000000000000000000000000000000a9bcaccef0d131b37e51c8ffcf5bb1651ecc405f6cc874e476c25c1fdc4c601829f17c8b3b06cbd773cf4f94d5062c590bceecfd0d446114e09a86b4441ae7572a2a94111403167bb4a2d4f4ed3e74cfebf670c598ca813d4888b7585db462391614b07256086cf6486057b33d9f23626076becd26034362e1762aeb5f01166b2f694f4fb19fb272377e38ab5f714bd29a48423ea8e96ef7e35df8e6876aabc0487e85216ea4365634b7ac29b70ea8baeeadc52e73f0eee87efb2d3583210ecf42a03d5bead8cb7300a58971525fb7c8ef19b3faa18c6156ec5ae4a3f705c8e6238575ba6d99ae608e93c5a4894bba336e568fca5fae3784df77b91be85ab990179936f3037f2e66315410d58d278124918f79914d9e4b497287fd48fff8f6feae623a26c49e08a871defe4f774dcdcc10dab8f45643a44070a3f0cb2e89d48aee35cec145d3ce061dc99fe2fae8aad527fefdabccb01855499673b57592322621904c51c31a84bd7be6d7e39c74c74710e25cee1931d2fed7ab0f20266f6361f6d336218a52698ab48ab21ec9b239319820000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			ForkBlockNumber:               328800,
			GasLimitSoftForkBlockNumber:   5204928,
			ExtraPeriod:                   4,
			ExtraPeriodForkBlockNumber:    8145252,
			FixExtraPeriodForkBlockNumber: 8258532,
		},
	}

	// MainnetTrustedCheckpoint contains the light client trusted checkpoint for the main network.
	MainnetTrustedCheckpoint = &TrustedCheckpoint{
		Name:         "mainnet",
		SectionIndex: 195,
		SectionHead:  common.HexToHash("0x1cdd2a84cf6c1261ffccc88f6bcefb513abd7934a96c1e909fbf74767560f16b"),
		CHTRoot:      common.HexToHash("0xe453333c20391d16b91b6fe11c104704f62c8dba15f69db73b4cdf7e100105eb"),
		BloomRoot:    common.HexToHash("0x47f30069473072e00d2cdca146dce40f0aad243dfc8221bf810822c091674efe"),
	}

	// TestnetChainConfig contains the chain parameters to run a node on the Ropsten test network.
	TestnetChainConfig = &ChainConfig{
		ChainID:             big.NewInt(0x41495454), // this is the HEX binary: "AITT", convirt to bigint as network ID
		TotalRewardBlockNum: big.NewInt(1250000000),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      false,
		EIP150Block:         nil,
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: nil,
		Ethash:              new(EthashConfig),
		AiConsensus: &AiConsensusConfig{
			MaxValidatorNumber:            4,
			MaxPooledMinerNumber:          4,
			Period:                        1,
			BlockValidNumber:              12,
			Epoch:                         120,
			VoteEpoch:                     30000,
			EthashDifficulty:              big.NewInt(10000),
			ExtraData:                     hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000043fa63f6e587975e93670ace6ab5a71061c1dafa47acbcffa2cccf1ce3e8631e7620a94823605e4f34eae4b8e5d2bed9cddfd6b309f965a27759bad96c40cee6c6692307dda2ff1a33860855fc3b39f1004beb845896ae589fbee97f37e3bff49cb68a3aa6cae15f60311b0990bd3e8545d1b19431094001948e0c1c6aaa39a5cf563e09e941e9c262c87b624007a7500fbb6a7c86fd3c272c77e6cf849af65d5ce0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			ForkBlockNumber:               360000,
			GasLimitSoftForkBlockNumber:   5204928,
			ExtraPeriod:                   4,
			ExtraPeriodForkBlockNumber:    8145252,
			FixExtraPeriodForkBlockNumber: 8258532,
		},
	}

	// TestnetTrustedCheckpoint contains the light client trusted checkpoint for the Ropsten test network.
	TestnetTrustedCheckpoint = &TrustedCheckpoint{
		Name:         "testnet",
		SectionIndex: 126,
		SectionHead:  common.HexToHash("0x48f7dd4c9c60be04bf15fd4d0bcac46ddd8caf6b01d6fb8f8e1f7955cdd1337a"),
		CHTRoot:      common.HexToHash("0x6e54cb80a1884881ea1a114243af9012c95e0296b47f103b5ab124313968508e"),
		BloomRoot:    common.HexToHash("0xb55accf6dce6455b47db8510d15eff38d0ed7378829f3036d26b48e7d15da3f6"),
	}

	// RinkebyChainConfig contains the chain parameters to run a node on the Rinkeby test network.
	RinkebyChainConfig = &ChainConfig{
		ChainID:             big.NewInt(4),
		TotalRewardBlockNum: big.NewInt(1250000000),
		HomesteadBlock:      big.NewInt(1),
		DAOForkBlock:        nil,
		DAOForkSupport:      false,
		EIP150Block:         nil,
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: nil,
		Clique: &CliqueConfig{
			Period: 15,
			Epoch:  30000,
		},
	}

	// RinkebyTrustedCheckpoint contains the light client trusted checkpoint for the Rinkeby test network.
	RinkebyTrustedCheckpoint = &TrustedCheckpoint{
		Name:         "rinkeby",
		SectionIndex: 93,
		SectionHead:  common.HexToHash("0xdefb94aa217ab38f2919f7318d1d5476bd2aabf1ec9148047fe03e555615e0b4"),
		CHTRoot:      common.HexToHash("0x52c98c2fe508a8332c27dc10538f3fead43306e2b22b597587763c2fe6586da6"),
		BloomRoot:    common.HexToHash("0x93d83be0c1b12f732b1a027ecdfb16f39b0d020b8c10bfb90e76f3b01adfc5b6"),
	}

	// AiConsensusChainConfig contains the chain parameters to run a node on the Ai consensus network.
	AiConsensusChainConfig = &ChainConfig{
		ChainID:             big.NewInt(4),
		TotalRewardBlockNum: big.NewInt(1250000000),
		HomesteadBlock:      big.NewInt(1),
		DAOForkBlock:        nil,
		DAOForkSupport:      false,
		EIP150Block:         nil,
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: nil,
		EWASMBlock:          nil,
		AiConsensus: &AiConsensusConfig{
			MaxValidatorNumber:            4,
			MaxPooledMinerNumber:          4,
			Period:                        1,
			BlockValidNumber:              12,
			Epoch:                         120,
			VoteEpoch:                     30000,
			EthashDifficulty:              big.NewInt(10000),
			ExtraData:                     hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000043fa63f6e587975e93670ace6ab5a71061c1dafa47acbcffa2cccf1ce3e8631e7620a94823605e4f34eae4b8e5d2bed9cddfd6b309f965a27759bad96c40cee6c6692307dda2ff1a33860855fc3b39f1004beb845896ae589fbee97f37e3bff49cb68a3aa6cae15f60311b0990bd3e8545d1b19431094001948e0c1c6aaa39a5cf563e09e941e9c262c87b624007a7500fbb6a7c86fd3c272c77e6cf849af65d5ce0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			ForkBlockNumber:               328800,
			GasLimitSoftForkBlockNumber:   5204928,
			ExtraPeriod:                   4,
			ExtraPeriodForkBlockNumber:    8145252,
			FixExtraPeriodForkBlockNumber: 8258532,
		},
	}

	// AllEthashProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the AICHAIN core developers into the Ethash consensus.
	//
	// This configuration is intentionally not using keyed fields to force anyone
	// adding flags to the config to also have to set these fields.
	AllEthashProtocolChanges = &ChainConfig{big.NewInt(1337), big.NewInt(1250000000), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, new(EthashConfig), nil,
		&AiConsensusConfig{
			MaxValidatorNumber:            10,
			MaxPooledMinerNumber:          10,
			Period:                        1,
			BlockValidNumber:              12,
			Epoch:                         1200,
			VoteEpoch:                     30000,
			EthashDifficulty:              big.NewInt(10000000),
			ExtraData:                     hexutil.MustDecode("0x00000000000000000000000000000000000000000000000000000000000000000a9bcaccef0d131b37e51c8ffcf5bb1651ecc405f6cc874e476c25c1fdc4c601829f17c8b3b06cbd773cf4f94d5062c590bceecfd0d446114e09a86b4441ae7572a2a94111403167bb4a2d4f4ed3e74cfebf670c598ca813d4888b7585db462391614b07256086cf6486057b33d9f23626076becd26034362e1762aeb5f01166b2f694f4fb19fb272377e38ab5f714bd29a48423ea8e96ef7e35df8e6876aabc0487e85216ea4365634b7ac29b70ea8baeeadc52e73f0eee87efb2d3583210ecf42a03d5bead8cb7300a58971525fb7c8ef19b3faa18c6156ec5ae4a3f705c8e6238575ba6d99ae608e93c5a4894bba336e568fca5fae3784df77b91be85ab990179936f3037f2e66315410d58d278124918f79914d9e4b497287fd48fff8f6feae623a26c49e08a871defe4f774dcdcc10dab8f45643a44070a3f0cb2e89d48aee35cec145d3ce061dc99fe2fae8aad527fefdabccb01855499673b57592322621904c51c31a84bd7be6d7e39c74c74710e25cee1931d2fed7ab0f20266f6361f6d336218a52698ab48ab21ec9b239319820000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			ForkBlockNumber:               328800,
			GasLimitSoftForkBlockNumber:   5204928,
			ExtraPeriod:                   4,
			ExtraPeriodForkBlockNumber:    8137200,
			FixExtraPeriodForkBlockNumber: 8258532,
		}}

	// AllCliqueProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the AICHAIN core developers into the Clique consensus.
	//
	// This configuration is intentionally not using keyed fields to force anyone
	// adding flags to the config to also have to set these fields.
	AllCliqueProtocolChanges = &ChainConfig{big.NewInt(1337), big.NewInt(1250000000), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, nil, &CliqueConfig{Period: 0, Epoch: 30000}, nil}

	// AllAiConsensusProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the AICHAIN core developers into the AiConsensus consensus.
	//
	// This configuration is intentionally not using keyed fields to force anyone
	// adding flags to the config to also have to set these fields.
	AllAiConsensusProtocolChanges = &ChainConfig{big.NewInt(1337), big.NewInt(1250000000), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, nil, nil,
		&AiConsensusConfig{
			MaxValidatorNumber:            4,
			MaxPooledMinerNumber:          4,
			Period:                        1,
			BlockValidNumber:              12,
			Epoch:                         120,
			VoteEpoch:                     30000,
			EthashDifficulty:              big.NewInt(10000),
			ExtraData:                     hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000043fa63f6e587975e93670ace6ab5a71061c1dafa47acbcffa2cccf1ce3e8631e7620a94823605e4f34eae4b8e5d2bed9cddfd6b309f965a27759bad96c40cee6c6692307dda2ff1a33860855fc3b39f1004beb845896ae589fbee97f37e3bff49cb68a3aa6cae15f60311b0990bd3e8545d1b19431094001948e0c1c6aaa39a5cf563e09e941e9c262c87b624007a7500fbb6a7c86fd3c272c77e6cf849af65d5ce0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			ForkBlockNumber:               328800,
			GasLimitSoftForkBlockNumber:   5204928,
			ExtraPeriod:                   4,
			ExtraPeriodForkBlockNumber:    8145252,
			FixExtraPeriodForkBlockNumber: 8258532,
		}}

	//TestChainConfig
	TestChainConfig = &ChainConfig{big.NewInt(1), big.NewInt(1250000000), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, new(EthashConfig), nil,
		&AiConsensusConfig{
			MaxValidatorNumber:            4,
			MaxPooledMinerNumber:          4,
			Period:                        1,
			BlockValidNumber:              12,
			Epoch:                         120,
			VoteEpoch:                     30000,
			EthashDifficulty:              big.NewInt(10000),
			ExtraData:                     hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000023fa63f6e587975e93670ace6ab5a71061c1dafa47acbcffa2cccf1ce3e8631e7620a94823605e4f304beb845896ae589fbee97f37e3bff49cb68a3aa6cae15f60311b0990bd3e8545d1b19431094001948e0c1c6aaa39a5cf563e09e941e9c262c87b624007a7500fbb6a7c86fd3c272c77e6cf849af65d5ce0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
			ForkBlockNumber:               360000,
			GasLimitSoftForkBlockNumber:   5204928,
			ExtraPeriod:                   4,
			ExtraPeriodForkBlockNumber:    8145252,
			FixExtraPeriodForkBlockNumber: 8258532,
		}}
	TestRules = TestChainConfig.Rules(new(big.Int))
)

// TrustedCheckpoint represents a set of post-processed trie roots (CHT and
// BloomTrie) associated with the appropriate section index and head hash. It is
// used to start light syncing from this checkpoint and avoid downloading the
// entire header chain while still being able to securely access old headers/logs.
type TrustedCheckpoint struct {
	Name         string      `json:"-"`
	SectionIndex uint64      `json:"sectionIndex"`
	SectionHead  common.Hash `json:"sectionHead"`
	CHTRoot      common.Hash `json:"chtRoot"`
	BloomRoot    common.Hash `json:"bloomRoot"`
}

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // chainId identifies the current chain and is used for replay protection
	TotalRewardBlockNum *big.Int `json:"totalRewardBlockNum,omitempty"`
	HomesteadBlock *big.Int `json:"homesteadBlock,omitempty"` // Homestead switch block (nil = no fork, 0 = already homestead)

	DAOForkBlock   *big.Int `json:"daoForkBlock,omitempty"`   // TheDAO hard-fork switch block (nil = no fork)
	DAOForkSupport bool     `json:"daoForkSupport,omitempty"` // Whether the nodes supports or opposes the DAO hard-fork

	// EIP150 implements the Gas price changes (https://github.com/AICHAIN-CORE/EIPs/issues/150)
	EIP150Block *big.Int    `json:"eip150Block,omitempty"` // EIP150 HF block (nil = no fork)
	EIP150Hash  common.Hash `json:"eip150Hash,omitempty"`  // EIP150 HF hash (needed for header only clients as only gas pricing changed)

	EIP155Block *big.Int `json:"eip155Block,omitempty"` // EIP155 HF block
	EIP158Block *big.Int `json:"eip158Block,omitempty"` // EIP158 HF block

	ByzantiumBlock      *big.Int `json:"byzantiumBlock,omitempty"`      // Byzantium switch block (nil = no fork, 0 = already on byzantium)
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"` // Constantinople switch block (nil = no fork, 0 = already activated)
	EWASMBlock          *big.Int `json:"ewasmBlock,omitempty"`          // EWASM switch block (nil = no fork, 0 = already activated)

	// Various consensus engines
	Ethash      *EthashConfig      `json:"ethash,omitempty"`
	Clique      *CliqueConfig      `json:"clique,omitempty"`
	AiConsensus *AiConsensusConfig `json:"aiconsensus,omitempty"`
}

// EthashConfig is the consensus engine configs for proof-of-work based sealing.
type EthashConfig struct{}

// String implements the stringer interface, returning the consensus engine details.
func (c *EthashConfig) String() string {
	return "ethash"
}

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
type CliqueConfig struct {
	Period uint64 `json:"period"` // Number of seconds between blocks to enforce
	Epoch  uint64 `json:"epoch"`  // Epoch length to reset votes and checkpoint
}

// String implements the stringer interface, returning the consensus engine details.
func (c *CliqueConfig) String() string {
	return "clique"
}

// AiConsensusConfig is the consensus engine configs for proof-of-authority based sealing.
type AiConsensusConfig struct {
	MaxValidatorNumber            int      `json:"max-validator-number"`              // Max number of Validator allowed
	MaxPooledMinerNumber          int      `json:"max-pooledminer-number"`            // Max number of Pooled miner allowed
	Period                        uint64   `json:"period"`                            // Number of seconds between blocks to enforce
	ExtraPeriod                   uint64   `json:"extra-period"`                      // Extra Number of seconds between blocks to enforce, if there is no tx in blocks.
	BlockValidNumber              uint64   `json:"block-valid-number"`                // Number of block to verify
	Epoch                         uint64   `json:"epoch"`                             // Epoch length to reset checkpoint
	VoteEpoch                     uint64   `json:"vote-epoch"`                        // Epoch length to reset votes
	EthashDifficulty              *big.Int `json:"ethash-difficulty"`                 // Difficulty to ethash mine
	ExtraData                     []byte   `json:"extra-data"`                        //Extra data for genesis
	ForkBlockNumber               uint64   `json:"fork-blockNumber"`                  //Block number to start engine fork
	GasLimitSoftForkBlockNumber   uint64   `json:"gaslimit-fork-blockNumber"`         //Block number to gas limit fork
	ExtraPeriodForkBlockNumber    uint64   `json:"extra-period-fork-blockNumber"`     //Block number to extra period
	FixExtraPeriodForkBlockNumber uint64   `json:"fix-extra-period-fork-blockNumber"` //Block number to fix extra period
	Standalone                    bool     `json:"standalone"`                        //If the engine is standalone
}

// String implements the stringer interface, returning the consensus engine details.
func (c *AiConsensusConfig) String() string {
	return "aiconsensus"
}

// String implements the fmt.Stringer interface.
func (c *ChainConfig) String() string {
	var engine interface{}
	switch {
	case c.AiConsensus != nil:
		engine = c.AiConsensus
	case c.Ethash != nil:
		engine = c.Ethash
	case c.Clique != nil:
		engine = c.Clique
	default:
		engine = "unknown"
	}
	return fmt.Sprintf("{ChainID: %v Homestead: %v DAO: %v DAOSupport: %v EIP150: %v EIP155: %v EIP158: %v Byzantium: %v Constantinople: %v Engine: %v}",
		c.ChainID,
		c.HomesteadBlock,
		c.DAOForkBlock,
		c.DAOForkSupport,
		c.EIP150Block,
		c.EIP155Block,
		c.EIP158Block,
		c.ByzantiumBlock,
		c.ConstantinopleBlock,
		engine,
	)
}

// IsHomestead returns whether num is either equal to the homestead block or greater.
func (c *ChainConfig) IsHomestead(num *big.Int) bool {
	return isForked(c.HomesteadBlock, num)
}

// IsDAOFork returns whether num is either equal to the DAO fork block or greater.
func (c *ChainConfig) IsDAOFork(num *big.Int) bool {
	return isForked(c.DAOForkBlock, num)
}

// IsEIP150 returns whether num is either equal to the EIP150 fork block or greater.
func (c *ChainConfig) IsEIP150(num *big.Int) bool {
	return isForked(c.EIP150Block, num)
}

// IsEIP155 returns whether num is either equal to the EIP155 fork block or greater.
func (c *ChainConfig) IsEIP155(num *big.Int) bool {
	return isForked(c.EIP155Block, num)
}

// IsEIP158 returns whether num is either equal to the EIP158 fork block or greater.
func (c *ChainConfig) IsEIP158(num *big.Int) bool {
	return isForked(c.EIP158Block, num)
}

// IsByzantium returns whether num is either equal to the Byzantium fork block or greater.
func (c *ChainConfig) IsByzantium(num *big.Int) bool {
	return isForked(c.ByzantiumBlock, num)
}

// IsConstantinople returns whether num is either equal to the Constantinople fork block or greater.
func (c *ChainConfig) IsConstantinople(num *big.Int) bool {
	return isForked(c.ConstantinopleBlock, num)
}

// IsEWASM returns whether num represents a block number after the EWASM fork
func (c *ChainConfig) IsEWASM(num *big.Int) bool {
	return isForked(c.EWASMBlock, num)
}

func (c *ChainConfig) IsCoinDelieverDone(num *big.Int) bool {
	if num == nil {
		return false
	}
	// var TotalRewardBlockNum *big.Int = big.NewInt(105000000) // after 315000000 AIT , we stop deliver AIT
	var TotalRewardBlockNum *big.Int = big.NewInt(1250000000) // after 315000000 AIT , we stop deliver AIT
	if c.TotalRewardBlockNum != nil {
		TotalRewardBlockNum = c.TotalRewardBlockNum
	}
	//New rewards mothod:
	//0.2*10+1+0=3 AIT/12 blocks.
	//Currently 360000*3 AIT is already mined.
	//So 315000000-360000*3=313920000 AIT counts blocks:  313920000/(3 AIT/12 blocks) =  1255680000+360000(forked)=1256040000Blocks.
	return TotalRewardBlockNum.Cmp(num) < 0
}

func (c *ChainConfig) AitNeedForMinerAccount() *big.Int {
	return big.NewInt(100000)
}

func (c *ChainConfig) CheckMinerAccountAit(num *big.Int) bool {
	if num == nil {
		return false
	}
	min := c.AitNeedForMinerAccount()
	gwei := big.NewInt(1e+18)
	min.Mul(gwei, min)
	return min.Cmp(num) <= 0
}

func (c *ChainConfig) DefaultCoinbase() string {
	if c.ChainID.Cmp(MainnetChainConfig.ChainID) == 0 {
		return "ai6846e953b9594b602bab319d1114836c2b050491"
	}
	return "aib135fb747599b830e2110b56e3c76496dc412c54"
}

func (c *ChainConfig) DefaultDifficaulty() *big.Int {
	return big.NewInt(1048576)
}

func (c *ChainConfig) DefaultMaxDifficaulty() *big.Int {
	return big.NewInt(1048576 * 4)
}

// GasTable returns the gas table corresponding to the current phase (homestead or homestead reprice).
//
// The returned GasTable's fields shouldn't, under any circumstances, be changed.
func (c *ChainConfig) GasTable(num *big.Int) GasTable {
	if num == nil {
		return GasTableHomestead
	}
	switch {
	case c.IsConstantinople(num):
		return GasTableConstantinople
	case c.IsEIP158(num):
		return GasTableEIP158
	case c.IsEIP150(num):
		return GasTableEIP150
	default:
		return GasTableHomestead
	}
}

// CheckCompatible checks whether scheduled fork transitions have been imported
// with a mismatching chain configuration.
func (c *ChainConfig) CheckCompatible(newcfg *ChainConfig, height uint64) *ConfigCompatError {
	bhead := new(big.Int).SetUint64(height)

	// Iterate checkCompatible to find the lowest conflict.
	var lasterr *ConfigCompatError
	for {
		err := c.checkCompatible(newcfg, bhead)
		if err == nil || (lasterr != nil && err.RewindTo == lasterr.RewindTo) {
			break
		}
		lasterr = err
		bhead.SetUint64(err.RewindTo)
	}
	return lasterr
}

func (c *ChainConfig) checkCompatible(newcfg *ChainConfig, head *big.Int) *ConfigCompatError {
	if isForkIncompatible(c.HomesteadBlock, newcfg.HomesteadBlock, head) {
		return newCompatError("Homestead fork block", c.HomesteadBlock, newcfg.HomesteadBlock)
	}
	if isForkIncompatible(c.DAOForkBlock, newcfg.DAOForkBlock, head) {
		return newCompatError("DAO fork block", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if c.IsDAOFork(head) && c.DAOForkSupport != newcfg.DAOForkSupport {
		return newCompatError("DAO fork support flag", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if isForkIncompatible(c.EIP150Block, newcfg.EIP150Block, head) {
		return newCompatError("EIP150 fork block", c.EIP150Block, newcfg.EIP150Block)
	}
	if isForkIncompatible(c.EIP155Block, newcfg.EIP155Block, head) {
		return newCompatError("EIP155 fork block", c.EIP155Block, newcfg.EIP155Block)
	}
	if isForkIncompatible(c.EIP158Block, newcfg.EIP158Block, head) {
		return newCompatError("EIP158 fork block", c.EIP158Block, newcfg.EIP158Block)
	}
	if c.IsEIP158(head) && !configNumEqual(c.ChainID, newcfg.ChainID) {
		return newCompatError("EIP158 chain ID", c.EIP158Block, newcfg.EIP158Block)
	}
	if isForkIncompatible(c.ByzantiumBlock, newcfg.ByzantiumBlock, head) {
		return newCompatError("Byzantium fork block", c.ByzantiumBlock, newcfg.ByzantiumBlock)
	}
	if isForkIncompatible(c.ConstantinopleBlock, newcfg.ConstantinopleBlock, head) {
		return newCompatError("Constantinople fork block", c.ConstantinopleBlock, newcfg.ConstantinopleBlock)
	}
	if isForkIncompatible(c.EWASMBlock, newcfg.EWASMBlock, head) {
		return newCompatError("ewasm fork block", c.EWASMBlock, newcfg.EWASMBlock)
	}
	return nil
}

// isForkIncompatible returns true if a fork scheduled at s1 cannot be rescheduled to
// block s2 because head is already past the fork.
func isForkIncompatible(s1, s2, head *big.Int) bool {
	return (isForked(s1, head) || isForked(s2, head)) && !configNumEqual(s1, s2)
}

// isForked returns whether a fork scheduled at block s is active at the given head block.
func isForked(s, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}

func configNumEqual(x, y *big.Int) bool {
	if x == nil {
		return y == nil
	}
	if y == nil {
		return x == nil
	}
	return x.Cmp(y) == 0
}

// ConfigCompatError is raised if the locally-stored blockchain is initialised with a
// ChainConfig that would alter the past.
type ConfigCompatError struct {
	What string
	// block numbers of the stored and new configurations
	StoredConfig, NewConfig *big.Int
	// the block number to which the local chain must be rewound to correct the error
	RewindTo uint64
}

func newCompatError(what string, storedblock, newblock *big.Int) *ConfigCompatError {
	var rew *big.Int
	switch {
	case storedblock == nil:
		rew = newblock
	case newblock == nil || storedblock.Cmp(newblock) < 0:
		rew = storedblock
	default:
		rew = newblock
	}
	err := &ConfigCompatError{what, storedblock, newblock, 0}
	if rew != nil && rew.Sign() > 0 {
		err.RewindTo = rew.Uint64() - 1
	}
	return err
}

func (err *ConfigCompatError) Error() string {
	return fmt.Sprintf("mismatching %s in database (have %d, want %d, rewindto %d)", err.What, err.StoredConfig, err.NewConfig, err.RewindTo)
}

// Rules wraps ChainConfig and is merely syntactic sugar or can be used for functions
// that do not have or require information about the block.
//
// Rules is a one time interface meaning that it shouldn't be used in between transition
// phases.
type Rules struct {
	ChainID                                   *big.Int
	IsHomestead, IsEIP150, IsEIP155, IsEIP158 bool
	IsByzantium, IsConstantinople             bool
}

// Rules ensures c's ChainID is not nil.
func (c *ChainConfig) Rules(num *big.Int) Rules {
	chainID := c.ChainID
	if chainID == nil {
		chainID = new(big.Int)
	}
	return Rules{
		ChainID:          new(big.Int).Set(chainID),
		IsHomestead:      c.IsHomestead(num),
		IsEIP150:         c.IsEIP150(num),
		IsEIP155:         c.IsEIP155(num),
		IsEIP158:         c.IsEIP158(num),
		IsByzantium:      c.IsByzantium(num),
		IsConstantinople: c.IsConstantinople(num),
	}
}
