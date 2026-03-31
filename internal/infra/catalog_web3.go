package infra

// Web3: blockchains, validators, wallets, and decentralized infrastructure.

const (
	Ethereum  Technology = "ethereum"
	Bitcoin   Technology = "bitcoin"
	Solana    Technology = "solana"
	Polygon   Technology = "polygon"
	Avalanche Technology = "avalanche"
	Arbitrum  Technology = "arbitrum"
	Optimism  Technology = "optimism"
	BNBChain  Technology = "bnb-chain"
	Cosmos    Technology = "cosmos"
	Polkadot  Technology = "polkadot"

	Geth       Technology = "geth"
	Nethermind Technology = "nethermind"
	Besu       Technology = "besu"
	Erigon     Technology = "erigon"
	Lighthouse Technology = "lighthouse"
	Prysm      Technology = "prysm"
	Teku       Technology = "teku"
	Lodestar   Technology = "lodestar"

	IPFS       Technology = "ipfs"
	Filecoin   Technology = "filecoin"
	Arweave    Technology = "arweave"

	Hardhat    Technology = "hardhat"
	Foundry    Technology = "foundry"
	Truffle    Technology = "truffle"
	Brownie    Technology = "brownie"
	AnchorLang Technology = "anchor"

	TheGraph   Technology = "the-graph"
	Chainlink  Technology = "chainlink"
)

func init() {
	// ── L1 Blockchains ──
	for _, m := range []*TechMeta{
		{ID: Ethereum, Name: "Ethereum", Category: CategoryWeb3, OpenSource: true, Vendor: "Ethereum Foundation", DefaultPorts: []int{8545, 8546, 30303}, Tags: []string{"l1", "evm"}},
		{ID: Bitcoin, Name: "Bitcoin", Category: CategoryWeb3, OpenSource: true, Vendor: "Bitcoin Core", DefaultPorts: []int{8332, 8333}, Tags: []string{"l1"}},
		{ID: Solana, Name: "Solana", Category: CategoryWeb3, OpenSource: true, Vendor: "Solana Foundation", DefaultPorts: []int{8899, 8900}, Tags: []string{"l1"}},
		{ID: BNBChain, Name: "BNB Chain", Category: CategoryWeb3, OpenSource: true, Vendor: "Binance", Tags: []string{"l1", "evm"}, Aliases: []string{"bsc", "binance-smart-chain"}},
		{ID: Cosmos, Name: "Cosmos", Category: CategoryWeb3, OpenSource: true, Vendor: "Interchain Foundation", DefaultPorts: []int{26656, 26657}, Tags: []string{"l1", "ibc"}},
		{ID: Polkadot, Name: "Polkadot", Category: CategoryWeb3, OpenSource: true, Vendor: "Web3 Foundation", DefaultPorts: []int{9944, 30333}, Tags: []string{"l1"}},
		{ID: Avalanche, Name: "Avalanche", Category: CategoryWeb3, OpenSource: true, Vendor: "Ava Labs", DefaultPorts: []int{9650, 9651}, Tags: []string{"l1", "evm"}},
	} {
		Register(m)
	}

	// ── L2 / Rollups ──
	for _, m := range []*TechMeta{
		{ID: Polygon, Name: "Polygon", Category: CategoryWeb3, OpenSource: true, Vendor: "Polygon Labs", Tags: []string{"l2", "evm"}},
		{ID: Arbitrum, Name: "Arbitrum", Category: CategoryWeb3, OpenSource: true, Vendor: "Offchain Labs", Tags: []string{"l2", "evm", "rollup"}},
		{ID: Optimism, Name: "Optimism", Category: CategoryWeb3, OpenSource: true, Vendor: "OP Labs", Tags: []string{"l2", "evm", "rollup"}},
	} {
		Register(m)
	}

	// ── Ethereum Execution Clients ──
	for _, m := range []*TechMeta{
		{ID: Geth, Name: "Geth", Category: CategoryWeb3, OpenSource: true, Vendor: "Ethereum Foundation", DefaultPorts: []int{8545, 8546, 30303}, DockerImage: "ethereum/client-go:latest", Tags: []string{"execution-client", "evm"}, Aliases: []string{"go-ethereum"}},
		{ID: Nethermind, Name: "Nethermind", Category: CategoryWeb3, OpenSource: true, Vendor: "Nethermind", DefaultPorts: []int{8545, 30303}, DockerImage: "nethermind/nethermind:latest", Tags: []string{"execution-client", "evm"}},
		{ID: Besu, Name: "Hyperledger Besu", Category: CategoryWeb3, OpenSource: true, Vendor: "Hyperledger/ConsenSys", DefaultPorts: []int{8545, 30303}, DockerImage: "hyperledger/besu:latest", Tags: []string{"execution-client", "evm"}},
		{ID: Erigon, Name: "Erigon", Category: CategoryWeb3, OpenSource: true, Vendor: "Erigon", DefaultPorts: []int{8545, 30303}, Tags: []string{"execution-client", "evm"}},
	} {
		Register(m)
	}

	// ── Ethereum Consensus Clients ──
	for _, m := range []*TechMeta{
		{ID: Lighthouse, Name: "Lighthouse", Category: CategoryWeb3, OpenSource: true, Vendor: "Sigma Prime", DefaultPorts: []int{5052, 9000}, Tags: []string{"consensus-client", "validator"}},
		{ID: Prysm, Name: "Prysm", Category: CategoryWeb3, OpenSource: true, Vendor: "Offchain Labs", DefaultPorts: []int{3500, 4000, 13000}, Tags: []string{"consensus-client", "validator"}},
		{ID: Teku, Name: "Teku", Category: CategoryWeb3, OpenSource: true, Vendor: "ConsenSys", DefaultPorts: []int{5051, 9000}, DockerImage: "consensys/teku:latest", Tags: []string{"consensus-client", "validator"}},
		{ID: Lodestar, Name: "Lodestar", Category: CategoryWeb3, OpenSource: true, Vendor: "ChainSafe", DefaultPorts: []int{9596, 9000}, Tags: []string{"consensus-client", "validator"}},
	} {
		Register(m)
	}

	// ── Decentralized Storage ──
	for _, m := range []*TechMeta{
		{ID: IPFS, Name: "IPFS", Category: CategoryWeb3, OpenSource: true, Vendor: "Protocol Labs", DefaultPorts: []int{4001, 5001, 8080}, DockerImage: "ipfs/kubo:latest", Tags: []string{"storage", "p2p"}},
		{ID: Filecoin, Name: "Filecoin", Category: CategoryWeb3, OpenSource: true, Vendor: "Protocol Labs", Tags: []string{"storage", "l1"}},
		{ID: Arweave, Name: "Arweave", Category: CategoryWeb3, OpenSource: true, Vendor: "Arweave", Tags: []string{"storage", "permanent"}},
	} {
		Register(m)
	}

	// ── Smart Contract Dev Frameworks ──
	for _, m := range []*TechMeta{
		{ID: Hardhat, Name: "Hardhat", Category: CategoryWeb3, OpenSource: true, Vendor: "Nomic Foundation", Tags: []string{"dev-framework", "evm"}},
		{ID: Foundry, Name: "Foundry", Category: CategoryWeb3, OpenSource: true, Vendor: "Paradigm", Tags: []string{"dev-framework", "evm"}, Aliases: []string{"forge"}},
		{ID: Truffle, Name: "Truffle", Category: CategoryWeb3, OpenSource: true, Vendor: "ConsenSys", Tags: []string{"dev-framework", "evm"}},
		{ID: Brownie, Name: "Brownie", Category: CategoryWeb3, OpenSource: true, Vendor: "Community", Tags: []string{"dev-framework", "evm", "python"}},
		{ID: AnchorLang, Name: "Anchor", Category: CategoryWeb3, OpenSource: true, Vendor: "Coral/Backpack", Tags: []string{"dev-framework", "solana"}},
	} {
		Register(m)
	}

	// ── Middleware / Oracles / Indexing ──
	for _, m := range []*TechMeta{
		{ID: TheGraph, Name: "The Graph", Category: CategoryWeb3, OpenSource: true, Vendor: "The Graph Foundation", Tags: []string{"indexing", "subgraph"}},
		{ID: Chainlink, Name: "Chainlink", Category: CategoryWeb3, OpenSource: true, Vendor: "Chainlink Labs", Tags: []string{"oracle"}},
	} {
		Register(m)
	}
}
