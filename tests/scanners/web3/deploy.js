// Deploy a deliberately vulnerable smart contract to the local Ganache chain.
// The contract has a classic reentrancy vulnerability.
const Web3 = require('web3');

const web3 = new Web3('http://localhost:8545');

// Simple vulnerable contract bytecode (Solidity compiled)
// Contract: VulnerableBank with deposit/withdraw reentrancy bug
const VULNERABLE_ABI = [
    {"inputs":[],"name":"deposit","outputs":[],"stateMutability":"payable","type":"function"},
    {"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"balances","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
];

// Minimal EVM bytecode for a vulnerable withdraw pattern:
// Sends ETH before updating balance (reentrancy)
const BYTECODE = '0x608060405234801561001057600080fd5b50610200806100206000396000f3fe60806040526004361061003f5760003560e01c806327e235e31461004457806339509351146100815780633ccfd60b1461008b578063d0e30db014610095575b600080fd5b34801561005057600080fd5b5061006f600480360381019061006a9190610145565b61009f565b60405190815260200160405180910390f35b005b34801561009757600080fd5b50005b61009d6100b7565b005b60006020528060005260406000206000915090505481565b3460008032815260200190815260200160002060008282546100d89190610183565b9091555050565b60003260009081526020819052604090205490508015610139573260009081526020819052604081205560405132904780156108fc02916000818181858888f19350505050158015610134573d6000803e3d6000fd5b505b50565b60006020828403121561015757600080fd5b81356001600160a01b038116811461016e57600080fd5b9392505050565b634e487b7160e01b600052601160045260246000fd5b808201808211156101a0576101a0610172565b9291505056';

async function deploy() {
    const accounts = await web3.eth.getAccounts();
    console.log('Deploying from account:', accounts[0]);

    const contract = new web3.eth.Contract(VULNERABLE_ABI);
    const deployed = await contract.deploy({ data: BYTECODE })
        .send({ from: accounts[0], gas: 500000 });

    console.log('Vulnerable contract deployed at:', deployed.options.address);

    // Deposit some ETH to make it interesting
    await web3.eth.sendTransaction({
        from: accounts[0],
        to: deployed.options.address,
        value: web3.utils.toWei('1', 'ether')
    });

    console.log('Deposited 1 ETH');
    console.log('DEPLOY_SUCCESS');
}

deploy().catch(err => {
    console.error('Deploy failed:', err.message);
    process.exit(1);
});
