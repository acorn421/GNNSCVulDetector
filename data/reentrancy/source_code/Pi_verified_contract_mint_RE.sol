/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a reward distribution contract after updating the user's balance but before updating the total supply. This creates a window where the contract state is inconsistent, allowing for multi-transaction exploitation patterns.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IRewardDistributor(rewardDistributor).notifyMint(msg.sender, amount)` 
 * 2. Positioned the external call after `balances[msg.sender] += amount` but before `totalSupply += amount`
 * 3. This violates the Checks-Effects-Interactions pattern by placing an external call between critical state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Owner calls mint(1000) → balances[owner] increases by 1000 → external call to rewardDistributor → if rewardDistributor is malicious, it can call mint again in the same transaction context but this would fail due to owner check
 * 
 * However, the real exploitation occurs across multiple transactions:
 * 1. **Transaction 1**: Owner calls mint(1000) → balances[owner] = 1000, totalSupply still old value → external call happens → totalSupply finally updated
 * 2. **Transaction 2**: Malicious rewardDistributor contract (if owner is compromised) can observe the inconsistent state and exploit timing windows
 * 3. **Transaction 3**: Multiple mint calls can be orchestrated to exploit the window where balances are updated but totalSupply lags behind
 * 
 * **Why Multi-Transaction Dependency:**
 * - The vulnerability creates a persistent state inconsistency window between balance updates and totalSupply updates
 * - External observers can detect this inconsistency across transactions
 * - The exploit requires building up state over multiple calls where the contract's invariants are temporarily broken
 * - Each transaction leaves the contract in a slightly inconsistent state that can be exploited by subsequent transactions
 * 
 * **State Accumulation Pattern:**
 * - Multiple mint operations can be called in sequence where each leaves a brief inconsistency
 * - Over time, these inconsistencies can accumulate if the external contract is designed to exploit the timing
 * - The vulnerability is stateful because each call builds upon the previous state modifications
 */
pragma solidity ^0.4.11;

contract IRewardDistributor {
    function notifyMint(address recipient, uint256 amount) public;
}

contract Pi {
    uint256 public totalSupply;
    string public name;
    uint256 public decimals;
    string public symbol;
    address public owner;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    address public rewardDistributor;

    function Pi(uint256 _totalSupply, string _symbol, string _name, uint8 _decimalUnits) public {
        decimals = _decimalUnits;
        symbol = _symbol;
        name = _name;
        owner = msg.sender;
        totalSupply = _totalSupply * (10 ** decimals);
        balances[msg.sender] = totalSupply;
    }

    //Fix for short address attack against ERC20
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length == size + 4);
        _;
    } 

    function balanceOf(address _owner) constant public returns (uint256) {
        return balances[_owner];
    }

    function transfer(address _recipient, uint256 _value) onlyPayloadSize(2*32) public {
        require(balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] -= _value;
        balances[_recipient] += _value;
        Transfer(msg.sender, _recipient, _value);        
    }

    function transferFrom(address _from, address _to, uint256 _value) public {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }

    function approve(address _spender, uint256 _value) public {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
    }

    function allowance(address _owner, address _spender) constant public returns (uint256) {
        return allowed[_owner][_spender];
    }

    function mint(uint256 amount) public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        assert(amount >= 0);
        require(msg.sender == owner);
        balances[msg.sender] += amount;
        
        // Notify reward distribution contract about minting
        if (rewardDistributor != address(0)) {
            IRewardDistributor(rewardDistributor).notifyMint(msg.sender, amount);
        }
        
        totalSupply += amount;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    //Event which is triggered to log all transfers to this contract's event log
    event Transfer(
        address indexed _from,
        address indexed _to,
        uint256 _value
        );
        
    //Event which is triggered whenever an owner approves a new allowance for a spender.
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint256 _value
        );

}
