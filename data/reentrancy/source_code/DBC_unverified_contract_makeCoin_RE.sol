/*
 * ===== SmartInject Injection Details =====
 * Function      : makeCoin
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a supply registry contract AFTER state updates. This creates a classic reentrancy pattern where:
 * 
 * 1. **Transaction 1**: Initial makeCoin() call updates totalSupply and balances, then makes external call to supplyRegistry.notifySupplyChange()
 * 2. **Reentrancy**: The malicious registry contract can reenter makeCoin() during the external call, causing additional state modifications
 * 3. **State Accumulation**: Multiple reentrant calls accumulate inflated totalSupply and balances values
 * 4. **Transaction 2+**: Subsequent legitimate calls operate on the corrupted state from previous reentrancy
 * 
 * The vulnerability requires multiple transactions because:
 * - Transaction 1 sets up the corrupted state through reentrancy
 * - Transaction 2+ exploits the accumulated inflated supply values
 * - The attacker needs to first deploy a malicious registry contract, then trigger the reentrancy across separate transactions
 * 
 * This is realistic because many DeFi protocols notify external registries/oracles about supply changes, and the state updates occur before the external call, creating a window for reentrancy exploitation.
 */
pragma solidity ^0.4.18;

contract DBC {
    mapping (address => uint256) private balances;
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX
    uint256 public totalSupply;
    address private originAddress;
    bool private locked;
    address public supplyRegistry; // Added missing state variable

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    
    // Moved interface outside contract body
}

// Added as a standalone contract as interface
tinterface ISupplyRegistry {
    function notifySupplyChange(uint256, uint256) external;
}

contract DBCImplementation is DBC {
    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               // Give the creator all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
        originAddress = msg.sender;
        locked = false;
    }
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(!locked);
        require(_to != address(0));
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    function setLock(bool _locked)public returns (bool){
        require(msg.sender == originAddress);
        locked = _locked;
        return true;
    }
    function burnFrom(address _who,uint256 _value)public returns (bool){
        require(msg.sender == originAddress);
        assert(balances[_who] >= _value);
        totalSupply -= _value;
        balances[_who] -= _value;
        return true;
    }
    function makeCoin(uint256 _value)public returns (bool){
        require(msg.sender == originAddress);
        totalSupply += _value;
        balances[originAddress] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external registry about supply change
        if(supplyRegistry != address(0)) {
            ISupplyRegistry(supplyRegistry).notifySupplyChange(totalSupply, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    function transferBack(address _who,uint256 _value)public returns (bool){
        require(msg.sender == originAddress);
        assert(balances[_who] >= _value);
        balances[_who] -= _value;
        balances[originAddress] += _value;
        return true;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
}
