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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` with `onTokenMinted` callback before state updates
 * 2. The call happens after assertion checks but before balance/totalSupply updates
 * 3. Used low-level call that continues execution regardless of callback result
 * 4. Violates the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenMinted` callback
 * 2. **Transaction 2**: Owner calls mint() targeting attacker's contract
 * 3. **During Transaction 2**: Callback is triggered, enabling reentrancy
 * 4. **Reentrant Calls**: Malicious contract can call mint() again during callback
 * 5. **State Accumulation**: Each reentrant call accumulates minted tokens while totalSupply lags behind
 * 
 * **Why Multi-Transaction is Required:**
 * - The malicious contract must be deployed first (separate transaction)
 * - Each reentrant call creates a new transaction context in the call stack
 * - State changes persist between calls, enabling accumulation of minted tokens
 * - The exploit requires the attacker to control a contract address that receives the mint
 * 
 * **Exploitation Flow:**
 * 1. Deploy malicious contract with onTokenMinted() that calls mint() again
 * 2. Owner calls mint() to attacker's contract
 * 3. During callback, attacker reenters mint() multiple times
 * 4. Each reentrant call mints more tokens before previous calls complete their state updates
 * 5. Final result: attacker receives more tokens than intended due to state inconsistencies
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions and contract interaction to exploit, making it suitable for defensive security research.
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
}

contract ChipotleCdsTok20221205I is Ownable {
    
    string public constant name = "ChipotleCdsTok20221205I";
    
    string public constant symbol = "CHIPOTI";
    
    uint32 public constant decimals = 8;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state update creates reentrancy vulnerability
        if (isContract(_to)) {
            // Attempt to call onTokenMinted callback if recipient is a contract
            _to.call(abi.encodeWithSignature("onTokenMinted(uint256,address)", _value, msg.sender));
            // Continue execution regardless of callback result
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        totalSupply += _value;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    
    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value; 
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value; 
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        } 
        return false;
    }
    
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
}
