/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Updates**: Added a call to a governance contract before critical state modifications, creating a reentrancy window where totalSupply and balances can be manipulated.
 * 
 * 2. **Persistent State Tracking**: Introduced pendingMints mapping that accumulates across transactions, enabling state-dependent exploits that require multiple function calls.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker (as owner) calls mint() → external call triggers reentrancy → during callback, attacker can call mint() again while state is inconsistent
 *    - **Transaction 2**: Attacker exploits accumulated pendingMints state or inconsistent totalSupply/balances from previous reentrancy
 *    - **Transaction 3+**: Further exploitation using the accumulated state inconsistencies
 * 
 * 4. **Realistic Integration**: The governance notification mechanism is a common pattern in DeFi protocols for transparency and compliance, making this injection realistic.
 * 
 * 5. **State Accumulation**: The vulnerability requires multiple transactions because:
 *    - Each reentrancy call accumulates inconsistent state in pendingMints
 *    - The attacker needs separate transactions to exploit the accumulated inconsistencies
 *    - Single-transaction exploitation is prevented by the need to build up exploitable state over multiple calls
 * 
 * The vulnerability is only exploitable through multiple transactions that accumulate state inconsistencies, making it a genuine multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.13;

contract  CNet5G {
    /* Public variables of the token */
    string public name = "CNet5G"; 
    uint256 public decimals = 2;
    uint256 public totalSupply;
    string public symbol = "NE5G";
    event Mint(address indexed owner,uint amount);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Added state variables to fix errors
    address public governanceContract;
    mapping(address => uint256) public pendingMints;
    
    // Constructor using constructor keyword
    constructor() public {
        owner = 0x5103bA50f2324c6A80c73867d93B173d94cB11c6;
        /* Total supply is 300 million (300,000,000)*/
        balances[0x5103bA50f2324c6A80c73867d93B173d94cB11c6] = 300000000 * 10**decimals;
        totalSupply =300000000 * 10**decimals; 
    }

 function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_to != 0x00);
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    address owner;


    function mint(uint amount) onlyOwner public returns(bool minted ){
        if (amount > 0){
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // First, make external call to notify governance contract
            // This creates a reentrancy window before state is finalized
            if (governanceContract != address(0)) {
                bool success = governanceContract.call(bytes4(keccak256("notifyMint(uint256,address)")), amount, owner);
                // Continue regardless of success to maintain functionality
            }
            
            // State updates happen after external call - vulnerability window
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            totalSupply += amount;
            balances[owner] += amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Track pending mint for multi-transaction exploitation
            pendingMints[owner] += amount;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Mint(msg.sender,amount);
            return true;
        }
        return false;
    }

    modifier onlyOwner() { 
        if (msg.sender != owner) revert(); 
        _; 
    }
    
    function setOwner(address _owner) onlyOwner public {
        balances[_owner] = balances[owner];
        balances[owner] = 0;
        owner = _owner;
    }

}