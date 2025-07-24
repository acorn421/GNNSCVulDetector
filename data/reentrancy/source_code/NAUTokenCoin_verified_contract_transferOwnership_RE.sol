/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variable**: Added `pendingOwnership` mapping to track ownership transfer states across transactions
 * 2. **External Call Before State Update**: Added `newOwner.call()` to notify the new owner BEFORE completing the ownership transfer
 * 3. **Conditional State Update**: Made the final ownership transfer conditional on the external call success
 * 4. **State Persistence**: The `pendingOwnership` mapping persists between transactions, creating multi-transaction exploitation opportunities
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker calls `transferOwnership(maliciousContract)` 
 * - **During Reentrancy**: The malicious contract's fallback function is triggered by the external call
 * - **Reentrant Call**: Malicious contract calls `transferOwnership` again while `pendingOwnership[attacker] = true` but `owner` hasn't changed yet
 * - **Transaction 2+**: Subsequent transactions can exploit the inconsistent state where multiple addresses have pending ownership
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability relies on the persistent `pendingOwnership` state across multiple function calls
 * - Single transaction exploitation is limited by the conditional state update
 * - Maximum impact requires building up accumulated state through multiple `transferOwnership` calls
 * - The attacker needs to establish pending ownership state first, then exploit it in subsequent transactions
 */
pragma solidity ^0.4.13;

contract Ownable {
    address public owner;
    function Ownable() public {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public pendingOwnership;
    
    function transferOwnership(address newOwner) onlyOwner public {
        // Mark ownership as pending for the new owner
        pendingOwnership[newOwner] = true;
        
        // Notify the new owner about pending ownership (external call before state change)
        if (newOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), msg.sender)) {
            // Only complete the transfer if the external call succeeds
            owner = newOwner;
            pendingOwnership[newOwner] = false;
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}

contract NAUTokenCoin is Ownable {
    string public constant name = "eNAU";
    string public constant symbol = "ENAU";
    uint32 public constant decimals = 4;
    uint public constant INITIAL_SUPPLY = 12850000000000;
    uint public totalSupply = 0;
    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;
    function NAUTokenCoin () public {
        totalSupply = INITIAL_SUPPLY;
        balances[msg.sender] = INITIAL_SUPPLY;
    }
    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }
    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[msg.sender] + _value >= balances[msg.sender]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if (allowed[_from][msg.sender] >= _value && balances[_from] >= _value && balances[_to] + _value >= balances[_to]) {
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