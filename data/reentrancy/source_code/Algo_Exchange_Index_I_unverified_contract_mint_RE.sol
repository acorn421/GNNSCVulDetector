/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with callback function `onTokenMinted(uint256)`
 * 2. Call placed AFTER state modifications (`balances[_to] += _value` and `totalSupply += _value`)
 * 3. Added contract code length check to only call contracts, not EOAs
 * 4. Violates Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker deploys malicious contract at address X
 * Transaction 2: Owner calls `mint(X, 1000)` → triggers callback → malicious contract calls back into `mint()` → state accumulates
 * 
 * **Why Multi-Transaction Required:**
 * - Attacker must first deploy malicious contract with `onTokenMinted()` function
 * - Contract address must be provided to owner for minting
 * - Owner's call to mint triggers the reentrancy chain
 * - Each reentrant call accumulates state (balances and totalSupply increase)
 * - Requires coordination between attacker deployment and owner's mint call
 * 
 * **State Persistence:**
 * - `balances[_to]` and `totalSupply` persist between transactions
 * - Reentrant calls compound these values
 * - Attack can drain or inflate token supply through accumulated state changes
 * 
 * This creates a realistic production-like vulnerability where the external call enables infinite token minting through reentrancy, requiring multiple transactions to set up and exploit.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract Algo_Exchange_Index_I is Ownable {
    string public constant name = "ALGOEXINDEX";
    string public constant symbol = "AEII";
    uint32 public constant decimals = 8;
    uint public totalSupply = 0;

    mapping(address => uint) balances;
    mapping(address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract of minting event
        if(isContract(_to)) {
            // For Solidity 0.4.8 compatibility, call via .call (no abi.encodeWithSignature & safe low-level call)
            if(!_to.call(bytes4(keccak256("onTokenMinted(uint256)")), _value)) {
                throw;
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) } // returns size of code at address
        return (length > 0);
    }

    function balanceOf(address _owner) public view returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if (allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value &&
            balances[_to] + _value >= balances[_to]) {
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

    function allowance(address _owner, address _spender) public view returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}