/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a vulnerability that requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract with `onTokenReceived` function and obtains approval to spend tokens from a victim account.
 * 
 * 2. **Transaction 2 (Exploitation)**: Attacker calls `transferFrom` to transfer tokens to their malicious contract. During the external call to `onTokenReceived`, the malicious contract can:
 *    - Re-enter `transferFrom` with the same parameters
 *    - Since state changes haven't occurred yet, the checks still pass
 *    - Drain more tokens than the allowance permits
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the attacker having a pre-deployed malicious contract (Transaction 1)
 * - The attacker must have obtained approval from the victim beforehand (separate transaction)
 * - The exploitation requires the malicious contract to be called during the transfer (Transaction 2)
 * - Each re-entrant call creates accumulated state inconsistencies that persist across the transaction sequence
 * 
 * **Stateful Nature:**
 * - The vulnerability exploits the persistent state of `balances` and `allowed` mappings
 * - Multiple calls accumulate to drain more tokens than should be possible
 * - State modifications from previous transactions enable the attack vector
 * 
 * This creates a realistic vulnerability pattern where the external call to notify recipient contracts (common in modern token standards) introduces a reentrancy risk when combined with improper state management across multiple transactions.
 */
pragma solidity ^0.4.8;

// ----------------------------------------------------------------------------------------------
// Sample fixed supply token contract
// Enjoy. (c) BokkyPooBah 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------

// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/issues/20
contract ERC20Interface {
    // Get the total token supply
    function totalSupply() constant returns (uint256 totalSupply);

    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) constant returns (uint256 balance);

    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _value) returns (bool success);

    // Send _value amount of tokens from address _from to address _to
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success);

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) returns (bool success);

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);

    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract FuturecomToken is ERC20Interface {
    string public constant symbol = "FUCOS";
    string public constant name = "Futurecom Interactive Token";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 42000000000000000000000000;
    
    // Owner of this contract
    address public owner;

    // Balances for each account
    mapping(address => uint256) balances;

    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) allowed;

    // Functions with this modifier can only be executed by the owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }

    // Constructor
    constructor() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    function totalSupply() constant returns (uint256 supply) {
        supply = _totalSupply;
    }

    // What is the balance of a particular account?
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    // Transfer the balance from owner's account to another account
    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Vulnerable transferFrom with reentrancy per the injected pattern
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            if (isContract(_to)) {
                // Call recipient contract's onTokenReceived function
                _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _amount));
                // Continue regardless of call success for compatibility
            }
            // State changes happen after external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Helper function to check for contract (in lieu of _to.code.length in 0.4.x)
    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
