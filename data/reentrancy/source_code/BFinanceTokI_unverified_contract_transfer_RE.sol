/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the recipient address after balance updates using `_to.call()`
 * 2. The callback notifies the recipient contract about token reception via `onTokenReceived()` function
 * 3. This violates the Checks-Effects-Interactions pattern by placing external call after state modifications
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys malicious contract and initiates first transfer
 * 2. **Transaction 2+**: During the callback, the malicious contract re-enters the transfer function multiple times
 * 3. **State Persistence**: Each re-entrant call sees the updated balances from previous calls, enabling progressive fund drainage
 * 4. **Accumulated Effect**: The attacker can drain more funds than their initial balance through multiple recursive calls
 * 
 * **Why Multi-Transaction Dependency:**
 * - The vulnerability depends on the persistent state changes to the `balances` mapping between calls
 * - Each re-entrant call builds upon the balance state modified by previous calls
 * - The exploit requires the callback mechanism to trigger multiple sequential function executions
 * - Single-transaction protection mechanisms cannot prevent this as each call appears legitimate individually
 * 
 * This creates a realistic notification feature that introduces a dangerous reentrancy window, requiring multiple function calls and state accumulation to exploit effectively.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

contract BFinanceTokI is Ownable {

    string public constant name = "\tBFinanceTokI\t\t";
    string public constant symbol = "\tBFTI\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) onlyOwner public {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            balances[_to] += _value;

            // Notify recipient if it's a contract (callback mechanism)
            uint32 size;
            assembly { size := extcodesize(_to) }
            if(size > 0) {
                // call onTokenReceived(address,uint256)
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                // Continue regardless of callback success for compatibility
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
