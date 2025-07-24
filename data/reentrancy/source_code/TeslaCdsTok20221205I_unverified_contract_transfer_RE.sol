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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient contract's `onTokenReceived` function after the balance updates. This creates a post-update external call that can be exploited across multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `ITokenReceiver(_to).onTokenReceived(msg.sender, _value)` after balance updates
 * 2. Added logic to revert the transfer if the recipient contract rejects it
 * 3. Used try-catch to handle potential failures in the external call
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker calls `transfer` to a malicious contract. The malicious contract's `onTokenReceived` function gets called after balance updates, but instead of exploiting immediately, it sets up state for future exploitation (e.g., storing the sender's address, marking itself as "primed").
 * 
 * 2. **Transaction 2**: The malicious contract now calls `transfer` again or triggers another user to call `transfer`. When `onTokenReceived` is called this time, it can exploit the accumulated state from the first transaction - for example, by performing a complex reentrancy attack that depends on the previously stored state.
 * 
 * 3. **Transaction 3+**: The attacker can continue to exploit the vulnerability by leveraging the persistent state changes from previous transactions, potentially draining funds through a series of coordinated calls.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the malicious contract to accumulate state across multiple calls
 * - The attacker needs to set up conditions in early transactions that enable exploitation in later ones
 * - Single-transaction exploitation is limited because the malicious contract needs to coordinate complex state changes that persist between calls
 * - The post-update external call creates a window for state manipulation that can be leveraged across multiple transactions
 * 
 * This represents a realistic vulnerability pattern where legitimate token recipient notification functionality creates a multi-transaction reentrancy attack vector.
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

// Interface declaration added for ITokenReceiver
interface ITokenReceiver {
    function onTokenReceived(address _from, uint _value) external returns (bool);
}

contract TeslaCdsTok20221205I is Ownable {
    
    string public constant name = "TeslaCdsTok20221205I";
    
    string public constant symbol = "TESLAII";
    
    uint32 public constant decimals = 8;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    function mint(address _to, uint _value) public onlyOwner {
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
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract if it's a contract address
            if (_to != address(0)) {
                uint256 size;
                assembly { size := extcodesize(_to) }
                if (size > 0) {
                    // Avoid `try`/`catch` (not available in 0.4.18), call directly
                    // Swallow errors using low-level call
                    if(!ITokenReceiver(_to).onTokenReceived(msg.sender, _value)) {
                        // Revert the transfer if recipient rejected
                        balances[msg.sender] += _value;
                        balances[_to] -= _value;
                        return false;
                    }
                }
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
