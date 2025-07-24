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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call()` after balance state updates
 * 2. Used low-level call to invoke `tokenReceived(address,uint256)` callback on recipient contract
 * 3. Placed the external call after state changes but before function return
 * 4. Added code length check to only call contracts (realistic pattern)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transfer()` to a malicious contract with X tokens
 * 2. **State Changes**: Attacker's balance decreases, malicious contract's balance increases
 * 3. **Callback Triggered**: Malicious contract's `tokenReceived()` is called
 * 4. **Transaction 2**: Inside callback, malicious contract calls `transfer()` again
 * 5. **Reentrancy**: Second call sees updated balances from first transaction
 * 6. **Exploitation**: Attacker can transfer tokens they no longer have due to state inconsistency
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the persistent state changes (balance updates) from the first transaction
 * - The callback mechanism requires the recipient contract to be deployed and configured (separate transaction)
 * - The exploit depends on accumulated state changes across multiple `transfer()` calls
 * - Each reentrant call builds upon the state modifications from previous calls
 * 
 * **Realistic Attack Vector:**
 * An attacker deploys a malicious contract that implements `tokenReceived()` to immediately transfer received tokens to another address, potentially draining the contract or double-spending tokens through carefully timed multi-transaction sequences.
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

contract ANHUI_ANNUITY_DAO_33_b is Ownable {
    string public constant name = "\tANHUI_ANNUITY_DAO_33_b\t\t";
    string public constant symbol = "\tAAI\t\t";
    uint32 public constant decimals = 18;
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Vulnerability: External call after state changes - enables reentrancy
            if(isContract(_to)) {
                // Call recipient contract's tokenReceived callback
                bool callSuccess = _to.call(bytes4(keccak256("tokenReceived(address,uint256)")), msg.sender, _value);
                // Continue execution regardless of callback success
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

    function isContract(address _addr) private constant returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
