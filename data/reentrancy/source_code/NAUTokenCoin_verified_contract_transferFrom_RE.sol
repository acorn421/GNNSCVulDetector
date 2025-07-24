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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a classic reentrancy pattern where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` hook before state updates
 * 2. Maintained all checks but moved state modifications after the external call
 * 3. Added contract code existence check to make the call realistic
 * 4. Preserved original function behavior and signature
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker approves a malicious contract to spend tokens via `approve()`
 * 2. **Transaction 2**: Malicious contract calls `transferFrom()` which triggers the external call
 * 3. **During External Call**: The malicious contract re-enters `transferFrom()` before state updates complete
 * 4. **Exploitation**: Since allowance and balances haven't been updated yet, the same tokens can be transferred multiple times
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior approval (separate transaction) to set up the allowance
 * - The reentrancy window only exists during the external call execution
 * - State persistence between transactions is essential - the allowance must be set in advance
 * - The exploit requires coordinated state across multiple calls to be effective
 * 
 * **Stateful Nature:**
 * - The `allowed` mapping persists between transactions and is essential for the exploit
 * - The vulnerability depends on accumulated state from previous `approve()` calls
 * - Each reentrant call depends on the persistent state not being updated yet
 * 
 * This creates a realistic vulnerability pattern commonly seen in token contracts that implement recipient hooks or callbacks.
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
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
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
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if (allowed[_from][msg.sender] >= _value && balances[_from] >= _value && balances[_to] + _value >= balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Try to detect contract using extcodesize
            uint256 size;
            assembly { size := extcodesize(_to) }
            if (size > 0) {
                // Call onTokenReceived hook if recipient is a contract
                _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
                // Continue execution even if call fails
            }
            // State updates occur AFTER external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            balances[_to] += _value;
            emit Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}
