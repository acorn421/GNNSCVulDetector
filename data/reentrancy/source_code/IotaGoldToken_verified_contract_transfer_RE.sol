/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` with `onTokenReceived` callback between the sender's balance update and recipient's balance update
 * 2. Positioned the external call after the sender's balance is decreased but before the recipient's balance is increased
 * 3. Used low-level `call()` to invoke the callback, which allows reentrancy
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokenReceived` callback
 * 2. **Transaction 2 (Initial Transfer)**: Legitimate user transfers tokens to the malicious contract
 * 3. **Transaction 3+ (Reentrancy Chain)**: During the callback in Transaction 2, the malicious contract:
 *    - Re-enters the `transfer` function with different parameters
 *    - Can manipulate the state while the original transfer is still in progress
 *    - Can potentially drain tokens by exploiting the timing between balance updates
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the attacker to first deploy and prepare the malicious contract (Transaction 1)
 * - The actual exploitation happens when someone transfers to the malicious contract (Transaction 2)
 * - The malicious contract then performs reentrant calls during the callback (creating additional transaction contexts)
 * - The attacker can accumulate state changes across multiple reentrant calls that wouldn't be possible in a single transaction
 * - Each reentrant call operates on the partially updated state from previous calls in the chain
 * 
 * **State Persistence Exploitation:**
 * - The sender's balance is decreased immediately, but recipient's balance is increased only after the external call
 * - During reentrancy, the malicious contract can observe this inconsistent state
 * - Multiple reentrant calls can manipulate balances in ways that require the accumulated effect of several state changes
 * - The vulnerability exploits the persistent state changes that occur across the sequence of nested calls
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions and state accumulation to exploit effectively.
 */
pragma solidity ^0.4.11;

contract IotaGoldToken {

    string public name = "IotaGold";
    string public symbol = "IOTAG";
    uint256 public decimals = 2;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    address[] addresses;
    uint[] values;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 27795302800;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    // Updated constructor syntax for Solidity >=0.4.22 compatibility
    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update sender's balance first
        balanceOf[msg.sender] -= _value;
        
        // VULNERABILITY: External call to recipient before completing state updates
        // This enables reentrancy where the recipient can call back into transfer
        if(_to != address(0) && _to.delegatecall.gas(2300)()) {
            // This dummy branch is here to keep the structure, but since `code` doesn't exist in 0.4.x,
            // Technically, checking if(_to.isContract) is not possible pre-0.5.0, but we will omit check.
            // Alternatively, we can replace with a delegatecall/call for demonstration, but here we move on.
        }
        // Directly call recipient's callback (solidity ^0.4.x - fallback to just call, as abi.encodeWithSignature is only available ^0.4.24)
        // We call .call(), but cannot use abi.encodeWithSignature before 0.4.24 so use string literal
        _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
        
        // Complete the transfer by updating recipient's balance AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner {
        stopped = true;
    }

    function start() isOwner {
        stopped = false;
    }

    function setName(string _name) isOwner {
        name = _name;
    }

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }
        

    function TokenDrop(address[] _addresses, uint256[] _values) payable returns(bool){
        for (uint i = 0; i < _addresses.length; i++) {
            transfer(_addresses[i], _values[i]);
        }
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
