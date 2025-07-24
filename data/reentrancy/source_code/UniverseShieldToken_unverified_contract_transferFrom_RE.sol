/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `isContract()` helper function to check if recipient is a contract
 * 2. Added external call to `_to.call()` with `onTokenReceived` callback BEFORE state updates
 * 3. The external call occurs before `balanceOf` and `allowance` state modifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `approve()` to give their malicious contract allowance to spend tokens from victim's account
 * 2. **Transaction 2**: Attacker calls `transferFrom()` with their malicious contract as `_to` address
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` callback is triggered before state updates
 * 4. **Reentrant Call**: The callback calls `transferFrom()` again, exploiting the fact that `allowance` hasn't been decremented yet
 * 5. **State Persistence**: The allowance remains unchanged between the initial call and reentrant call, allowing double-spending
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first establish allowance in a separate transaction via `approve()`
 * - The vulnerability exploits the persistent state (allowance) that was set in the previous transaction
 * - The reentrant call depends on the allowance state that persists from the initial approval
 * - Cannot be exploited in a single transaction because allowance must be pre-established
 * 
 * **Attack Vector:**
 * An attacker deploys a malicious contract that implements `onTokenReceived()` to call `transferFrom()` again before the original call completes, effectively draining more tokens than the allowance should permit by exploiting the stateful allowance that persists between transactions.
 */
pragma solidity ^0.4.11;

contract UniverseShieldToken {

    string public name = "Universe Shield Token";      //  token name
    string public symbol = "UST";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 1000000000000000;
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

    function UniverseShieldToken(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer notification callback to recipient before state updates
        if (isContract(_to)) {
            // External call before state changes - enables reentrancy
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            require(callSuccess, "Transfer notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setName(string _name) public isOwner {
        name = _name;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}