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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Completion**: Added a callback to the recipient (`_to`) after balance updates but before allowance updates. This creates a critical window where state is partially modified.
 * 
 * 2. **State Persistence Between Transactions**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker sets up allowances using `approve()`
 *    - **Transaction 2**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 *    - **During callback**: The malicious contract can re-enter `transferFrom()` while allowances haven't been decremented yet
 *    - **Transaction 3+**: Additional exploitation rounds using the same allowance
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Setup Phase**: Attacker creates allowance through separate transaction
 *    - **Exploitation Phase**: Uses `transferFrom()` with malicious recipient contract
 *    - **Reentrancy Window**: During `onTokenReceived()` callback, allowance is still available for reuse
 *    - **State Accumulation**: Each successful reentrancy transfers tokens but doesn't decrement allowance until after callback completes
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The allowance must be established in a prior transaction
 *    - The vulnerability exploits the gap between balance updates and allowance updates
 *    - Multiple calls can drain more tokens than the original allowance should permit
 *    - The attack requires coordination between the attacker's main contract and the malicious recipient contract
 * 
 * This creates a realistic vulnerability where an attacker can transfer more tokens than their allowance permits by exploiting the reentrancy window during the recipient notification callback.
 */
pragma solidity ^0.4.11;

contract ExKnox {

    string public name = "ExKnox";      //  token name
    string public symbol = "EKX";           //  token symbol
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 100000000000000000;
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

    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about incoming transfer (external call before allowance update)
        if (_to != address(0)) { /* dummy check to avoid warning */ }
        /*
         Note: Direct code size checks are not possible pre-0.5.0. The canonical way in 0.4.x is to use addr.call.code.length,
         but code.size is not available. To simulate pre-existing functionality, the external call remains as
         _to.call(bytes4(keccak256(...)), ...). We'll avoid 'code.length' check and just proceed to the external call. */

        _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value);
        
        // Update allowance AFTER external call - creates reentrancy window
        allowance[_from][msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
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
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
