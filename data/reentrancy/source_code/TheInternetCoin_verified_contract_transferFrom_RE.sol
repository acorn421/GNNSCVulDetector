/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. Added external call to recipient contract using `_to.call()` after state updates
 * 2. The call invokes `onTokenReceived()` on the recipient contract
 * 3. State updates (balanceOf, allowance) occur BEFORE the external call
 * 4. No reentrancy guard protection
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 1. **Transaction 1**: Attacker deploys malicious contract as recipient
 * 2. **Transaction 2**: Victim calls `transferFrom()` with malicious contract as `_to`
 * 3. **During Transaction 2**: The external call triggers the malicious contract's `onTokenReceived()` 
 * 4. **Reentrant Calls**: Malicious contract calls `transferFrom()` again before original call completes
 * 5. **State Exploitation**: Updated balances from step 3 are used to pass checks in reentrant calls
 * 
 * **WHY MULTI-TRANSACTION:**
 * - The vulnerability requires pre-deployed malicious contract (Transaction 1)
 * - The exploit depends on accumulated state changes across multiple reentrant calls within Transaction 2
 * - Each reentrant call builds upon the state changes from previous calls
 * - The allowance mechanism provides persistent state that enables repeated exploitation
 * 
 * **STATEFUL NATURE:**
 * - `balanceOf[_to]` is updated before external call, creating exploitable state
 * - `allowance[_from][msg.sender]` tracks remaining allowance across calls
 * - Malicious contract can drain funds by leveraging these persistent state changes
 * - Each reentrant call operates on the updated state from previous calls
 * 
 * This creates a realistic vulnerability pattern where the recipient notification feature, combined with improper state management, enables cross-transaction reentrancy attacks.
 */
pragma solidity ^0.4.25;

contract TheInternetCoin {

    string public name = "TheInternetCoin" ;                                //by @hilobrain
    string public symbol = "INT";           
    uint256 public decimals = 18;            

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 200*10**24;
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

    constructor (address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances and allowance first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about incoming transfer (potential reentrancy point)
        // Using extcodesize for contract check (Solidity <0.5.0)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call to recipient contract after state updates
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner public {
        stopped = true;
    }

    function start() isOwner public {
        stopped = false;
    }

    function setName(string _name) isOwner public {
        name = _name;
    }

    function burn(uint256 _value) isOwner public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
        totalSupply = totalSupply - _value ; 
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
