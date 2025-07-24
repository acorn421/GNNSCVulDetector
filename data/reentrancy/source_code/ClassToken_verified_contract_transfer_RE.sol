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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call hook between balance checks and state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added external call to `_to.call()` after balance checks but before state updates
 * 2. The call attempts to invoke `onTokenReceived()` function on the recipient contract
 * 3. This violates the Checks-Effects-Interactions pattern by placing external call before state modifications
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1-N**: Attacker calls transfer() to build up balance state in target contract
 * 2. **Transaction N+1**: Attacker triggers transfer() to malicious contract that implements onTokenReceived()
 * 3. **During callback**: Malicious contract calls transfer() again, exploiting the fact that sender's balance hasn't been updated yet
 * 4. **State persistence**: Each successful reentrancy call reduces the victim's balance while increasing attacker's balance across multiple transactions
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the persistent `balanceOf` state between transactions
 * - Attacker needs to accumulate tokens in previous transactions to have sufficient balance for the exploit
 * - The reentrancy attack drains funds progressively across multiple calls, not in a single atomic transaction
 * - Each reentrant call depends on the balance state established by previous transactions
 * 
 * This creates a realistic scenario where an attacker must execute a sequence of transactions to build up the necessary state before triggering the final exploitative transaction.
 */
pragma solidity ^0.4.11;

contract ClassToken {

    string public name = "ClassToken";      //  token name
    string public symbol = "CTC";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 5*10**26;
    address owner = 0x16D6234c2FBBEf7B7Bea8a7B181825daA4E5B56D;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(owner != msg.sender);
        _;
    }

    constructor(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(owner, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notification hook - external call before state update
        if (_to != address(0)) { // workaround to allow vulnerable external call (see note)
            _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
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

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[owner] += _value;
        emit Transfer(msg.sender, owner, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
