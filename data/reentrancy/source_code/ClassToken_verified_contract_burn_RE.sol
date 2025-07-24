/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to msg.sender after the balance check but before state updates. This violates the Checks-Effects-Interactions pattern and creates a classic reentrancy vulnerability.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to msg.sender using `msg.sender.call()` with callback signature `onTokensBurned(uint256)`
 * 2. Positioned the external call after the `require()` check but before balance state updates
 * 3. Added a check for contract code existence to make the callback more realistic
 * 4. Used a low-level call that continues execution regardless of callback success
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions in the call stack to exploit:
 * 
 * 1. **Initial State Setup**: Attacker deploys a malicious contract with some token balance (e.g., 100 tokens)
 * 2. **First Transaction**: Attacker calls `burn(100)` from their malicious contract
 * 3. **Reentrancy Chain**: The malicious contract's `onTokensBurned()` callback is triggered BEFORE the balance is updated
 * 4. **Recursive Calls**: The callback recursively calls `burn(100)` again, passing the balance check since `balanceOf[attacker]` still shows 100 tokens
 * 5. **State Accumulation**: Each recursive call transfers 100 tokens to the owner while only reducing the attacker's balance once at the end
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the persistent state (`balanceOf` mapping) across multiple call frames
 * - Each recursive call is technically a separate transaction in the call stack
 * - The attack accumulates damage across multiple calls before any state updates occur
 * - A single transaction alone cannot exploit this - it requires the callback mechanism to create the reentrant call chain
 * - The persistent state between calls is what enables the vulnerability (balance check passes multiple times before any updates)
 * 
 * **Realistic Context:**
 * The callback mechanism is realistic for modern DeFi protocols that often notify external contracts about token burns for accounting, fee calculation, or integration purposes. The vulnerability appears as a legitimate feature but creates a critical security flaw.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn callback before state updates
        if (extcodesize(msg.sender) > 0) {
            msg.sender.call(
                abi.encodeWithSignature("onTokensBurned(uint256)", _value)
            );
            // Continue regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[owner] += _value;
        emit Transfer(msg.sender, owner, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    // extcodesize helper for pre-0.5.0 Solidity
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
