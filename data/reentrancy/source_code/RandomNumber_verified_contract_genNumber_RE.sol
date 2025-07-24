/*
 * ===== SmartInject Injection Details =====
 * Function      : genNumber
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to subscriber contracts before state updates. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Attacker registers malicious subscriber contract
 * 2. **Transaction 2**: Attacker calls genNumber() which triggers external call to their contract before _time is updated
 * 3. **Reentrant Call**: Malicious subscriber can re-enter genNumber() during callback, bypassing time check with stale _time value
 * 
 * **Key Changes Made:**
 * - Added external call to subscriber contracts before state updates (_time, _number)
 * - External call uses stale state values (_number, _time) from previous generation
 * - State updates occur after external calls, violating checks-effects-interactions pattern
 * - Requires _subscribers array to be populated (separate transaction) before exploitation
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Setup Transaction**: Attacker must first register their malicious contract as a subscriber
 * 2. **Trigger Transaction**: Call genNumber() which makes external call with stale state
 * 3. **Reentrancy Window**: During the callback, attacker can re-enter genNumber() before _time is updated
 * 4. **Bypass Time Check**: Reentrant call sees old _time value, allowing multiple number generations in rapid succession
 * 
 * **Why Multi-Transaction is Required:**
 * - Subscriber registration must happen in separate transaction before attack
 * - Time-based cooldown naturally enforces multi-transaction sequence
 * - Reentrancy exploitation depends on state accumulated from previous legitimate calls
 * - Cannot be exploited in single atomic transaction due to time-based gating mechanism
 * 
 * This creates a realistic vulnerability where an attacker can bypass the intended time-based rate limiting by exploiting the window between external calls and state updates.
 */
pragma solidity ^0.4.24;

library SafeMath {
    function add(uint256 a, uint256 b)
        internal
        pure
        returns (uint256 c) 
    {
        c = a + b;
        require(c >= a, "SafeMath add failed");
        return c;
    }
}

// Declare the interface for subscribers
interface IRandomNumberSubscriber {
    function onNumberGenerated(uint24 number, uint256 time) external;
}

contract RandomNumber {
    using SafeMath for uint256;

    address _owner;
    uint24 private _number;
    uint256 private _time;
    uint256 private _timespan;
    address[] private _subscribers; // Declare the _subscribers array
    event onNewNumber
    (
        uint24 number,
        uint256 time
    );
    
    constructor(uint256 timespan) 
        public 
    {
        _owner = msg.sender;
        _time = 0;
        _number = 0;
        _timespan = timespan;
    }

    function number() 
        public 
        view 
        returns (uint24) 
    {
        return _number;
    }

    function time() 
        public 
        view 
        returns (uint256) 
    {
        return _time;
    }

    function timespan() 
        public 
        view 
        returns (uint256) 
    {
        return _timespan;
    }

    // Added a function to allow subscribing (not required, but for completeness)
    function addSubscriber(address subscriber) public {
        // No access restriction for simplicity
        _subscribers.push(subscriber);
    }

    function genNumber() 
        public 
    {
        require(block.timestamp > _time + _timespan);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify subscribers before state updates
        if (_subscribers.length > 0) {
            for (uint i = 0; i < _subscribers.length; i++) {
                IRandomNumberSubscriber(_subscribers[i]).onNumberGenerated(_number, _time);
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _time = block.timestamp;
        _number = random();
        emit RandomNumber.onNewNumber (
            _number,
            _time
        );
    }

    function random() 
        private 
        view 
        returns (uint24)
    {
        uint256 randnum = uint256(keccak256(abi.encodePacked(
            (block.timestamp).add
            (block.difficulty).add
            ((uint256(keccak256(abi.encodePacked(block.coinbase)))) / (now)).add
            (block.gaslimit).add
            ((uint256(keccak256(abi.encodePacked(msg.sender)))) / (now)).add
            (block.number)
            
        )));
        return uint24(randnum%1000000);
    }
}
