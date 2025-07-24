/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimespanWindow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. An attacker can first call genNumber() to set _time to a specific value, then wait and call setTimespanWindow() with a very small timespan when the timestamp condition is met. This allows manipulation of the random number generation timing in subsequent transactions, requiring state persistence between calls.
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

contract RandomNumber {
    using SafeMath for uint256;

    address _owner;
    uint24 private _number;
    uint256 private _time;
    uint256 private _timespan;
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    function setTimespanWindow(uint256 newTimespan) 
        public 
    {
        require(msg.sender == _owner, "Only owner can set timespan");
        require(block.timestamp > _time + _timespan, "Cannot modify during active period");
        _timespan = newTimespan;
    }
    // === END FALLBACK INJECTION ===

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

    function genNumber() 
        public 
    {
        require(block.timestamp > _time + _timespan);
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
