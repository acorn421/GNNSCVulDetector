/*
 * ===== SmartInject Injection Details =====
 * Function      : take
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by moving the `envelope.tooks[msg.sender] = true` assignment to AFTER the external call `msg.sender.transfer(value)`. This creates a reentrancy window where:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: An attacker deploys a malicious contract that implements a fallback function. This contract calls `take()` for an envelope and re-enters during the transfer callback, but the first reentrancy fails due to insufficient gas or other limitations.
 * 
 * 2. **Transaction 2 (Exploitation)**: The attacker's contract calls `take()` again. During the `transfer()` call, the malicious contract's fallback function is triggered and re-enters `take()` for the same envelope. Since `envelope.tooks[msg.sender]` is only set AFTER the transfer completes, the reentrancy check passes, allowing the attacker to:
 *    - Drain more value than intended
 *    - Claim the same envelope multiple times
 *    - Exploit the inconsistent state where funds are deducted but the "taken" flag isn't set
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker needs to establish the initial state in Transaction 1
 * - The actual exploitation happens in Transaction 2 when the reentrancy window is utilized
 * - The persistent state changes (envelope.remainingValue, envelope.remainingNumber) from Transaction 1 set up the conditions for successful exploitation in Transaction 2
 * - The vulnerability leverages the fact that the "taken" flag is only set after the external call completes, creating a persistent state inconsistency that can be exploited across multiple transactions
 * 
 * This creates a realistic reentrancy vulnerability that requires careful timing and multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.18;

contract RedEnvelope {

    struct EnvelopeType {
        uint256 maxNumber;
        uint256 feeRate;
    }
    
    struct Envelope {
        address maker;
        address arbiter;
        uint256 envelopeTypeId;
        uint256 minValue;
        uint256 remainingValue;
        uint256 remainingNumber;
        uint256 willExpireAfter;
        bool random;
        mapping(address => bool) tooks;
    }

    struct Settings {
        address arbiter;
        uint256 minValue;
    }

    event Made (
        address indexed maker,
        address indexed arbiter,
        uint256 indexed envelopeId,
        uint256 envelopeTypeId,
        uint256 minValue,
        uint256 total,
        uint256 quantity,
        uint256 willExpireAfter,
        uint256 minedAt,
        uint256 random
    );

    event Took (
        address indexed taker,
        uint256 indexed envelopeId,
        uint256 value,
        uint256 minedAt
    );

    event Redeemed(
        address indexed maker,
        uint256 indexed envelopeId,
        uint256 value,
        uint256 minedAt
    );

    Settings public settings;
    address public owner;
    uint256 public balanceOfEnvelopes;
    
    mapping (address => uint256) public envelopeCounts;
    mapping (uint256 => EnvelopeType) public envelopeTypes;
    mapping (uint256 => Envelope) public envelopes;

    modifier onlyOwner {
        require(owner == msg.sender);
        _;
    }

    function random() view private returns (uint256) {
        // factor = ceil(2 ^ 256 / 100)
        uint256 factor = 1157920892373161954235709850086879078532699846656405640394575840079131296399;
        bytes32 blockHash = block.blockhash(block.number - 1);
        return uint256(uint256(blockHash) / factor);
    }

    function RedEnvelope() public {
        settings = Settings(
            msg.sender,
            2000000000000000 // minValue = 0.002 ETH
        );
        owner = msg.sender;
    }

    function setSettings(address _arbiter, uint256 _minValue) onlyOwner public {
        settings.arbiter = _arbiter;
        settings.minValue = _minValue;
    }
    
    function setOwner(address _owner) onlyOwner public {
        owner = _owner;
    }

    function () payable public {}

    /*
     * uint256 _envelopeTypeId
     * uint256[2] _data
     *  [0] - maxNumber
     *  [1] - feeRate
     */
    function setEnvelopeType(uint256 _envelopeTypeId, uint256[2] _data) onlyOwner public {
        envelopeTypes[_envelopeTypeId].maxNumber = _data[0];
        envelopeTypes[_envelopeTypeId].feeRate = _data[1];
    }

    /*
     * uint256 _envelopeId
     * uint256[3] _data
     *  [0] - envelopeTypeId
     *  [1] - quantity;
     *  [2] - willExpireIn;
     *  [3] - random
     */
    function make(uint256 _envelopeId, uint256[4] _data) payable external {
        uint256 count = envelopeCounts[msg.sender] + 1;
        if (uint256(keccak256(msg.sender, count)) != _envelopeId) { // 错误的envelopeId
            revert();
        }
        EnvelopeType memory envelopeType = envelopeTypes[_data[0]];
        if (envelopeType.maxNumber < _data[1]) { // quantity过大
            revert();
        }
        uint256 total = ( msg.value * 1000 ) / ( envelopeType.feeRate + 1000 );
        if (total / _data[1] < settings.minValue) { // value过小
            revert();
        }
        Envelope memory envelope = Envelope(
            msg.sender,                     // maker
            settings.arbiter,               // arbiter
            _data[0],                       // envelopeTypeId
            settings.minValue,              // minValue
            total,                          // remainingValue
            _data[1],                       // remainingNumber
            block.timestamp + _data[2],     // willExpireAfter
            _data[3] > 0                    // random
        );
        
        envelopes[_envelopeId] = envelope;
        balanceOfEnvelopes += total;
        envelopeCounts[msg.sender] = count;

        Made(
            envelope.maker,
            envelope.arbiter,
            _envelopeId,
            envelope.envelopeTypeId,
            envelope.minValue,
            envelope.remainingValue,
            envelope.remainingNumber,
            envelope.willExpireAfter,
            block.timestamp,
            envelope.random ? 1 : 0
        );
    }

    /*
     * uint256 _envelopeId
     * uint256[4] _data
     *  [0] - willExpireAfter
     *  [1] - v
     *  [2] - r
     *  [3] - s
     */
    function take(uint256 _envelopeId, uint256[4] _data) external {
        // 验证红包
        Envelope storage envelope = envelopes[_envelopeId];
        if (envelope.willExpireAfter < block.timestamp) { // 红包过期
            revert();
        }
        if (envelope.remainingNumber == 0) { // 抢完了
            revert();
        }
        if (envelope.tooks[msg.sender]) { // 抢过了
            revert();
        }
        // 验证arbiter的签名
        if (_data[0] < block.timestamp) { // 签名过期
            revert();
        }
        if (envelope.arbiter != ecrecover(keccak256(_envelopeId, _data[0], msg.sender), uint8(_data[1]), bytes32(_data[2]), bytes32(_data[3]))) { // 签名错误
            revert();
        }
        
        uint256 value = 0;
        if (!envelope.random) {
            value = envelope.remainingValue / envelope.remainingNumber;
        } else {
            if (envelope.remainingNumber == 1) {
                value = envelope.remainingValue;
            } else {
                uint256 maxValue = envelope.remainingValue - (envelope.remainingNumber - 1) * envelope.minValue;
                uint256 avgValue = envelope.remainingValue / envelope.remainingNumber * 2;
                value = avgValue < maxValue ? avgValue * random() / 100 : maxValue * random() / 100;
                value = value < envelope.minValue ? envelope.minValue : value;
            }
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update state variables before external call, but mark as taken AFTER
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        envelope.remainingValue -= value;
        envelope.remainingNumber -= 1;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        balanceOfEnvelopes -= value;
        
        // External call BEFORE marking as taken - creates reentrancy window
        msg.sender.transfer(value);
        
        // Mark as taken AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        envelope.tooks[msg.sender] = true;

        Took(
            msg.sender,
            _envelopeId,
            value,
            block.timestamp
        );
    }

    function redeem(uint256 _envelopeId) external {
        Envelope storage envelope = envelopes[_envelopeId];
        if (envelope.willExpireAfter >= block.timestamp) { // 尚未失效
            revert();
        }
        if (envelope.remainingValue == 0) { // 没钱
            revert();
        }
        if (envelope.maker != msg.sender) { // 不是maker
            revert();
        }

        uint256 value = envelope.remainingValue;
        envelope.remainingValue = 0;
        envelope.remainingNumber = 0;
        balanceOfEnvelopes -= value;
        msg.sender.transfer(value);

        Redeemed(
            msg.sender,
            _envelopeId,
            value,
            block.timestamp
        );
    }

    function getPaid(uint256 amount) onlyOwner external {
        uint256 maxAmount = this.balance - balanceOfEnvelopes;
        msg.sender.transfer(amount < maxAmount ? amount : maxAmount);
    }

    function sayGoodBye() onlyOwner external {
        selfdestruct(msg.sender);
    }
}