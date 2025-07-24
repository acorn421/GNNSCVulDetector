/*
 * ===== SmartInject Injection Details =====
 * Function      : make
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
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by adding an external call to the msg.sender before critical state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a callback to `msg.sender.call()` with envelope validation parameters before state variables are updated
 * 2. **Violated CEI Pattern**: The external call occurs before state updates (`envelopes[_envelopeId]`, `balanceOfEnvelopes`, `envelopeCounts[msg.sender]`)
 * 3. **Realistic Integration**: The callback appears as a legitimate feature for custom envelope validation by the maker
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onEnvelopeValidation()` function that calls back to `make()` 
 * 2. **Transaction 2**: Attacker calls `make()` with their malicious contract as `msg.sender`
 * 3. **Reentrancy Trigger**: During the external call, malicious contract re-enters `make()` before state updates complete
 * 4. **State Manipulation**: Multiple envelope creations with same ID, balance manipulation, and count inconsistencies
 * 5. **Accumulated Impact**: Each reentrant call compounds the state corruption
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - The malicious contract must implement the callback interface to trigger reentrancy (separate setup)
 * - Multiple calls accumulate state inconsistencies that can be exploited in subsequent transactions
 * - The envelope count mechanism creates dependencies between transactions that enable the exploit
 * 
 * **Exploitation Impact:**
 * - Create duplicate envelopes with same ID
 * - Manipulate `balanceOfEnvelopes` accounting
 * - Corrupt `envelopeCounts` leading to ID prediction issues
 * - Drain contract funds through accumulated state inconsistencies
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

    constructor() public {
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
        if (uint256(keccak256(abi.encodePacked(msg.sender, count))) != _envelopeId) { // 错误的envelopeId
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add pre-state validation callback to maker's contract
        // This allows the maker to implement custom validation logic
        if (extcodesize(msg.sender) > 0) {
            // External call to maker's contract before state updates
            (bool success, ) = msg.sender.call(abi.encodeWithSignature("onEnvelopeValidation(uint256,uint256,uint256)", _envelopeId, total, _data[1]));
            // Continue regardless of callback result for backwards compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

        envelope.remainingValue -= value;
        envelope.remainingNumber -= 1;
        envelope.tooks[msg.sender] = true;
        balanceOfEnvelopes -= value;
        msg.sender.transfer(value);

        Took(
            msg.sender,
            _envelopeId,
            value,
            block.timestamp
        );
    }

    /*
     * uint256 _envelopeId
     */
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
