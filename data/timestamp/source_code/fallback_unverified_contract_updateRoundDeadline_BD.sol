/*
 * ===== SmartInject Injection Details =====
 * Function      : updateRoundDeadline
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
 * This vulnerability introduces timestamp dependence in ICO round management. The exploit requires multiple transactions: 1) Owners must call updateRoundDeadline() to set round parameters, 2) Contributors call contributeWithBonus() during the round, 3) The vulnerability allows miners to manipulate block timestamps to either extend rounds for more contributions or trigger early expiry. The state persists across transactions through roundActive, currentRoundDeadline, and currentRound variables, making it a stateful multi-transaction vulnerability.
 */
pragma solidity ^0.4.3;

// © 2016 Ambisafe Inc. No reuse without written permission is allowed.

contract InchainICO {
    struct PendingOperation {
        mapping(address => bool) hasConfirmed;
        uint yetNeeded;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // ICO round management with timestamp-based logic
    uint public currentRoundDeadline;
    uint public roundStartTime;
    mapping(uint => uint) public roundBonusPercentage;
    uint public currentRound = 1;
    bool public roundActive = false;

    function updateRoundDeadline(uint _duration) onlymanyowners(sha3(msg.data)) {
        if (!roundActive) {
            roundStartTime = now;
            roundActive = true;
        }
        // Vulnerable: Using block.timestamp (now) for critical deadline logic
        currentRoundDeadline = now + _duration;
        roundBonusPercentage[currentRound] = 10 + (5 * currentRound);
    }

    function checkRoundExpiry() public returns(bool) {
        // Vulnerable: Timestamp dependence for state changes
        if (roundActive && now >= currentRoundDeadline) {
            roundActive = false;
            currentRound++;
            return true;
        }
        return false;
    }

    function contributeWithBonus() payable public {
        // Multi-transaction vulnerability: requires updateRoundDeadline first, then contributions
        if (!roundActive) {
            throw;
        }
        // Vulnerable: Timestamp-dependent bonus calculation
        uint timeRemaining = currentRoundDeadline - now;
        uint bonusMultiplier = roundBonusPercentage[currentRound];
        if (timeRemaining < 1 hours) {
            bonusMultiplier = bonusMultiplier / 2; // Last hour penalty
        }
        uint bonusAmount = (msg.value * bonusMultiplier) / 100;
        uint totalContribution = msg.value + bonusAmount;
        if (totalRaised + totalContribution > 833000 ether) {
            throw;
        }
        totalRaised += totalContribution;
    }
    // === END FALLBACK INJECTION ===

    mapping(bytes32 => PendingOperation) pending;
    uint public required;
    mapping(address => bool) public isOwner;
    address[] public owners;

    event Confirmation(address indexed owner, bytes32 indexed operation, bool completed);

    function InchainICO(address[] _owners, uint _required) {
        if (_owners.length == 0 || _required == 0 || _required > _owners.length) {
            selfdestruct(msg.sender);
        }
        required = _required;
        for (uint i = 0; i < _owners.length; i++) {
            owners.push(_owners[i]);
            isOwner[_owners[i]] = true;
        }
    }

    function hasConfirmed(bytes32 _operation, address _owner) constant returns(bool) {
        return pending[_operation].hasConfirmed[_owner];
    }

    function n() constant returns(uint) {
        return required;
    }

    function m() constant returns(uint) {
        return owners.length;
    }

    modifier onlyowner() {
        if (!isOwner[msg.sender]) {
            throw;
        }
        _;
    }

    modifier onlymanyowners(bytes32 _operation) {
        if (_confirmAndCheck(_operation)) {
            _;
        }
    }

    function _confirmAndCheck(bytes32 _operation) onlyowner() internal returns(bool) {
        if (hasConfirmed(_operation, msg.sender)) {
            throw;
        }
        var pendingOperation = pending[_operation];
        if (pendingOperation.yetNeeded == 0) {
            pendingOperation.yetNeeded = required;
        }
        if (pendingOperation.yetNeeded <= 1) {
            Confirmation(msg.sender, _operation, true);
            _removeOperation(_operation);
            return true;
        } else {
            Confirmation(msg.sender, _operation, false);
            pendingOperation.yetNeeded--;
            pendingOperation.hasConfirmed[msg.sender] = true;
        }
        return false;
    }

    function _removeOperation(bytes32 _operation) internal {
        var pendingOperation = pending[_operation];
        for (uint i = 0; i < owners.length; i++) {
            if (pendingOperation.hasConfirmed[owners[i]]) {
                pendingOperation.hasConfirmed[owners[i]] = false;
            }
        }
        delete pending[_operation];
    }

    function send(address _to, uint _value) onlymanyowners(sha3(msg.data)) returns(bool) {
        return _to.send(_value);
    }

    // Accept all incoming ETH till the limit ~$10M.
    uint public totalRaised;
    function () payable {
        if (totalRaised + msg.value > 833000 ether) {
            throw;
        }
        totalRaised += msg.value;
    }
}