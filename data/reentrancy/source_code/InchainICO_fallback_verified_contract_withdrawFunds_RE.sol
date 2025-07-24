/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawFunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) Owners to first enable withdrawals via enableWithdrawals(), 2) Owners to allocate withdrawal balance via allocateWithdrawalBalance(), 3) The attacker to call withdrawFunds() which is vulnerable to reentrancy due to external call before state update. The vulnerability requires state persistence across multiple transactions and cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.3;

// © 2016 Ambisafe Inc. No reuse without written permission is allowed.

contract InchainICO {
    struct PendingOperation {
        mapping(address => bool) hasConfirmed;
        uint yetNeeded;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint) public withdrawableBalance;
    bool public withdrawalsEnabled = false;

    function enableWithdrawals() onlymanyowners(sha3(msg.data)) {
        withdrawalsEnabled = true;
    }

    function allocateWithdrawalBalance(address _investor, uint _amount) onlymanyowners(sha3(msg.data)) {
        withdrawableBalance[_investor] += _amount;
    }

    function withdrawFunds(uint _amount) {
        if (!withdrawalsEnabled) {
            throw;
        }

        if (withdrawableBalance[msg.sender] < _amount) {
            throw;
        }

        // Vulnerable to reentrancy - external call before state update
        if (msg.sender.call.value(_amount)()) {
            withdrawableBalance[msg.sender] -= _amount;
        }
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
