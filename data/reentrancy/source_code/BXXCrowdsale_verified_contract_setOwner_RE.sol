/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls before and after the state update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Calls**: Introduced two external calls to `IOwnershipNotifier` interface - one before and one after the state update
 * 2. **State Capture**: Captured the old owner address before any modifications
 * 3. **Notification Pattern**: Implemented a realistic ownership transfer notification pattern that could exist in production code
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker calls `setOwner(maliciousContract)` where maliciousContract implements `IOwnershipNotifier`
 * 2. **Transaction 2**: During the first external call to `oldOwner.onOwnershipTransferred()`, the malicious contract can re-enter and call `setOwner` again
 * 3. **Transaction 3**: The state becomes inconsistent as the owner variable is modified multiple times across the call stack
 * 4. **Transaction 4**: The second external call to `newOwner.onOwnershipReceived()` can further exploit the inconsistent state
 * 
 * **Why Multi-Transaction Dependency:**
 * - The vulnerability relies on the persistent `owner` state variable that accumulates changes across transactions
 * - The external calls create windows for reentrancy that span multiple transaction contexts
 * - The old owner address is captured at the beginning, creating a time-of-check vs time-of-use vulnerability across transactions
 * - An attacker needs to deploy a malicious contract first, then call setOwner, then exploit the callback - requiring multiple separate transactions
 * 
 * **Realistic Integration:**
 * - Ownership transfer notifications are common in real smart contracts
 * - The pattern of notifying both old and new owners is realistic for access control systems
 * - The vulnerability is subtle and could easily be missed in code reviews
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) public;
}

// Declared interface for IOwnershipNotifier to resolve undeclared identifier errors
interface IOwnershipNotifier {
    function onOwnershipTransferred(address previousOwner, address newOwner) external;
    function onOwnershipReceived(address previousOwner, address newOwner) external;
}

contract BXXCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x54aEe5794e0e012775D9E3E86Eb6a7edf0e0380F;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    // Updated constructor to follow Solidity >=0.4.22 guidelines is optional in pragma ^0.4.16, but left as function for compatibility
    function BXXCrowdsale() public {
        creator = msg.sender;
        startDate = 1518393600;
        endDate = 1523142000;
        price = 5000;
        tokenReward = Token(0x53562419E435cBAe65d73E7EAe2723A43E6cd887);
    }

    function setOwner(address _owner) isCreator public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        address oldOwner = owner;
        
        // External call to notify old owner before state update
        if (oldOwner != address(0) && oldOwner != _owner) {
            IOwnershipNotifier(oldOwner).onOwnershipTransferred(oldOwner, _owner);
        }
        
        owner = _owner;
        
        // External call to notify new owner after state update
        if (_owner != address(0)) {
            IOwnershipNotifier(_owner).onOwnershipReceived(oldOwner, _owner);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function setCreator(address _creator) isCreator public {
        creator = _creator;      
    }

    function setStartDate(uint256 _startDate) isCreator public {
        startDate = _startDate;      
    }

    function setEndtDate(uint256 _endDate) isCreator public {
        endDate = _endDate;      
    }

    function setPrice(uint256 _price) isCreator public {
        price = _price;      
    }

    function setToken(address _token) isCreator public {
        tokenReward = Token(_token);      
    }

    function sendToken(address _to, uint256 _value) isCreator public {
        tokenReward.transfer(_to, _value);      
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
        uint amount = msg.value * price;
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}