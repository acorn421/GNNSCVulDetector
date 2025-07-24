/*
 * ===== SmartInject Injection Details =====
 * Function      : setPrice
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created mappings for `priceValidators`, `pendingPriceUpdates`, and flags for tracking price update state across transactions.
 * 
 * 2. **External Call Before State Update**: Added a loop that calls external `PriceValidator` contracts before updating the actual price state. This creates the classic reentrancy pattern where external calls occur before state modifications.
 * 
 * 3. **Stateful Multi-Transaction Exploitation**: The vulnerability requires multiple transactions:
 *    - **Transaction 1**: Attacker calls `setPrice()` which triggers external validator calls
 *    - **During Transaction 1**: Malicious validator contract re-enters `setPrice()` with different parameters
 *    - **Transaction 2**: Attacker exploits the inconsistent state created by the reentrancy to manipulate price calculations
 *    - **State Accumulation**: The `pendingPriceUpdates` mapping and `priceUpdateNonce` persist between transactions, allowing state manipulation across multiple calls
 * 
 * 4. **Realistic Scenario**: The code mimics a real-world price oracle validation system where external validators must approve price changes before they take effect.
 * 
 * **Multi-Transaction Exploitation Process**:
 * - Transaction 1: `setPrice(100)` → External validator call → Reentrant call sets different pending price
 * - State persists with manipulated `pendingPriceUpdates` and `priceUpdateNonce`
 * - Transaction 2: Attacker exploits the inconsistent state to achieve unintended price manipulation
 * - The vulnerability requires the accumulated state changes across multiple transactions to be effective
 * 
 * **Why Multi-Transaction**: The exploit cannot work in a single transaction because the state corruption requires the persistence of `pendingPriceUpdates` and validator state between separate transaction calls, making it impossible to exploit atomically.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) public;
}

interface PriceValidator {
    function validatePrice(uint256 _price, uint256 _nonce) public;
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

    address[] public validatorAddresses;
    mapping(address => bool) public priceValidators;
    mapping(address => uint256) public pendingPriceUpdates;
    uint256 public priceUpdateNonce;
    bool public priceUpdateInProgress;

    function BXXCrowdsale() public {
        creator = msg.sender;
        startDate = 1518393600;
        endDate = 1523142000;
        price = 5000;
        tokenReward = Token(0x53562419E435cBAe65d73E7EAe2723A43E6cd887);
    }

    function setOwner(address _owner) isCreator public {
        owner = _owner;      
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function setPrice(uint256 _price) isCreator public {
        require(!priceUpdateInProgress, "Price update already in progress");
        
        priceUpdateInProgress = true;
        pendingPriceUpdates[msg.sender] = _price;
        priceUpdateNonce++;
        
        // External call to validate price with oracle/validator
        // This enables reentrancy vulnerability
        for (uint i = 0; i < validatorAddresses.length; i++) {
            address validator = validatorAddresses[i];
            if (priceValidators[validator]) {
                // External call that can be reentered
                PriceValidator(validator).validatePrice(_price, priceUpdateNonce);
            }
        }
        
        // State update occurs after external calls - vulnerable to reentrancy
        if (pendingPriceUpdates[msg.sender] != 0) {
            price = pendingPriceUpdates[msg.sender];
            delete pendingPriceUpdates[msg.sender];
        }
        
        priceUpdateInProgress = false;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
