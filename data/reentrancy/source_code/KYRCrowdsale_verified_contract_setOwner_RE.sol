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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the current owner before updating the owner state. This creates a classic Checks-Effects-Interactions (CEI) pattern violation where the external call happens before the state update.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 - Setup**: Attacker must first become the creator (through setCreator if possible) or exploit must be launched when attacker is already creator
 * 2. **Transaction 2 - Initial Owner Setup**: Attacker calls setOwner() with a malicious contract address to establish the first owner
 * 3. **Transaction 3 - Exploitation**: Attacker calls setOwner() again with a new address. During this call:
 *    - The function calls the malicious contract (current owner) via `owner.call()`
 *    - The malicious contract's fallback/receive function executes
 *    - This callback can re-enter setOwner() before the original owner state is updated
 *    - The re-entrant call can manipulate the ownership state multiple times
 * 
 * **State Persistence Requirements:**
 * - The vulnerability requires the owner state to be set in a previous transaction
 * - Each transaction builds upon the state changes from previous transactions
 * - The external call relies on the persistent owner state from earlier transactions
 * - Multiple calls to setOwner() compound the vulnerability as the owner state accumulates changes
 * 
 * **Why Multi-Transaction is Required:**
 * - Transaction 1: Must establish initial state (owner != address(0))
 * - Transaction 2+: Exploit the external call to the established owner
 * - Single transaction exploitation is impossible because the owner must be pre-established
 * - The vulnerability depends on the accumulated state changes across multiple transactions
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address receiver, uint amount) public;
}

contract KYRCrowdsale {
    
    Token public tokenReward;
    address creator;
    address owner = 0x0;

    uint256 public startDate;
    uint256 public endDate;
    uint256 public price;

    event FundTransfer(address backer, uint amount, bool isContribution);

    function KYRCrowdsale() public {
        creator = msg.sender;
        startDate = 0;
        endDate = 0;
        price = 10000;
        tokenReward = Token(0xc7aF722472DC3268cd57c7554BdE50c4F1C20cc8);
    }

    function setOwner(address _owner) public {
        require(msg.sender == creator);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the previous owner before changing ownership
        if (owner != address(0)) {
            owner.call(bytes4(keccak256("ownershipTransferred(address)")), _owner);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = _owner;      
    }

    function setCreator(address _creator) public {
        require(msg.sender == creator);
        creator = _creator;      
    }    

    function setStartDate(uint256 _startDate) public {
        require(msg.sender == creator);
        startDate = _startDate;      
    }

    function setEndDate(uint256 _endDate) public {
        require(msg.sender == creator);
        endDate = _endDate;      
    }

    function setPrice(uint256 _price) public {
        require(msg.sender == creator);
        price = _price;      
    }

    function sendToken(address receiver, uint amount) public {
        require(msg.sender == creator);
        tokenReward.transfer(receiver, amount);
        FundTransfer(receiver, amount, true);    
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