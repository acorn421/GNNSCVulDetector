/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the previous owner before updating the owner state. This creates a classic Check-Effects-Interactions pattern violation where the external call happens before the state update, allowing for reentrancy attacks that require multiple transactions to exploit effectively.
 * 
 * **Specific Changes Made:**
 * 1. Added storage of the previous owner address
 * 2. Introduced an external call to `previousOwner.call()` with owner change notification
 * 3. Moved the state update (`owner = _owner`) to occur AFTER the external call
 * 4. Added a require statement to ensure the call succeeds, making the vulnerability more realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `setOwner(maliciousContract)` where `maliciousContract` is controlled by the attacker
 * 2. **Transaction 2**: When the current owner is notified via the external call, the malicious contract's `ownerChanged()` function is triggered
 * 3. **During Reentrancy**: The malicious contract can call `setOwner()` again before the original state update completes, potentially:
 *    - Setting the owner to a different address than intended
 *    - Bypassing access controls that depend on the owner state
 *    - Creating race conditions with other state-dependent operations
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract that implements the `ownerChanged()` callback
 * - The exploitation happens when the external call triggers the callback, which then makes additional calls back to the contract
 * - The persistent state changes between transactions create windows of opportunity where the contract is in an inconsistent state
 * - The attack sequence requires: setup transaction → trigger transaction → exploitation transactions
 * 
 * This creates a realistic vulnerability that mirrors real-world reentrancy patterns seen in production contracts where notification mechanisms or callback patterns are implemented incorrectly.
 */
pragma solidity ^0.4.16;

interface Token {
    function transferFrom(address _from, address _to, uint256 _value) external;
}

contract IRideBounty3 {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0xBeDF65990326Ed2236C5A17432d9a30dbA3aBFEe;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    function IRideBounty3() public {
        creator = msg.sender;
        startDate = 1793491200;
        endDate = 1919721600;
        price = 17500;
        tokenReward = Token(0x69D94dC74dcDcCbadEc877454a40341Ecac34A7c);
    }

    function setOwner(address _owner) isCreator public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        address previousOwner = owner;
        
        // External call to notify previous owner before state update
        if (previousOwner != address(0) && previousOwner != _owner) {
            (bool success, ) = previousOwner.call(abi.encodeWithSignature("ownerChanged(address)", _owner));
            require(success, "Owner notification failed");
        }
        
        owner = _owner;
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

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
	    uint amount = msg.value * price;
        tokenReward.transferFrom(owner, msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}