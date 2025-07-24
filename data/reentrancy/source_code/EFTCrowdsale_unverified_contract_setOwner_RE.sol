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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the previous owner about ownership transfer. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Attacker deploys a malicious contract and calls setOwner to become the owner
 * 2. **Transaction 2**: Legitimate user calls setOwner with a new address, triggering the external call to the attacker's contract
 * 3. **Transaction 3**: During the callback, the attacker can re-enter setOwner or other functions while the contract is in an inconsistent state
 * 
 * The vulnerability is stateful because:
 * - It depends on the previous owner being set to a malicious contract
 * - The external call creates a callback opportunity that persists across transactions
 * - The state changes (owner and creator) happen after the external call, creating a window for manipulation
 * 
 * The multi-transaction nature is enforced because:
 * - The attacker must first become the owner in a previous transaction
 * - The vulnerability is only triggered when someone else tries to change ownership
 * - The reentrancy opportunity only exists during the callback phase of the ownership transfer
 * 
 * This creates a realistic scenario where an attacker can set up the vulnerability in advance and exploit it when legitimate ownership transfers occur.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) public;
}

contract EFTCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x515C1c5bA34880Bc00937B4a483E026b0956B364;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    function EFTCrowdsale() public {
        creator = msg.sender;
        startDate = 1518307200;
        endDate = 1530399600;
        price = 100;
        tokenReward = Token(0x21929a10fB3D093bbd1042626Be5bf34d401bAbc);
    }

    function setOwner(address _owner) isCreator public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(_owner != address(0));
        
        // Store the previous owner for notification
        address previousOwner = owner;
        
        // Update owner first to prevent immediate re-entry
        owner = _owner;
        
        // Notify previous owner about ownership change via external call
        if (previousOwner != address(0) && previousOwner != _owner) {
            // External call that enables reentrancy in subsequent transactions
            (bool success, ) = previousOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address,address)", previousOwner, _owner));
            
            // If notification fails, revert the ownership change
            if (!success) {
                owner = previousOwner;
                revert("Ownership transfer notification failed");
            }
        }
        
        // Additional state update after external call (vulnerable pattern)
        if (previousOwner != address(0)) {
            // This creates a window where state can be manipulated
            // in subsequent transactions during the callback
            creator = _owner; // Update creator to match new owner
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

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
	    uint amount = msg.value * price;
        uint _amount = amount / 5;

        // period 1 : 100%
        if(now > 1518307200 && now < 1519862401) {
            amount += amount;
        }
        
        // period 2 : 75%
        if(now > 1519862400 && now < 1522537201) {
            amount += _amount * 15;
        }

        // Pperiod 3 : 50%
        if(now > 1522537200 && now < 1525129201) {
            amount += _amount * 10;
        }

        // Pperiod 4 : 25%
        if(now > 1525129200 && now < 1527807601) { 
            amount += _amount * 5;
        }

        // Pperiod 5 : 10%
        if(now > 1527807600 && now < 1530399600) {
            amount += _amount * 2;
        }

        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}