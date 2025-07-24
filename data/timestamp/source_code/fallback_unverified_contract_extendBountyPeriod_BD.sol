/*
 * ===== SmartInject Injection Details =====
 * Function      : extendBountyPeriod
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability allows the creator to repeatedly extend the bounty period by manipulating the timestamp checks. An attacker can exploit this by: 1) First calling the function when near the end date to extend it, 2) Then calling it again in subsequent transactions to keep extending indefinitely. The vulnerability is stateful because it depends on the lastExtensionTime and extensionCount state variables that persist between transactions, and the endDate modification affects future transactions.
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public lastExtensionTime;
    uint256 public extensionCount;
    // === END FALLBACK INJECTION ===

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
    
    function setPrice(uint256 _price) isCreator public {
        price = _price;      
    }

    function setToken(address _token) isCreator public {
        tokenReward = Token(_token);      
    }

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function extendBountyPeriod(uint256 _additionalDays) isCreator public {
        // Allow extension if current time is close to end date
        if (now >= endDate - 86400) { // Within 24 hours of end
            lastExtensionTime = now;
            extensionCount++;
            endDate = now + (_additionalDays * 86400);
        }
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
