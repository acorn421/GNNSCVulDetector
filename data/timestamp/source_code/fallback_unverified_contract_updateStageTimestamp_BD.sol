/*
 * ===== SmartInject Injection Details =====
 * Function      : updateStageTimestamp
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract creator can manipulate crowdsale stage timings through emergency extensions. The vulnerability is stateful and multi-transaction: 1) First, the creator calls updateStageTimestamp() to set an extension, 2) The contract state (emergencyExtension, lastUpdateTime) is modified, 3) Subsequent transactions to the fallback function use getAdjustedTime() which adds the extension to the current timestamp, effectively extending crowdsale stages. This allows manipulation of when stages end, potentially allowing purchases at favorable rates beyond intended deadlines. The vulnerability requires multiple transactions - one to set the extension and others to exploit the modified timing logic.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) external;
}

contract ETHLCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x0;

    uint256 private tokenSold;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public lastUpdateTime;
    uint256 public emergencyExtension = 0;
    
    function updateStageTimestamp(uint256 _extensionHours) isCreator public {
        require(_extensionHours <= 48); // Maximum 48 hours extension
        require(now > lastUpdateTime + 1 hours); // Minimum 1 hour between updates
        
        lastUpdateTime = now;
        emergencyExtension = _extensionHours * 1 hours;
    }
    
    function getAdjustedTime() internal view returns (uint256) {
        if (emergencyExtension > 0 && now > lastUpdateTime) {
            return now + emergencyExtension;
        }
        return now;
    }
    // === END FALLBACK INJECTION ===

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    function ETHLCrowdsale() public {
        creator = msg.sender;
        tokenReward = Token(0x813a823F35132D822708124e01759C565AB4331d);
    }

    function setOwner(address _owner) isCreator public {
        owner = _owner;      
    }

    function setCreator(address _creator) isCreator public {
        creator = _creator;      
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
        uint256 amount;
        
        // stage 1
        if (now > 1525129200 && now < 1525734000 && tokenSold < 350001) {
            amount = msg.value * 2500;
        }

        // stage 2
        if (now > 1525733999 && now < 1526252400 && tokenSold > 350000 && tokenSold < 700001) {
            amount = msg.value * 1250;
        }

        // stage 3
        if (now > 1526252399 && now < 1526857200 && tokenSold > 700000 && tokenSold < 1150001) {
            amount = msg.value * 833;
        }

        // stage 4
        if (now > 1526857199 && now < 1527721200 && tokenSold > 1150000 && tokenSold < 2000001) {
            amount = msg.value * 416;
        }

        // stage 5
        if (now > 1527721199 && now < 1528671600 && tokenSold > 2000000 && tokenSold < 3000001) {
            amount = msg.value * 357;
        }

        // stage 6
        if (now > 1528671599 && now < 1530399600 && tokenSold > 3000000 && tokenSold < 4000001) {
            amount = msg.value * 333;
        }

        tokenSold += amount / 1 ether;
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
