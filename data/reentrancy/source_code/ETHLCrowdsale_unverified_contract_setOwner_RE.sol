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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding External Call Before State Update**: The function now makes an external call to the old owner before updating the state, violating the Check-Effects-Interactions (CEI) pattern.
 * 
 * 2. **State-Dependent External Call**: The external call is made only when there's an existing owner (oldOwner != address(0)), making it dependent on previous state changes.
 * 
 * 3. **Multi-Transaction Exploitation Scenario**:
 *    - **Transaction 1**: Creator calls setOwner(attackerContract) to set initial owner
 *    - **Transaction 2**: Creator calls setOwner(legitimateOwner) to change to legitimate owner
 *    - **During Transaction 2**: The attackerContract receives onOwnershipChanged callback and re-enters setOwner(maliciousOwner)
 *    - **Result**: Due to reentrancy, the final owner becomes maliciousOwner instead of legitimateOwner
 * 
 * 4. **Why Multiple Transactions Are Required**:
 *    - The vulnerability requires an initial owner to be set (Transaction 1)
 *    - The exploit occurs during the second ownership change (Transaction 2)
 *    - The external call only happens when oldOwner != address(0), requiring prior state
 *    - The attacker must deploy a contract that implements the callback, requiring separate deployment transaction
 * 
 * 5. **State Accumulation**: The vulnerability leverages the accumulated state (previous owner) to enable the external call that creates the reentrancy opportunity.
 * 
 * This creates a realistic scenario where ownership changes could legitimately notify previous owners, but the improper ordering of operations creates a reentrancy vulnerability that requires multiple transactions to exploit.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        address oldOwner = owner;
        
        // External call to notify old owner about ownership change
        if (oldOwner != address(0)) {
            // State-dependent external call that can be re-entered
            (bool success, ) = oldOwner.call(abi.encodeWithSignature("onOwnershipChanged(address)", _owner));
            require(success, "Notification failed");
        }
        
        // State update after external call - violates CEI pattern
        owner = _owner;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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