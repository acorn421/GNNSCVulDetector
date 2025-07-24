/*
 * ===== SmartInject Injection Details =====
 * Function      : setCreator
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to both the previous and new creator addresses before and after the state update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call to Previous Creator**: Before updating the creator state, the function now calls `onCreatorChange(address)` on the previous creator address. This external call occurs while the old creator is still set, creating a reentrancy window.
 * 
 * 2. **State Update After External Call**: The `creator = _creator` assignment happens after the first external call, violating the checks-effects-interactions pattern.
 * 
 * 3. **Additional External Call to New Creator**: After the state update, another external call is made to the new creator for "confirmation", extending the vulnerability window.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker (current creator) calls `setCreator(maliciousContract)` where `maliciousContract` is controlled by the attacker
 * - **During Transaction 1**: The external call to the previous creator (attacker) triggers `onCreatorChange()` in the malicious contract
 * - **Reentrancy Window**: The malicious contract can call back into `setCreator()` again since `creator` hasn't been updated yet
 * - **State Manipulation**: The attacker can manipulate the creator state through nested calls, potentially setting themselves as creator multiple times or bypassing intended restrictions
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Persistence**: The vulnerability relies on the `creator` state persisting between calls and being checked by the `isCreator` modifier
 * 2. **Callback Preparation**: The attacker needs to deploy a malicious contract that implements the callback functions (`onCreatorChange`, `confirmCreatorRole`)
 * 3. **Sequence Dependency**: The exploit requires a specific sequence where the attacker is first the legitimate creator, then uses reentrancy to manipulate the creator change process
 * 4. **Accumulated State**: The vulnerability becomes more severe when combined with other functions that depend on the creator state, requiring multiple transactions to fully exploit
 * 
 * This creates a realistic vulnerability where the creator change process includes legitimate-looking external notifications but opens up reentrancy attack vectors that require careful orchestration across multiple transactions.
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
        owner = _owner;      
    }

    function setCreator(address _creator) isCreator public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        address previousCreator = creator;
        
        // External call to notify previous creator before state change
        if (previousCreator != address(0)) {
            // This external call creates reentrancy opportunity
            previousCreator.call(abi.encodeWithSignature("onCreatorChange(address)", _creator));
            // Note: Intentionally not checking success for realistic vulnerability
        }
        
        // State update happens after external call - vulnerable to reentrancy
        creator = _creator;
        
        // Additional external call to new creator for confirmation
        if (_creator != address(0)) {
            _creator.call(abi.encodeWithSignature("confirmCreatorRole()"));
            // Note: Intentionally not checking success for realistic vulnerability
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        emit FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}