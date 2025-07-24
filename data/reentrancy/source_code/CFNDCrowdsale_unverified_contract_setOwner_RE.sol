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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls before and after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_owner.call()` with `validateOwnership()` before state update
 * 2. Added another external call to `_owner.call()` with `onOwnershipTransferred()` after state update
 * 3. External calls are made to user-controlled contracts without reentrancy protection
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract and calls `setOwner()` with their contract address
 * 2. **Transaction 2**: During the first external call (`validateOwnership`), the malicious contract can reenter `setOwner()` again
 * 3. **Transaction 3+**: The attacker can chain multiple reentrancy calls, each time manipulating the owner state
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the fact that state changes persist between the external calls
 * - Each reentrant call can observe and modify the owner state from previous calls
 * - The attacker needs to set up the malicious contract first, then trigger the reentrancy sequence
 * - The accumulated state changes from multiple reentrant calls create the exploitable condition
 * 
 * **State Persistence Exploitation:**
 * - The `owner` variable is modified between external calls, creating windows for reentrancy
 * - Subsequent calls to the contract (like the fallback function) will use the manipulated owner state
 * - The vulnerability allows the attacker to potentially drain funds by changing the owner multiple times during execution
 * 
 * This creates a realistic reentrancy vulnerability that requires careful orchestration across multiple transactions and leverages persistent state changes to be exploitable.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) external;
}

contract CFNDCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x56D215183E48881f10D1FaEb9325cf02171B16B7;

    uint256 private price;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    function CFNDCrowdsale() public {
        creator = msg.sender;
        price = 400;
        tokenReward = Token(0x2a7d19F2bfd99F46322B03C2d3FdC7B7756cAe1a);
    }

    function setOwner(address _owner) isCreator public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Enhanced owner validation with external verification
        // Solidity <0.5.0 does not support address.code.length; proxy using extcodesize
        uint256 length;
        assembly { length := extcodesize(_owner) }
        if (length > 0) {
            // Call external contract to verify ownership eligibility
            bool success;
            bytes memory data = abi.encodeWithSignature("validateOwnership(address)", address(this));
            assembly {
                let ptr := add(data, 0x20)
                success := call(gas, _owner, 0, ptr, mload(data), 0, 0)
            }
            require(success, "Owner validation failed");
        }
        
        owner = _owner;
        
        // Notify the new owner about ownership transfer
        assembly { length := extcodesize(_owner) }
        if (length > 0) {
            bool notifySuccess;
            bytes memory notifyData = abi.encodeWithSignature("onOwnershipTransferred(address,address)", owner, _owner);
            assembly {
                let ptr := add(notifyData, 0x20)
                notifySuccess := call(gas, _owner, 0, ptr, mload(notifyData), 0, 0)
            }
            // Continue even if notification fails
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function setCreator(address _creator) isCreator public {
        creator = _creator;      
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
        require(now > 1527238800);
        uint256 amount = msg.value * price;
        uint256 _amount = amount / 100;

        
        // stage 1
        if (now > 1527238800 && now < 1527670800) {
            amount += _amount * 15;
        }

        // stage 2
        if (now > 1527843600 && now < 1528189200) {
            amount += _amount * 10;
        }

        // stage 3
        if (now > 1528275600 && now < 1528621200) {
            amount += _amount * 5;
        }

        // stage 4
        if (now > 1528707600 && now < 1529053200) {
            amount += _amount * 2;
        }

        // stage 5
        require(now < 1531123200);

        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
