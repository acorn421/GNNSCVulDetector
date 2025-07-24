/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 1. **Added State Variables**: 
 *    - `pendingOwners` mapping to track pending ownership transfers
 *    - `pendingOwner` address to store the current pending owner
 * 
 * 2. **Violation of Checks-Effects-Interactions Pattern**:
 *    - External call to `newOwner.call()` occurs BEFORE state updates
 *    - State modifications happen after the external call, creating a reentrancy window
 * 
 * 3. **Multi-Transaction Stateful Exploitation**:
 *    - **Transaction 1**: Current owner calls `transferOwnership(maliciousContract)` → triggers external call to malicious contract
 *    - **Reentrancy Window**: Malicious contract's `onOwnershipTransferred` function can call back into `transferOwnership` 
 *    - **Transaction 2**: During reentrancy, malicious contract can call `transferOwnership(attackerAddress)` while still being the "newOwner"
 *    - **State Manipulation**: The persistent state (`pendingOwners`, `pendingOwner`) gets corrupted across transactions
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The vulnerability requires the malicious contract to be deployed first (Transaction 0)
 *    - The initial ownership transfer must be initiated (Transaction 1)
 *    - The reentrant call happens during the callback (nested within Transaction 1, but creates persistent state corruption)
 *    - The corrupted state persists between transactions, allowing further exploitation
 *    - Multiple calls can manipulate the `pendingOwners` mapping to create inconsistent states
 * 
 * 5. **Realistic Integration**: 
 *    - The owner notification mechanism is a realistic feature
 *    - The two-phase transfer pattern appears legitimate
 *    - The vulnerability is subtle and could easily be missed in code reviews
 * 
 * **Exploitation Scenario**:
 * 1. Attacker deploys malicious contract with `onOwnershipTransferred` function
 * 2. Current owner calls `transferOwnership(maliciousContract)`
 * 3. During the external call, malicious contract reenters and calls `transferOwnership(attackerAddress)`
 * 4. State corruption occurs with multiple pending owners
 * 5. Attacker can manipulate the pending state across subsequent transactions to gain ownership
 */
pragma solidity ^0.4.11;

contract ERC20 {
    function transfer(address to, uint tokens) public returns (bool success);
}

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public pendingOwners;
    address public pendingOwner;

    function transferOwnership(address newOwner) onlyOwner public {
        // Notify the new owner contract about ownership transfer
        if (isContract(newOwner)) {
            // External call before state update - vulnerable to reentrancy
            bool success = newOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), owner);
            require(success);
        }
        
        // State update after external call - creates reentrancy window
        pendingOwner = newOwner;
        pendingOwners[newOwner] = true;
        
        // If this is a confirmation call (newOwner is already pending), complete the transfer
        if (pendingOwner == newOwner && pendingOwners[newOwner]) {
            owner = newOwner;
            pendingOwners[newOwner] = false;
            pendingOwner = address(0);
        }
    }
    
    // Helper for contract detection in Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}


library SafeMath {
    function mul(uint a, uint b) internal pure returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint a, uint b) internal pure returns (uint) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint a, uint b) internal pure returns (uint) {
        assert(b <= a);
        return a - b;
    }

    function add(uint a, uint b) internal pure returns (uint) {
        uint c = a + b;
        assert(c >= a);
        return c;
    }

    function max64(uint64 a, uint64 b) internal pure returns (uint64) {
        return a >= b ? a : b;
    }

    function min64(uint64 a, uint64 b) internal pure returns (uint64) {
        return a < b ? a : b;
    }

    function max256(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }

    function min256(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}


contract Rockets is owned {
    using SafeMath for uint;
    bool public ICOOpening = true;
    uint256 public USD = 0;
    uint256 public ICORate = 0;
    uint256 public ICOBonus = 0;
    address public ROK = 0xca2660F10ec310DF91f3597574634A7E51d717FC;

    function updateUSD(uint256 usd) onlyOwner public {
        USD = usd;
    }

    function updateRate(uint256 rate, uint256 bonus) onlyOwner public {
        ICORate = rate;
        ICOBonus = bonus;
    }

    function updateOpen(bool opening) onlyOwner public{
        ICOOpening = opening;
    }

    function Rockets() public {
    }

    function() payable {
        require(ICOOpening == true);
        uint256 tokensToBuy;
        uint256 ethAmount = msg.value;
        tokensToBuy = ethAmount * (10 ** 18) / 1 ether * USD * ICORate;
        if(ICOBonus > 0){
            uint256 bonusAmount;
            bonusAmount = tokensToBuy / 100 * ICOBonus;
            tokensToBuy = tokensToBuy + bonusAmount;
        }
        ERC20(ROK).transfer(address(msg.sender), tokensToBuy);
    }

    function getAmountToBuy(uint256 ethAmount) public view returns (uint256){
        uint256 tokensToBuy;
        tokensToBuy = ethAmount * (10 ** 18) / 1 ether * USD * ICORate;
        if(ICOBonus > 0){
            uint256 bonusAmount;
            bonusAmount = tokensToBuy / 100 * ICOBonus;
            tokensToBuy = tokensToBuy + bonusAmount;
        }
        return tokensToBuy;
    }

    function withdrawROK(uint256 amount, address sendTo) onlyOwner public {
        ERC20(ROK).transfer(sendTo, amount);
    }

    function withdrawEther(uint256 amount, address sendTo) onlyOwner public {
        sendTo.transfer(amount);
    }

    function withdrawToken(ERC20 token, uint256 amount, address sendTo) onlyOwner public {
        require(token.transfer(sendTo, amount));
    }
}