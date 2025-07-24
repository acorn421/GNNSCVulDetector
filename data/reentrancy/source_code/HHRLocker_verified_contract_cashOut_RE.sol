/*
 * ===== SmartInject Injection Details =====
 * Function      : cashOut
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Variables Added**: 
 *    - `pendingWithdrawals` mapping to track withdrawal amounts
 *    - `withdrawalTimestamps` mapping to track last withdrawal time
 *    - `withdrawalCooldown` to enforce time-based restrictions
 * 
 * 2. **Vulnerability Mechanics**:
 *    - The function updates `pendingWithdrawals[owner] += amount` BEFORE the external call
 *    - The external call `HHR.transfer(owner, amount)` can trigger reentrancy
 *    - The state cleanup `pendingWithdrawals[owner] -= amount` happens AFTER the external call
 *    - This creates a classic checks-effects-interactions pattern violation
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner calls cashOut(100), pendingWithdrawals[owner] becomes 100, timestamp is set
 *    - **Transaction 2**: After cooldown, owner calls cashOut(200) again
 *    - **During Transaction 2**: If HHR contract is malicious/compromised, it can call back into cashOut during the transfer
 *    - **Reentrancy Attack**: The callback sees pendingWithdrawals[owner] = 200 (from current call) plus any accumulated state from previous calls
 *    - **State Inconsistency**: The attacker can exploit the accumulated pending withdrawals and timestamp states that persist between transactions
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The cooldown mechanism requires time to pass between calls, necessitating multiple transactions
 *    - The vulnerability exploits accumulated state (pendingWithdrawals) that builds up across multiple function calls
 *    - The timestamp state persists between transactions, creating windows for exploitation
 *    - Single-transaction exploitation is prevented by the cooldown check, but multi-transaction sequences can exploit state inconsistencies
 * 
 * 5. **Realistic Exploitation Scenario**:
 *    - Attacker (if owner is compromised) or malicious HHR contract waits for cooldown periods
 *    - Calls cashOut multiple times to build up pendingWithdrawals state
 *    - During a later call, triggers reentrancy to exploit the accumulated pending state
 *    - Can potentially withdraw more than intended by exploiting the state that persists between transactions
 */
pragma solidity ^0.4.19;
contract Ownable {
    address public owner;


    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    function Ownable() public {
        owner = msg.sender;
    }


    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }


    /**
     * @dev Allows the current owner to transfer control of the contract to a newOwner.
     * @param newOwner The address to transfer ownership to.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

}
library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}
contract HHRinterface {
    uint256 public totalSupply;
    function balanceOf(address who) public view returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    function allowance(address owner, address spender) public view returns (uint256);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool); 
}
contract HHRLocker is Ownable {
    using SafeMath for uint;
    uint lockTime;
    uint[] frozenAmount=[7500000000000,3750000000000,1875000000000,937500000000,468750000000,234375000000,117187500000,58593750000,29296875000,0];
    HHRinterface HHR;
    
    function HHRFallback(address _from, uint _value, uint _code){
        
    } //troll's trap
    function getToken(uint _amount,address _to) onlyOwner {
        uint deltaTime = now-lockTime;
        uint yearNum = deltaTime.div(1 years);
        if (_amount>frozenAmount[yearNum]){
            revert();
        }
        else{
            HHR.transfer(_to,_amount);
        }        
    }
    function setLockTime() onlyOwner {
        lockTime=now;
    }
    function HHRLocker(){
        lockTime = now;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public pendingWithdrawals;
    mapping(address => uint) public withdrawalTimestamps;
    uint public withdrawalCooldown = 1 hours;
    
    function cashOut(uint amount) onlyOwner{
        // Check if enough time has passed since last withdrawal
        require(now >= withdrawalTimestamps[owner] + withdrawalCooldown, "Cooldown period not met");
        
        // Add to pending withdrawals first
        pendingWithdrawals[owner] += amount;
        
        // Update timestamp before external call (vulnerable pattern)
        withdrawalTimestamps[owner] = now;
        
        // External call that can trigger reentrancy
        HHR.transfer(owner, amount);
        
        // State update after external call (vulnerable - should be before)
        pendingWithdrawals[owner] -= amount;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    function setHHRAddress(address HHRAddress) onlyOwner{
        HHR = HHRinterface(HHRAddress);
    }
}