/*
 * ===== SmartInject Injection Details =====
 * Function      : getToken
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
 * 1. **Added State Variables**: Introduced `withdrawalRequests` mapping to track pending withdrawal amounts and `withdrawalInProgress` boolean mapping to track active withdrawals
 * 2. **State-Before-Call Pattern**: Set withdrawal state before the external HHR.transfer() call
 * 3. **State-After-Call Cleanup**: Moved critical state updates (frozenAmount reduction and withdrawal cleanup) to after the external call
 * 4. **Vulnerable Window**: Created a window where state is inconsistent during the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner calls getToken(1000, maliciousContract) - sets withdrawalInProgress[maliciousContract] = true, withdrawalRequests[maliciousContract] = 1000
 * - **During HHR.transfer()**: Malicious contract's receive/fallback function is triggered
 * - **Reentrancy Attack**: Malicious contract calls getToken again before original state cleanup occurs
 * - **Transaction 2**: Second call sees withdrawalInProgress[maliciousContract] = true but can still proceed because state checks happen before external call
 * - **Result**: frozenAmount is decremented multiple times but only one legitimate withdrawal occurred
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the initial state setup in transaction 1
 * - The reentrancy exploitation happens during the callback in the same transaction
 * - However, the persistent state (withdrawalRequests, withdrawalInProgress) enables continued exploitation across multiple calls
 * - An attacker could set up the vulnerable state in one transaction, then exploit it in subsequent transactions through accumulated reentrancy calls
 * 
 * **State Persistence**: The withdrawal tracking state persists between transactions, allowing an attacker to build up multiple pending withdrawals that can be exploited when the frozen amount limits are bypassed through repeated reentrancy.
 */
pragma solidity ^0.4.19;
contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
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
    
    // Added missing mappings for withdrawalRequests and withdrawalInProgress
    mapping(address => uint) withdrawalRequests;
    mapping(address => bool) withdrawalInProgress;
    
    function HHRFallback(address _from, uint _value, uint _code){
        
    } //troll's trap
    function getToken(uint _amount,address _to) onlyOwner {
        uint deltaTime = now-lockTime;
        uint yearNum = deltaTime.div(1 years);
        if (_amount>frozenAmount[yearNum]){
            revert();
        }
        else{
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Initialize withdrawal request state
            withdrawalRequests[_to] = _amount;
            withdrawalInProgress[_to] = true;
            
            // External call before state cleanup - vulnerable to reentrancy
            HHR.transfer(_to,_amount);
            
            // State cleanup after external call (vulnerable window)
            frozenAmount[yearNum] = frozenAmount[yearNum].sub(_amount);
            withdrawalInProgress[_to] = false;
            delete withdrawalRequests[_to];
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }        
    }
    function setLockTime() onlyOwner {
        lockTime=now;
    }
    constructor() public{
        lockTime = now;
    }
    function cashOut(uint amount) onlyOwner{
        HHR.transfer(owner,amount);
    }
    function setHHRAddress(address HHRAddress) onlyOwner{
        HHR = HHRinterface(HHRAddress);
    }
}