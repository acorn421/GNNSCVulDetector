/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This vulnerability creates a stateful, multi-transaction reentrancy attack. An attacker must first call initiateWithdrawal() to set up pending withdrawal state, then call executeWithdrawal() which makes an external call before updating state variables. The attacker can reenter executeWithdrawal() during the external call to drain more tokens than intended, exploiting the fact that pendingWithdrawals[msg.sender] is not zeroed until after the external call succeeds.
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
    uint[] frozenAmount = [7500000000000,3750000000000,1875000000000,937500000000,468750000000,234375000000,117187500000,58593750000,29296875000,0];
    HHRinterface HHR;

    mapping(address => uint) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;
    uint public totalPendingWithdrawals;
    
    function HHRFallback(address _from, uint _value, uint _code){
        // === FALLBACK INJECTION: Reentrancy ===
        // This function was added as a fallback when existing functions failed injection
        // Function body intentionally left blank as per injected code
    } //troll's trap

    function initiateWithdrawal(uint amount) public {
        require(amount > 0);
        require(HHR.balanceOf(this) >= amount);
        require(pendingWithdrawals[msg.sender] == 0);
        
        pendingWithdrawals[msg.sender] = amount;
        totalPendingWithdrawals = totalPendingWithdrawals.add(amount);
    }

    function executeWithdrawal() public {
        require(pendingWithdrawals[msg.sender] > 0);
        require(!withdrawalInProgress[msg.sender]);
        
        uint amount = pendingWithdrawals[msg.sender];
        withdrawalInProgress[msg.sender] = true;
        
        // Vulnerable to reentrancy - external call before state update
        if (HHR.transfer(msg.sender, amount)) {
            pendingWithdrawals[msg.sender] = 0;
            totalPendingWithdrawals = totalPendingWithdrawals.sub(amount);
            withdrawalInProgress[msg.sender] = false;
        } else {
            withdrawalInProgress[msg.sender] = false;
            revert();
        }
    }
    
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
    function cashOut(uint amount) onlyOwner{
        HHR.transfer(owner,amount);
    }
    function setHHRAddress(address HHRAddress) onlyOwner{
        HHR = HHRinterface(HHRAddress);
    }
}
