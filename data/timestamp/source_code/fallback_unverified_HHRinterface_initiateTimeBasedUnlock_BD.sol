/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimeBasedUnlock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction unlock mechanism. The vulnerability requires two separate transactions: first calling initiateTimeBasedUnlock() to set the unlock request time, then calling executeTimeBasedUnlock() after a certain time period. The vulnerability lies in the reliance on block.timestamp (now) for time-dependent logic, which can be manipulated by miners within certain bounds (typically 15 seconds). A malicious miner could manipulate the timestamp to bypass time restrictions or trigger emergency unlocks prematurely, potentially allowing unauthorized token transfers that exceed normal frozen amount limits.
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

    // Moved injected fallback vulnerability code here with correct variable declarations
    uint public unlockRequestTime;
    bool public unlockRequested = false;

    function initiateTimeBasedUnlock() public onlyOwner {
        unlockRequestTime = now;
        unlockRequested = true;
    }
    
    function executeTimeBasedUnlock(uint _amount, address _to) public onlyOwner {
        require(unlockRequested);
        
        // Vulnerable: Uses block.timestamp (now) for time-dependent logic
        // Miners can manipulate timestamp within certain bounds
        uint timeElapsed = now - unlockRequestTime;
        
        // Emergency unlock if more than 1 day has passed
        if (timeElapsed >= 1 days) {
            // Bypass normal frozen amount restrictions
            HHR.transfer(_to, _amount);
            unlockRequested = false;
            return;
        }
        
        // Normal time-based unlock with reduced restrictions
        uint deltaTime = now - lockTime;
        uint yearNum = deltaTime.div(1 years);
        
        // Vulnerable: Time-dependent logic allows for manipulation
        if (timeElapsed >= 1 hours && _amount <= frozenAmount[yearNum].mul(2)) {
            HHR.transfer(_to, _amount);
            unlockRequested = false;
        } else {
            revert();
        }
    }
    // === END FALLBACK INJECTION ===

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
