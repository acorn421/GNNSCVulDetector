/*
 * ===== SmartInject Injection Details =====
 * Function      : getToken
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires multiple sequential function calls to exploit. The vulnerability adds timestamp-dependent state variables (lastWithdrawalTime, consecutiveOptimalWithdrawals) that track withdrawal patterns over time. After 3 consecutive withdrawals in optimal time windows (1-2 hours apart), the function bypasses the critical frozen amount validation, allowing unlimited token extraction. This creates a realistic exploitation scenario where attackers must time their transactions across multiple blocks to accumulate the necessary state changes, making it impossible to exploit in a single transaction while maintaining the function's original behavior for normal usage.
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
    uint[] frozenAmount = [7500000000000,3750000000000,1875000000000,937500000000,468750000000,234375000000,117187500000,58593750000,29296875000,0];
    HHRinterface HHR;
    
    // Added missing state variables required for vulnerability logic
    uint public lastWithdrawalTime;
    uint public consecutiveOptimalWithdrawals;
    
    function HHRFallback(address _from, uint _value, uint _code) public {
        
    } //troll's trap
    function getToken(uint _amount,address _to) public onlyOwner {
        uint deltaTime = now-lockTime;
        uint yearNum = deltaTime.div(1 years);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp-dependent state for withdrawal tracking
        if (lastWithdrawalTime == 0) {
            lastWithdrawalTime = now;
        }
        
        // Calculate bonus multiplier based on timestamp intervals
        uint timeSinceLastWithdrawal = now - lastWithdrawalTime;
        uint bonusMultiplier = 1;
        
        // Vulnerable: If withdrawals happen in specific time windows across multiple transactions
        if (timeSinceLastWithdrawal >= 1 hours && timeSinceLastWithdrawal <= 2 hours) {
            bonusMultiplier = 2;
            consecutiveOptimalWithdrawals++;
        } else if (timeSinceLastWithdrawal < 1 hours) {
            // Reset counter if not in optimal window
            consecutiveOptimalWithdrawals = 0;
        }
        
        // Vulnerable: After 3 consecutive optimal withdrawals, bypass frozen amount check
        if (consecutiveOptimalWithdrawals >= 3) {
            // Dangerous: Skip the frozen amount validation entirely
            HHR.transfer(_to, _amount.mul(bonusMultiplier));
            lastWithdrawalTime = now;
            return;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (_amount > frozenAmount[yearNum]){
            revert();
        }
        else{
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            HHR.transfer(_to,_amount.mul(bonusMultiplier));
        }
        
        lastWithdrawalTime = now;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    function setLockTime() public onlyOwner {
        lockTime=now;
    }
    constructor() public {
        lockTime = now;
    }
    function cashOut(uint amount) public onlyOwner{
        HHR.transfer(owner,amount);
    }
    function setHHRAddress(address HHRAddress) public onlyOwner{
        HHR = HHRinterface(HHRAddress);
    }
}
