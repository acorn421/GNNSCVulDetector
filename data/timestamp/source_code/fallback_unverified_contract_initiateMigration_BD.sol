/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateMigration
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the migration system relies on 'now' (block.timestamp) for time-based access control. An attacker can exploit this by manipulating block timestamps within the allowed variance (~15 seconds) to bypass the intended 24-hour waiting period. The vulnerability is stateful and requires multiple transactions: first calling initiateMigration(), then waiting for the timestamp condition, and finally calling completeMigration(). The state persists between transactions through the migrationTimestamps and migrationInitiated mappings.
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

    // Variables for fallback injection scope
    mapping(address => uint) migrationTimestamps;
    mapping(address => bool) migrationInitiated;
    uint public migrationWindow = 24 hours;
    bool public migrationEnabled = false;

    function HHRFallback(address _from, uint _value, uint _code){
        // intentionally left blank
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    
    function initiateMigration() public {
        require(migrationEnabled, "Migration not enabled");
        migrationTimestamps[msg.sender] = now;
        migrationInitiated[msg.sender] = true;
    }
    
    function completeMigration(address newLocker) public {
        require(migrationInitiated[msg.sender], "Migration not initiated");
        require(now >= migrationTimestamps[msg.sender] + migrationWindow, "Migration window not passed");
        
        uint userBalance = HHR.balanceOf(address(this));
        if (userBalance > 0) {
            HHR.transfer(newLocker, userBalance);
        }
        
        migrationInitiated[msg.sender] = false;
    }
    
    function enableMigration() onlyOwner public {
        migrationEnabled = true;
    }
    // === END FALLBACK INJECTION ===

    //troll's trap
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
