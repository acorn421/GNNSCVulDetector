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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the new owner before updating the ownership state. This creates a reentrancy window where the attacker can exploit the inconsistent state across multiple transactions.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Initial Setup)**: Attacker deploys a malicious contract that implements the onOwnershipTransfer callback
 * 2. **Transaction 2 (Exploit Trigger)**: Current owner calls transferOwnership with attacker's contract address
 * 3. **Transaction 3 (Reentrancy Attack)**: During the external call, attacker's contract receives control and can:
 *    - Call back into transferOwnership to change ownership again
 *    - Access other onlyOwner functions while still being recognized as owner
 *    - Manipulate contract state before the ownership transfer completes
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability depends on the attacker having a deployed contract ready to receive the callback
 * - The exploit requires the external call to trigger the attacker's code
 * - State changes persist between the initial call and the reentrant calls
 * - The attacker can accumulate state changes across multiple nested calls
 * 
 * **State Persistence Aspect:**
 * - The `owner` variable remains unchanged during the external call
 * - Attacker can perform multiple operations while maintaining owner privileges
 * - The vulnerability window exists between the external call and the final state update
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the new owner about ownership transfer
        // This external call creates a reentrancy window
        if (newOwner.call(bytes4(keccak256("onOwnershipTransfer(address)")), owner)) {
            // Reentrancy possible here - attacker can call back into this function
            // or other functions while ownership state is in transition
        }
        
        // State update happens after external call (vulnerable pattern)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    function cashOut(uint amount) onlyOwner{
        HHR.transfer(owner,amount);
    }
    function setHHRAddress(address HHRAddress) onlyOwner{
        HHR = HHRinterface(HHRAddress);
    }
}