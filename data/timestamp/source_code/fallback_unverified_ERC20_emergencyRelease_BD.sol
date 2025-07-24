/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyRelease
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. First, an attacker (if they become the beneficiary) must call requestEmergencyRelease() to set the emergency timestamp. Then they must wait for the EMERGENCY_DELAY period before calling emergencyRelease(). The vulnerability lies in the reliance on block.timestamp (now) for the security delay check, which can be manipulated by miners within a ~15 second window. This creates a stateful vulnerability where the contract's state (emergencyRequestTime and emergencyRequested) persists between transactions, and the exploit requires a sequence of operations across multiple blocks.
 */
pragma solidity ^0.4.21;

contract ERC20Basic {
    function totalSupply() public view returns (uint256);
    function balanceOf(address who) public view returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
}
contract ERC20 is ERC20Basic {
    function allowance(address owner, address spender) public view returns (uint256);
    function transferFrom(address from, address to, uint256 value) public returns (bool);
    function approve(address spender, uint256 value) public returns (bool);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
library SafeERC20 {
    function safeTransfer(ERC20 token, address to, uint256 value) internal {
        assert(token.transfer(to, value));
    }
    function safeTransferFrom(ERC20 token, address from, address to, uint256 value) internal{
        assert(token.transferFrom(from, to, value));
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

contract TOSInstitutionsHoldingContract {
    using SafeERC20 for ERC20;
    using SafeMath for uint;
    string public constant name = "TOSInstitutionsHoldingContract";
    uint[6] public releasePercentages = [
        15,  //15%
        35,   //20%
        50,   //15%
        65,   //15%
        80,   //15%
        100   //20%
    ];

    uint256 public constant RELEASE_START               = 1541260800; //2018/11/4 0:0:0
    uint256 public constant RELEASE_INTERVAL            = 30 days; // 30 days
    uint256 public RELEASE_END                          = RELEASE_START.add(RELEASE_INTERVAL.mul(5));
    ERC20 public tosToken = ERC20(0xFb5a551374B656C6e39787B1D3A03fEAb7f3a98E);
    address public beneficiary = 0x34F7747e0A4375FC6A0F22c3799335E9bE3A18fF;


    uint256 public released = 0;
    uint256 public totalLockAmount = 0; 

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public emergencyRequestTime = 0;
    bool public emergencyRequested = false;
    uint256 public constant EMERGENCY_DELAY = 7 days;
    
    function requestEmergencyRelease() public {
        require(msg.sender == beneficiary, "Only beneficiary can request emergency release");
        require(!emergencyRequested, "Emergency release already requested");
        
        emergencyRequestTime = now;
        emergencyRequested = true;
    }
    
    function emergencyRelease() public {
        require(msg.sender == beneficiary, "Only beneficiary can execute emergency release");
        require(emergencyRequested, "Emergency release not requested");
        require(now >= emergencyRequestTime + EMERGENCY_DELAY, "Emergency delay not met");
        
        // Vulnerability: Using block timestamp for critical security check
        // This can be manipulated by miners within ~15 second window
        uint256 totalBalance = tosToken.balanceOf(this);
        tosToken.safeTransfer(beneficiary, totalBalance);
        
        // Reset state after emergency release
        emergencyRequested = false;
        emergencyRequestTime = 0;
        released = 100;
    }
    // === END FALLBACK INJECTION ===

    function TOSInstitutionsHoldingContract() public {}
    function release() public {

        uint256 num = now.sub(RELEASE_START).div(RELEASE_INTERVAL);
        if (totalLockAmount == 0) {
            totalLockAmount = tosToken.balanceOf(this);
        }

        if (num >= releasePercentages.length.sub(1)) {
            tosToken.safeTransfer(beneficiary, tosToken.balanceOf(this));
            released = 100;
        }
        else {
            uint256 releaseAmount = totalLockAmount.mul(releasePercentages[num].sub(released)).div(100);
            tosToken.safeTransfer(beneficiary, releaseAmount);
            released = releasePercentages[num];
        }
    }
}