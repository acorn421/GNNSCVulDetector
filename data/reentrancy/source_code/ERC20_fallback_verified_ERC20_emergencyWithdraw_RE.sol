/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
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
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The attack requires: 1) First transaction: Call requestEmergencyWithdraw() to set up the withdrawal state, 2) Second transaction: Call emergencyWithdraw() which performs external call before updating state, allowing reentrancy attacks where the malicious contract can call back into emergencyWithdraw() before the state variables are reset, potentially draining more tokens than intended.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public emergencyWithdrawals;
    mapping(address => bool) public emergencyWithdrawEnabled;
    uint256 public emergencyWithdrawDelay = 7 days;
    
    function requestEmergencyWithdraw(uint256 amount) public {
        require(msg.sender == beneficiary, "Only beneficiary can request emergency withdrawal");
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= tosToken.balanceOf(this), "Insufficient balance");
        
        emergencyWithdrawals[msg.sender] = amount;
        emergencyWithdrawEnabled[msg.sender] = true;
    }
    
    function emergencyWithdraw() public {
        require(emergencyWithdrawEnabled[msg.sender], "Emergency withdrawal not enabled");
        require(emergencyWithdrawals[msg.sender] > 0, "No withdrawal amount set");
        
        uint256 amount = emergencyWithdrawals[msg.sender];
        
        // Vulnerable: External call before state update
        tosToken.safeTransfer(msg.sender, amount);
        
        // State update after external call - vulnerable to reentrancy
        emergencyWithdrawals[msg.sender] = 0;
        emergencyWithdrawEnabled[msg.sender] = false;
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