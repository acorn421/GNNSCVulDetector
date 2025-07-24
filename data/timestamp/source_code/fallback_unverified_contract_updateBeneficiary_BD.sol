/*
 * ===== SmartInject Injection Details =====
 * Function      : updateBeneficiary
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction beneficiary change process. The vulnerability requires: 1) First transaction to call requestBeneficiaryChange() which sets beneficiaryChangeRequestTime = now, 2) Second transaction after delay period to call updateBeneficiary() which checks if now >= beneficiaryChangeRequestTime + DELAY. A malicious miner can manipulate the timestamp in the second transaction to bypass the delay period by setting a timestamp that's artificially ahead, allowing premature beneficiary changes. This is stateful because it depends on the beneficiaryChangeRequestTime state persisting between transactions.
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
    uint256 public beneficiaryChangeRequestTime = 0;
    address public pendingBeneficiary = 0x0;
    uint256 public constant BENEFICIARY_CHANGE_DELAY = 7 days;
    
    function requestBeneficiaryChange(address newBeneficiary) public {
        require(msg.sender == beneficiary, "Only current beneficiary can request change");
        require(newBeneficiary != 0x0, "New beneficiary cannot be zero address");
        
        pendingBeneficiary = newBeneficiary;
        beneficiaryChangeRequestTime = now;
    }
    
    function updateBeneficiary() public {
        require(pendingBeneficiary != 0x0, "No pending beneficiary change");
        require(msg.sender == beneficiary, "Only current beneficiary can update");
        
        // Vulnerable: Using block.timestamp for time-sensitive operations
        // Miners can manipulate timestamp within certain bounds
        require(now >= beneficiaryChangeRequestTime + BENEFICIARY_CHANGE_DELAY, "Delay period not met");
        
        beneficiary = pendingBeneficiary;
        pendingBeneficiary = 0x0;
        beneficiaryChangeRequestTime = 0;
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