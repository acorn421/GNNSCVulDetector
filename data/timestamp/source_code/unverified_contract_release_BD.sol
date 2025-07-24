/*
 * ===== SmartInject Injection Details =====
 * Function      : release
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful timestamp dependence vulnerability that creates a cumulative time-based bonus system. The vulnerability accumulates bonus percentages across multiple transactions based on manipulable block.timestamp values. Attackers can exploit this by:
 * 
 * 1. **Multi-Transaction Exploitation**: Making multiple release() calls with carefully timed transactions to accumulate time bonuses
 * 2. **State Dependency**: The vulnerability only activates after the first transaction (when released > 0), requiring multiple calls
 * 3. **Miner Manipulation**: Miners can manipulate block.timestamp across sequential transactions to maximize the timeBonus calculation
 * 4. **Cumulative Effect**: Each transaction builds upon previous state changes, with the bonus growing based on timestamp differences
 * 
 * The vulnerability is realistic as it appears to be a legitimate bonus system for early/frequent releases, but actually allows exploitation through timestamp manipulation across multiple transactions. The attack requires at least 2 transactions: one to initialize the released state, and subsequent ones to exploit the time-based bonus calculations.
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
    function TOSInstitutionsHoldingContract() public {}
    function release() public {

        uint256 num = now.sub(RELEASE_START).div(RELEASE_INTERVAL);
        if (totalLockAmount == 0) {
            totalLockAmount = tosToken.balanceOf(this);
        }

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store cumulative timestamp for bonus calculation
        uint256 storedTime = now;
        
        // Vulnerability: Cumulative time-based bonus that accumulates across multiple transactions
        // Uses block.timestamp without validation and accumulates across state changes
        uint256 timeBonus = 0;
        if (released > 0) {
            // Calculate bonus based on time elapsed between transactions
            uint256 timeDiff = storedTime.sub(RELEASE_START);
            // Accumulate bonus percentage based on timestamp manipulation opportunities
            timeBonus = timeDiff.div(RELEASE_INTERVAL).mul(2); // Up to 2% per interval
            if (timeBonus > 20) timeBonus = 20; // Cap at 20%
        }

        if (num >= releasePercentages.length.sub(1)) {
            // Apply accumulated time bonus to final release
            uint256 finalBalance = tosToken.balanceOf(this);
            if (timeBonus > 0) {
                finalBalance = finalBalance.add(finalBalance.mul(timeBonus).div(100));
            }
            tosToken.safeTransfer(beneficiary, finalBalance);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            released = 100;
        }
        else {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            uint256 baseReleaseAmount = totalLockAmount.mul(releasePercentages[num].sub(released)).div(100);
            
            // Apply accumulated time bonus to current release
            uint256 releaseAmount = baseReleaseAmount;
            if (timeBonus > 0) {
                releaseAmount = baseReleaseAmount.add(baseReleaseAmount.mul(timeBonus).div(100));
            }
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            tosToken.safeTransfer(beneficiary, releaseAmount);
            released = releasePercentages[num];
        }
    }
}