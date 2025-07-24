/*
 * ===== SmartInject Injection Details =====
 * Function      : release
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Replaced safeTransfer with regular transfer**: Removed the built-in reentrancy protection from safeTransfer
 * 2. **Added callback mechanism**: Introduced a call to beneficiary's onTokensReceived function after each transfer, creating a reentrancy entry point
 * 3. **State updates after external calls**: The critical state variable `released` is updated after both the token transfer and the callback, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract as beneficiary with onTokensReceived function
 * **Transaction 2 (Trigger)**: Attacker calls release() which:
 * - Calculates release amount based on current `released` state
 * - Transfers tokens to malicious beneficiary
 * - Calls beneficiary's onTokensReceived callback
 * - Malicious callback can reenter release() with unchanged `released` state
 * - Second call calculates release amount using same old `released` value
 * - Process can repeat multiple times before original state update
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the beneficiary to be a contract with the callback function (setup in previous transaction)
 * - The attack relies on accumulated state (`released` percentage) that tracks progress across multiple legitimate releases over time
 * - The time-based release mechanism means attackers must wait for different time periods to maximize exploitation across multiple release windows
 * - State manipulation affects subsequent legitimate calls to release() in future transactions
 * 
 * **Exploitation Flow:**
 * 1. **Transaction 1**: Deploy malicious beneficiary contract
 * 2. **Transaction 2**: Wait for release period and call release() - triggers reentrancy
 * 3. **Transaction 3**: Malicious contract can call release() again with manipulated state
 * 4. **Transaction 4**: Subsequent legitimate releases are affected by corrupted `released` state
 * 
 * The vulnerability creates a persistent state corruption that affects future multi-transaction interactions with the contract.
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

        if (num >= releasePercentages.length.sub(1)) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Vulnerable: External call before state update
            tosToken.transfer(beneficiary, tosToken.balanceOf(this));
            // Add callback to beneficiary for "notification" - creates reentrancy opportunity
            if (beneficiary.call(bytes4(keccak256("onTokensReceived(uint256)")), tosToken.balanceOf(this))) {
                // Callback executed - beneficiary can reenter
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            released = 100;
        }
        else {
            uint256 releaseAmount = totalLockAmount.mul(releasePercentages[num].sub(released)).div(100);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Vulnerable: External call before state update  
            tosToken.transfer(beneficiary, releaseAmount);
            // Add callback to beneficiary for "notification" - creates reentrancy opportunity
            if (beneficiary.call(bytes4(keccak256("onTokensReceived(uint256)")), releaseAmount)) {
                // Callback executed - beneficiary can reenter
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            released = releasePercentages[num];
        }
    }
}