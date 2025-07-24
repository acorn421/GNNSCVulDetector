/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Replaced secure transfer() with vulnerable call()**: Changed `msg.sender.transfer(balance)` to `bool success = msg.sender.call.value(balance)("")` which provides 2300+ gas and enables reentrancy attacks.
 * 
 * 2. **Moved state update after external call**: The `withdrawals[msg.sender]` update now only occurs AFTER the external call succeeds, creating a classic reentrancy window.
 * 
 * 3. **Preserved withdrawal tracking logic**: The vulnerability relies on the existing `withdrawals` mapping and `getBalance()` calculation that accumulates over time.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker calls `buy()` to establish `joined[msg.sender] > 0` and `investments[msg.sender]`
 * - Wait for time to pass so `getBalance()` accumulates significant value
 * 
 * **Transaction 2 (Preparation)**:
 * - Attacker deploys malicious contract with fallback function that calls back to `withdraw()`
 * - This contract becomes the `msg.sender` for the withdrawal
 * 
 * **Transaction 3 (Exploitation)**:
 * - Attacker calls `withdraw()` from malicious contract
 * - During the `call.value(balance)("")`, the malicious contract's fallback is triggered
 * - Before `withdrawals[msg.sender]` is updated, the attacker can call `withdraw()` again
 * - Since `withdrawals` hasn't been updated yet, `getBalance()` returns the same high value
 * - This allows multiple withdrawals before the state is properly updated
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The `getBalance()` function depends on time elapsed since `joined[msg.sender]`, requiring time between transactions
 * 2. **Setup Phase**: Attacker must first establish legitimacy through `buy()` function
 * 3. **Contract Deployment**: The malicious contract must be deployed and funded between setup and exploitation
 * 4. **Timing Dependency**: The vulnerability depends on accumulated dividends over time, making single-transaction exploitation impossible
 * 
 * This creates a realistic vulnerability where an attacker must build up legitimate state over multiple transactions before being able to exploit the reentrancy flaw.
 */
pragma solidity ^0.4.24;

/**
*
Daily - 75% daily
*/
contract Daily75 {

    using SafeMath for uint256;

    mapping(address => uint256) investments;
    mapping(address => uint256) joined;
    mapping(address => uint256) withdrawals;
    mapping(address => uint256) referrer;

    uint256 public step = 125;
    uint256 public minimum = 10 finney;
    uint256 public stakingRequirement = 0.01 ether;
    address public ownerWallet;
    address public owner;
    address promoter1 = 0xC558895aE123BB02b3c33164FdeC34E9Fb66B660;
    address promoter2 = 0x70C7Eac2858e52856d8143dec1a38bDEc9503eBc;

    event Invest(address investor, uint256 amount);
    event Withdraw(address investor, uint256 amount);
    event Bounty(address hunter, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Constructor Sets the original roles of the contract
     */

    constructor() public {
        owner = msg.sender;
        ownerWallet = msg.sender;
    }

    /**
     * @dev Modifiers
     */

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    /**
     * @dev Allows current owner to transfer control of the contract to a newOwner.
     * @param newOwner The address to transfer ownership to.
     * @param newOwnerWallet The address to transfer ownership to.
     */
    function transferOwnership(address newOwner, address newOwnerWallet) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        ownerWallet = newOwnerWallet;
    }

    /**
     * @dev Investments
     */
    function () public payable {
        buy(0x0);
    }

    function buy(address _referredBy) public payable {
        require(msg.value >= minimum);

        address _customerAddress = msg.sender;

        if(
           // is this a referred purchase?
           _referredBy != 0x0000000000000000000000000000000000000000 &&

           // no cheating!
           _referredBy != _customerAddress &&

           // does the referrer have at least X whole tokens?
           // i.e is the referrer a godly chad masternode
           investments[_referredBy] >= stakingRequirement
       ){
           // wealth redistribution
           referrer[_referredBy] = referrer[_referredBy].add(msg.value.mul(5).div(100));
       }

       if (investments[msg.sender] > 0){
           if (withdraw()){
               withdrawals[msg.sender] = 0;
           }
       }
       investments[msg.sender] = investments[msg.sender].add(msg.value);
       joined[msg.sender] = block.timestamp;
       ownerWallet.transfer(msg.value.mul(5).div(100));
       promoter1.transfer(msg.value.div(100).mul(5));
       promoter2.transfer(msg.value.div(100).mul(1));
       emit Invest(msg.sender, msg.value);
    }

    /**
    * @dev Evaluate current balance
    * @param _address Address of investor
    */
    function getBalance(address _address) view public returns (uint256) {
        uint256 minutesCount = now.sub(joined[_address]).div(1 minutes);
        uint256 percent = investments[_address].mul(step).div(100);
        uint256 different = percent.mul(minutesCount).div(1440);
        uint256 balance = different.sub(withdrawals[_address]);

        return balance;
    }

    /**
    * @dev Withdraw dividends from contract
    */
    function withdraw() public returns (bool){
        require(joined[msg.sender] > 0);
        uint256 balance = getBalance(msg.sender);
        if (address(this).balance > balance){
            if (balance > 0){
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Add callback interface for "withdrawal processing"
                bool success = msg.sender.call.value(balance)("");
                if (success) {
                    withdrawals[msg.sender] = withdrawals[msg.sender].add(balance);
                    emit Withdraw(msg.sender, balance);
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            }
            return true;
        } else {
            return false;
        }
    }

    /**
    * @dev Bounty reward
    */
    function bounty() public {
        uint256 refBalance = checkReferral(msg.sender);
        if(refBalance >= minimum) {
             if (address(this).balance > refBalance) {
                referrer[msg.sender] = 0;
                msg.sender.transfer(refBalance);
                emit Bounty(msg.sender, refBalance);
             }
        }
    }

    /**
    * @dev Gets balance of the sender address.
    * @return An uint256 representing the amount owned by the msg.sender.
    */
    function checkBalance() public view returns (uint256) {
        return getBalance(msg.sender);
    }

    /**
    * @dev Gets withdrawals of the specified address.
    * @param _investor The address to query the the balance of.
    * @return An uint256 representing the amount owned by the passed address.
    */
    function checkWithdrawals(address _investor) public view returns (uint256) {
        return withdrawals[_investor];
    }

    /**
    * @dev Gets investments of the specified address.
    * @param _investor The address to query the the balance of.
    * @return An uint256 representing the amount owned by the passed address.
    */
    function checkInvestments(address _investor) public view returns (uint256) {
        return investments[_investor];
    }

    /**
    * @dev Gets referrer balance of the specified address.
    * @param _hunter The address of the referrer
    * @return An uint256 representing the referral earnings.
    */
    function checkReferral(address _hunter) public view returns (uint256) {
        return referrer[_hunter];
    }
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
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